//! `reshare` subcommand: change t-of-n parameters of an existing key without
//! changing its public key.
//!
//! Three flows, selected by old/new parameters:
//!
//! * TSS -> TSS: the dkls23 `quorum_change` protocol. All currently online
//!   holders contribute their shares; the first `new_n` participants (sorted
//!   by peer id) become the new quorum.
//! * singleton -> TSS ("import"): the holder Shamir-splits the plain private
//!   key with [`sl_dkls23::key_import::ecdsa_secret_shares`], distributes the
//!   temporary shares over the encrypted iroh connections and everyone runs
//!   the `key_refresh` protocol to turn them into proper DKLs23 shares.
//! * TSS -> singleton ("export"): `old_t` holders run; everyone sends s_i to
//!   the deterministically chosen receiver (lowest peer id), which combines
//!   the shares into a plain private key with
//!   [`sl_dkls23::key_export::combine_shares`].
//!
//! The session starts when max(new_n, old_t) instances are online.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use k256::elliptic_curve::PrimeField;
use k256::{NonZeroScalar, ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sl_dkls23::keygen::key_refresh::KeyshareForRefresh;
use sl_dkls23::setup::NoSigningKey;
use sl_mpc_mate::message::InstanceId;
use tracing::info;

use crate::net::{establish, Hello, Mesh, SessionConfig};
use crate::store::{self, KeyMaterial, ShareFile};
use crate::{ids, ops};

const DIRECT_TIMEOUT: Duration = Duration::from_secs(100);

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct OldParams {
    singleton: bool,
    t: u8,
    n: u8,
    pubkey: String,
}

pub async fn run(key_id: &str, peer_id: &str, new_t: u8, new_n: u8) -> Result<()> {
    ensure!(new_t >= 1, "threshold must be at least 1");
    ensure!(new_n >= new_t, "n must be >= t");
    ensure!(
        new_t >= 2 || new_n == 1,
        "t=1 means a singleton key and requires n=1"
    );

    let old = store::load_opt(key_id, peer_id)?;
    let old_params = old.as_ref().map(|sf| OldParams {
        singleton: sf.is_singleton(),
        t: sf.t,
        n: sf.n,
        pubkey: sf.public_key_hex.clone(),
    });

    if old.is_none() && new_n == 1 {
        bail!("resharing to a singleton requires this peer to hold an existing share");
    }

    // trivial case: singleton -> singleton for the same holder
    if let Some(sf) = &old {
        if sf.is_singleton() && new_n == 1 {
            info!("key is already a singleton; nothing to do");
            println!("{}", sf.public_key_hex);
            return Ok(());
        }
    }

    let payload = match &old_params {
        Some(p) => json!({
            "new_t": new_t, "new_n": new_n,
            "holder": true, "old": p,
        }),
        None => json!({ "new_t": new_t, "new_n": new_n, "holder": false }),
    };
    let hello = Hello::new("reshare", key_id, peer_id, payload.clone());

    let compat = {
        let payload = payload.clone();
        Arc::new(move |h: &Hello| {
            for field in ["new_t", "new_n"] {
                if h.payload.get(field) != payload.get(field) {
                    return Err(format!(
                        "reshare parameter mismatch on '{field}': peer has {:?}, we have {:?}",
                        h.payload.get(field),
                        payload.get(field)
                    ));
                }
            }
            let both_holders = payload.get("holder") == Some(&json!(true))
                && h.payload.get("holder") == Some(&json!(true));
            if both_holders && h.payload.get("old") != payload.get("old") {
                return Err(format!(
                    "old key parameters mismatch: peer has {:?}, we have {:?}",
                    h.payload.get("old"),
                    payload.get("old")
                ));
            }
            Ok(())
        })
    };

    let quorum = {
        Arc::new(move |hs: &[Hello]| {
            let holders: Vec<&Hello> = hs
                .iter()
                .filter(|h| h.payload.get("holder") == Some(&json!(true)))
                .collect();
            let Some(first) = holders.first() else {
                return false;
            };
            let Ok(old) = serde_json::from_value::<OldParams>(
                first.payload.get("old").cloned().unwrap_or_default(),
            ) else {
                return false;
            };
            let old_t_eff = if old.singleton { 1 } else { old.t };
            let required = (new_n as usize).max(old_t_eff as usize);
            let fresh = hs.len() - holders.len();
            hs.len() == required
                && holders.len() >= old_t_eff as usize
                && fresh <= new_n as usize
                && (!old.singleton || holders.len() == 1)
        })
    };

    info!("waiting for reshare quorum for key '{key_id}' (target {new_t}-of-{new_n})");
    let mut mesh = establish(SessionConfig {
        hello,
        compat,
        quorum,
    })
    .await?;

    // reconstruct the old parameters every participant agreed on
    let holder_hello = mesh
        .participants
        .iter()
        .find(|h| h.payload.get("holder") == Some(&json!(true)))
        .context("no holder in session")?;
    let old_agreed: OldParams =
        serde_json::from_value(holder_hello.payload.get("old").cloned().unwrap_or_default())
            .context("invalid old parameters in holder hello")?;

    let pk_hex = if old_agreed.singleton {
        import_flow(&mut mesh, key_id, peer_id, &old_agreed, old.as_ref(), new_t, new_n).await?
    } else if new_n == 1 {
        export_flow(&mut mesh, key_id, peer_id, &old_agreed, old.as_ref()).await?
    } else {
        quorum_change_flow(&mut mesh, key_id, peer_id, &old_agreed, old.as_ref(), new_t, new_n)
            .await?
    };

    mesh.shutdown().await;
    println!("{pk_hex}");
    Ok(())
}

fn holder_peer_ids(mesh: &Mesh) -> Vec<String> {
    mesh.participants
        .iter()
        .filter(|h| h.payload.get("holder") == Some(&json!(true)))
        .map(|h| h.peer_id.clone())
        .collect()
}

fn pubkey_point(pk_hex: &str) -> Result<ProjectivePoint> {
    use k256::elliptic_curve::group::GroupEncoding;
    let bytes = hex::decode(pk_hex).context("invalid public key hex")?;
    let point =
        ProjectivePoint::from_bytes(k256::CompressedPoint::from_slice(&bytes));
    Option::from(point).context("invalid public key point")
}

/// singleton -> t-of-n
async fn import_flow(
    mesh: &mut Mesh,
    key_id: &str,
    peer_id: &str,
    old: &OldParams,
    my_old: Option<&ShareFile>,
    new_t: u8,
    new_n: u8,
) -> Result<String> {
    ensure!(new_t >= 2, "import target must be a real threshold (t >= 2)");
    let order = mesh.peer_ids();
    let my_idx = mesh.my_index();
    let holders = holder_peer_ids(mesh);
    ensure!(holders.len() == 1, "singleton import requires exactly one holder");
    let holder = holders[0].clone();

    let instance = ids::reshare_instance(key_id, "import", 1, new_t, new_n, &order, &holders);

    let my_kfr = if let Some(sf) = my_old {
        // we hold the plain key: split it and distribute the temporary shares
        let sk = sf.signing_key()?;
        let scalar: NonZeroScalar = *sk.as_nonzero_scalar();
        let chain_code: [u8; 32] = rand::random();
        let kfrs = sl_dkls23::key_import::ecdsa_secret_shares(
            new_t,
            vec![0u8; new_n as usize],
            &scalar,
            chain_code,
            None,
            &mut rand::thread_rng(),
        );
        ensure!(kfrs.len() == new_n as usize, "unexpected share count");
        for (idx, target) in order.iter().enumerate() {
            if target != peer_id {
                mesh.send_direct(target, kfrs[idx].to_bytes())
                    .with_context(|| format!("sending temporary share to {target}"))?;
            }
        }
        info!("distributed {} temporary shares", new_n - 1);
        kfrs.into_iter()
            .nth(my_idx)
            .context("missing own temporary share")?
    } else {
        info!("waiting for temporary share from holder '{holder}'");
        let bytes = mesh.recv_direct(&holder, DIRECT_TIMEOUT).await?;
        let kfr = KeyshareForRefresh::from_bytes(&bytes)
            .context("invalid temporary share from holder")?;
        ensure!(kfr.party_id as usize == my_idx, "temporary share party id mismatch");
        kfr
    };

    let setup = sl_dkls23::setup::keygen::SetupMessage::new(
        InstanceId::new(instance),
        NoSigningKey,
        my_idx,
        ops::no_vks(new_n as usize),
        &vec![0u8; new_n as usize],
        new_t as usize,
    );

    info!("running key refresh to finalize import (party {my_idx} of {new_n})");
    let share =
        sl_dkls23::keygen::key_refresh::run(setup, ops::seed(), mesh.relay(), my_kfr)
            .await
            .map_err(|e| anyhow!("key import failed: {e:?}"))?;

    let pk_hex = store::pubkey_hex_of(&share.public_key());
    ensure!(
        pk_hex == old.pubkey,
        "public key changed during import: {pk_hex} != {}",
        old.pubkey
    );

    store::save(&ShareFile {
        key_id: key_id.to_string(),
        peer_id: peer_id.to_string(),
        t: new_t,
        n: new_n,
        public_key_hex: pk_hex.clone(),
        material: KeyMaterial::Threshold {
            keyshare_b64: store::keyshare_b64(&share),
        },
    })?;
    Ok(pk_hex)
}

#[derive(Serialize, Deserialize)]
struct ExportShare {
    kg_party_id: u8,
    s_i_hex: String,
}

/// t-of-n -> singleton. The receiver is the participant with the lowest peer
/// id; everyone else sends their share over the encrypted connection and
/// deletes their share file after the receiver confirms.
async fn export_flow(
    mesh: &mut Mesh,
    key_id: &str,
    peer_id: &str,
    old: &OldParams,
    my_old: Option<&ShareFile>,
) -> Result<String> {
    let sf = my_old.context("export requires an existing share on every participant")?;
    let keyshare = sf.keyshare()?;
    let my_kg_pid = keyshare.party_id;
    let order = mesh.peer_ids();
    let receiver = order[0].clone();
    let pk_point = pubkey_point(&old.pubkey)?;

    if peer_id != receiver {
        let msg = serde_json::to_vec(&ExportShare {
            kg_party_id: my_kg_pid,
            s_i_hex: hex::encode(keyshare.s_i().to_bytes()),
        })?;
        mesh.send_direct(&receiver, msg)?;
        info!("sent share to receiver '{receiver}', waiting for confirmation");
        let ack = mesh.recv_direct(&receiver, DIRECT_TIMEOUT).await?;
        ensure!(ack == b"ok", "unexpected confirmation from receiver");
        store::delete(key_id, peer_id)?;
        info!("share deleted; key '{key_id}' now lives on '{receiver}' as a singleton");
        return Ok(old.pubkey.clone());
    }

    // we are the receiver: collect t-1 shares and combine
    let x_i_list = keyshare.x_i_list();
    let mut xs: Vec<(NonZeroScalar, usize)> = vec![(x_i_list[my_kg_pid as usize], 0)];
    let mut ss: Vec<Scalar> = vec![keyshare.s_i()];
    let mut seen = vec![my_kg_pid];

    let others: Vec<String> = order.iter().filter(|p| **p != receiver).cloned().collect();
    for other in &others {
        let bytes = mesh.recv_direct(other, DIRECT_TIMEOUT).await?;
        let es: ExportShare = serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid share payload from {other}"))?;
        ensure!(
            !seen.contains(&es.kg_party_id),
            "duplicate share for party {}",
            es.kg_party_id
        );
        ensure!(
            (es.kg_party_id as usize) < x_i_list.len(),
            "party id out of range"
        );
        seen.push(es.kg_party_id);
        let s_bytes = hex::decode(&es.s_i_hex).context("invalid share hex")?;
        let arr: [u8; 32] = s_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("invalid share length"))?;
        let s: Option<Scalar> = Option::from(Scalar::from_repr(arr.into()));
        ss.push(s.context("invalid share scalar")?);
        xs.push((x_i_list[es.kg_party_id as usize], 0));
    }

    let secret = sl_dkls23::key_export::combine_shares(&xs, &ss, &pk_point)
        .context("failed to reconstruct private key from shares")?;

    let sk = k256::ecdsa::SigningKey::from_slice(&secret.to_bytes())
        .context("reconstructed key invalid")?;
    let pk_hex = store::pubkey_hex_of(&(ProjectivePoint::GENERATOR * secret));
    ensure!(
        pk_hex == old.pubkey,
        "reconstructed key does not match the expected public key"
    );

    store::save(&ShareFile {
        key_id: key_id.to_string(),
        peer_id: peer_id.to_string(),
        t: 1,
        n: 1,
        public_key_hex: pk_hex.clone(),
        material: KeyMaterial::Singleton {
            private_key_hex: hex::encode(sk.to_bytes()),
        },
    })?;
    info!("key '{key_id}' is now a singleton held by this peer");

    for other in &others {
        mesh.send_direct(other, b"ok".to_vec())?;
    }
    // give the acks a moment to flush before the mesh shuts down
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(pk_hex)
}

/// t-of-n -> t'-of-n' via the dkls23 quorum change protocol.
async fn quorum_change_flow(
    mesh: &mut Mesh,
    key_id: &str,
    peer_id: &str,
    old: &OldParams,
    my_old: Option<&ShareFile>,
    new_t: u8,
    new_n: u8,
) -> Result<String> {
    let order = mesh.peer_ids();
    let my_idx = mesh.my_index();
    let total = order.len();
    let holders = holder_peer_ids(mesh);
    let pk_point = pubkey_point(&old.pubkey)?;

    let old_parties: Vec<usize> = mesh
        .participants
        .iter()
        .enumerate()
        .filter(|(_, h)| h.payload.get("holder") == Some(&json!(true)))
        .map(|(idx, _)| idx)
        .collect();
    ensure!(
        old_parties.len() >= old.t as usize,
        "need at least {} holders online, have {}",
        old.t,
        old_parties.len()
    );

    // new quorum: the first new_n participants in sorted order. When
    // new_n == total this is everyone; when shrinking (old_t > new_n) the
    // quorum predicate guarantees all participants are holders.
    let new_parties: Vec<(usize, u8)> = (0..new_n as usize).map(|idx| (idx, 0u8)).collect();

    let old_keyshare = my_old.map(|sf| sf.keyshare()).transpose()?.map(Arc::new);

    let instance =
        ids::reshare_instance(key_id, "qc", old.t, new_t, new_n, &order, &holders);

    let setup = sl_dkls23::setup::quorum_change::SetupMessage::new(
        InstanceId::new(instance),
        my_idx,
        &old_parties,
        &new_parties,
        new_t as usize,
        NoSigningKey,
        ops::no_vks(total),
        pk_point,
    )
    .with_keyshare_opt(old_keyshare);

    info!(
        "running quorum change: {}-of-{} -> {new_t}-of-{new_n} (participant {my_idx} of {total})",
        old.t, old.n
    );
    let result = sl_dkls23::keygen::quorum_change::run(setup, ops::seed(), mesh.relay())
        .await
        .map_err(|e| anyhow!("quorum change failed: {e:?}"))?;

    match result {
        Some(share) => {
            let pk_hex = store::pubkey_hex_of(&share.public_key());
            ensure!(
                pk_hex == old.pubkey,
                "public key changed during reshare: {pk_hex} != {}",
                old.pubkey
            );
            store::save(&ShareFile {
                key_id: key_id.to_string(),
                peer_id: peer_id.to_string(),
                t: new_t,
                n: new_n,
                public_key_hex: pk_hex.clone(),
                material: KeyMaterial::Threshold {
                    keyshare_b64: store::keyshare_b64(&share),
                },
            })?;
            info!("new {new_t}-of-{new_n} share stored");
            Ok(pk_hex)
        }
        None => {
            if my_old.is_some() {
                store::delete(key_id, peer_id)?;
                info!("this peer is not part of the new quorum; old share deleted");
            }
            Ok(old.pubkey.clone())
        }
    }
}
