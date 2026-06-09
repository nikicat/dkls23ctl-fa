//! `sign` subcommand: distributed (DSG) or local singleton signing.

use std::sync::Arc;

use anyhow::{anyhow, bail, ensure, Context, Result};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use serde_json::json;
use sl_dkls23::setup::{NoSigningKey, NoVerifyingKey};
use sl_mpc_mate::message::InstanceId;
use tracing::info;

use crate::net::{establish, Hello, SessionConfig};
use crate::store;
use crate::{ids, ops};

pub async fn run(key_id: &str, peer_id: &str, msg: &str) -> Result<()> {
    let sf = store::load(key_id, peer_id)?;
    let hash = ids::msg_hash(msg);

    let sig_hex = if sf.is_singleton() {
        singleton_sign(&sf, &hash)?
    } else {
        distributed_sign(&sf, key_id, peer_id, &hash).await?
    };

    // sanity check against the stored public key before printing
    let vk = super::keygen::load_pubkey(key_id)?;
    let sig = k256::ecdsa::Signature::from_slice(&hex::decode(&sig_hex)?)?;
    vk.verify_prehash(&hash, &sig)
        .context("produced signature failed verification")?;

    println!("{sig_hex}");
    Ok(())
}

fn singleton_sign(sf: &store::ShareFile, hash: &[u8; 32]) -> Result<String> {
    let sk = sf.signing_key()?;
    let (sig, _recovery_id) = sk
        .sign_prehash_recoverable(hash)
        .context("signing failed")?;
    info!("signed locally with singleton key");
    Ok(hex::encode(sig.to_bytes()))
}

async fn distributed_sign(
    sf: &store::ShareFile,
    key_id: &str,
    peer_id: &str,
    hash: &[u8; 32],
) -> Result<String> {
    let share = Arc::new(sf.keyshare()?);
    let t = sf.t;
    let my_kg_pid = share.party_id;
    let hash_hex = hex::encode(hash);

    let payload = json!({
        "t": sf.t,
        "n": sf.n,
        "pubkey": sf.public_key_hex,
        "msg_hash": hash_hex,
        "kg_party_id": my_kg_pid,
    });
    let hello = Hello::new("sign", key_id, peer_id, payload.clone());

    let compat = {
        let payload = payload.clone();
        Arc::new(move |h: &Hello| {
            for field in ["t", "n", "pubkey", "msg_hash"] {
                if h.payload.get(field) != payload.get(field) {
                    return Err(format!(
                        "sign session mismatch on '{field}': peer has {:?}, we have {:?}",
                        h.payload.get(field),
                        payload.get(field)
                    ));
                }
            }
            if h.payload.get("kg_party_id") == payload.get("kg_party_id") {
                return Err("peer holds the same key share (same party id)".into());
            }
            Ok(())
        })
    };
    let t_usize = t as usize;
    let quorum = Arc::new(move |hs: &[Hello]| {
        let mut pids: Vec<u64> = hs
            .iter()
            .filter_map(|h| h.payload.get("kg_party_id").and_then(|v| v.as_u64()))
            .collect();
        pids.sort_unstable();
        pids.dedup();
        pids.len() == hs.len() && hs.len() >= t_usize
    });

    info!("waiting for at least {t} signers for key '{key_id}'");
    let mesh = establish(SessionConfig {
        hello,
        compat,
        quorum,
    })
    .await?;

    // deterministic signer subset: the t lowest keygen party ids
    let mut parts: Vec<(u8, String)> = mesh
        .participants
        .iter()
        .map(|h| {
            let pid = h
                .payload
                .get("kg_party_id")
                .and_then(|v| v.as_u64())
                .context("missing kg_party_id")? as u8;
            Ok((pid, h.peer_id.clone()))
        })
        .collect::<Result<_>>()?;
    parts.sort();
    let subset = &parts[..t_usize];

    let my_idx = match subset.iter().position(|(pid, _)| *pid == my_kg_pid) {
        Some(idx) => idx,
        None => {
            mesh.shutdown().await;
            bail!(
                "signing quorum already has {t} participants; this peer (party {my_kg_pid}) is not needed"
            );
        }
    };

    let subset_peers: Vec<String> = subset.iter().map(|(_, p)| p.clone()).collect();
    let subset_pids: Vec<u8> = subset.iter().map(|(pid, _)| *pid).collect();
    ensure!(
        subset_pids.iter().all(|pid| (*pid as usize) < sf.n as usize),
        "invalid party id in subset"
    );

    let instance = ids::sign_instance(key_id, hash, &subset_peers, &subset_pids);
    let vks: Vec<NoVerifyingKey> = subset_pids
        .iter()
        .map(|pid| NoVerifyingKey::new(*pid as usize))
        .collect();

    let setup = sl_dkls23::setup::sign::SetupMessage::new(
        InstanceId::new(instance),
        NoSigningKey,
        my_idx,
        vks,
        share.clone(),
    )
    .with_hash(*hash);

    info!(
        "starting signing as subset member {my_idx} (party {my_kg_pid}), signers: {:?}",
        subset_peers
    );
    let relay = mesh.relay();
    let (sig, _recovery_id) = sl_dkls23::sign::run(setup, ops::seed(), relay)
        .await
        .map_err(|e| anyhow!("distributed signing failed: {e:?}"))?;

    mesh.shutdown().await;
    Ok(hex::encode(sig.to_bytes()))
}
