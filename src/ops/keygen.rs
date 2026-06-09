//! `keygen` subcommand: distributed key generation (or local singleton).

use std::sync::Arc;

use anyhow::{anyhow, ensure, Context, Result};
use serde_json::json;
use sl_dkls23::setup::NoSigningKey;
use sl_mpc_mate::message::InstanceId;
use tracing::info;

use crate::net::{establish, Hello, SessionConfig};
use crate::store::{self, KeyMaterial, ShareFile};
use crate::{ids, ops};

pub async fn run(key_id: &str, peer_id: &str, t: u8, n: u8) -> Result<()> {
    ensure!(t >= 1, "threshold must be at least 1");
    ensure!(n >= t, "n must be >= t");
    ensure!(
        !store::exists(key_id, peer_id),
        "share for key '{key_id}' / peer '{peer_id}' already exists at {}",
        store::share_path(key_id, peer_id).display()
    );

    if t == 1 {
        ensure!(
            n == 1,
            "t=1 means a singleton (plain ECDSA) key and requires n=1"
        );
        return singleton(key_id, peer_id);
    }

    let pk_hex = distributed(key_id, peer_id, t, n).await?;
    println!("{pk_hex}");
    Ok(())
}

fn singleton(key_id: &str, peer_id: &str) -> Result<()> {
    let sk = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
    let pk_hex = hex::encode(sk.verifying_key().to_encoded_point(true).as_bytes());
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
    info!("generated singleton ECDSA key '{key_id}'");
    println!("{pk_hex}");
    Ok(())
}

async fn distributed(key_id: &str, peer_id: &str, t: u8, n: u8) -> Result<String> {
    let payload = json!({ "t": t, "n": n });
    let hello = Hello::new("keygen", key_id, peer_id, payload.clone());

    let compat = {
        let payload = payload.clone();
        Arc::new(move |h: &Hello| {
            if h.payload == payload {
                Ok(())
            } else {
                Err(format!(
                    "keygen parameter mismatch: peer wants {}, we want {payload}",
                    h.payload
                ))
            }
        })
    };
    let n_usize = n as usize;
    let quorum = Arc::new(move |hs: &[Hello]| hs.len() == n_usize);

    info!("waiting for {n} peers running keygen for key '{key_id}'");
    let mesh = establish(SessionConfig {
        hello,
        compat,
        quorum,
    })
    .await?;

    let order = mesh.peer_ids();
    let my_idx = mesh.my_index();
    let instance = ids::keygen_instance(key_id, t, n, &order);

    let setup = sl_dkls23::setup::keygen::SetupMessage::new(
        InstanceId::new(instance),
        NoSigningKey,
        my_idx,
        ops::no_vks(n_usize),
        &vec![0u8; n_usize],
        t as usize,
    );

    info!("starting DKG as party {my_idx} of {n} (t={t})");
    let relay = mesh.relay();
    let share = sl_dkls23::keygen::run(setup, ops::seed(), relay)
        .await
        .map_err(|e| anyhow!("distributed key generation failed: {e:?}"))?;

    let pk_hex = store::pubkey_hex_of(&share.public_key());
    store::save(&ShareFile {
        key_id: key_id.to_string(),
        peer_id: peer_id.to_string(),
        t,
        n,
        public_key_hex: pk_hex.clone(),
        material: KeyMaterial::Threshold {
            keyshare_b64: store::keyshare_b64(&share),
        },
    })?;
    info!(
        "key share stored at {}",
        store::share_path(key_id, peer_id).display()
    );

    mesh.shutdown().await;
    Ok(pk_hex)
}

/// Shared validation used by `pubkey` and `verify`.
pub fn load_pubkey(key_id: &str) -> Result<k256::ecdsa::VerifyingKey> {
    let pk_hex = store::public_key_hex(key_id)?;
    let bytes = hex::decode(&pk_hex).context("invalid stored public key hex")?;
    k256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes).context("invalid stored public key")
}
