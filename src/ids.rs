//! Deterministic derivation of protocol instance ids and helpers.
//!
//! Every participant must independently derive the same `InstanceId` for a
//! protocol run, so all inputs are canonical: sorted peer id lists, explicit
//! numeric parameters and a per-operation domain separation tag.

use sha2::{Digest, Sha256};

pub const TOOL_ID: &str = "dkls23ctl/1";

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Hash of the message to be signed.
pub fn msg_hash(msg: &str) -> [u8; 32] {
    sha256(msg.as_bytes())
}

fn instance(tag: &str, key_id: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(TOOL_ID.as_bytes());
    h.update([0u8]);
    h.update(tag.as_bytes());
    h.update([0u8]);
    h.update(key_id.as_bytes());
    h.update([0u8]);
    for p in parts {
        h.update((p.len() as u64).to_le_bytes());
        h.update(p);
    }
    h.finalize().into()
}

fn join_ids(ids: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for id in ids {
        out.extend_from_slice((id.len() as u64).to_le_bytes().as_ref());
        out.extend_from_slice(id.as_bytes());
    }
    out
}

pub fn keygen_instance(key_id: &str, t: u8, n: u8, sorted_peers: &[String]) -> [u8; 32] {
    instance("keygen", key_id, &[&[t, n], &join_ids(sorted_peers)])
}

pub fn sign_instance(
    key_id: &str,
    msg_hash: &[u8; 32],
    subset_peers: &[String],
    subset_party_ids: &[u8],
) -> [u8; 32] {
    instance(
        "sign",
        key_id,
        &[msg_hash, &join_ids(subset_peers), subset_party_ids],
    )
}

pub fn reshare_instance(
    key_id: &str,
    flavor: &str, // "import" | "export" | "qc"
    old_t: u8,
    new_t: u8,
    new_n: u8,
    sorted_peers: &[String],
    holder_peers: &[String],
) -> [u8; 32] {
    instance(
        "reshare",
        key_id,
        &[
            flavor.as_bytes(),
            &[old_t, new_t, new_n],
            &join_ids(sorted_peers),
            &join_ids(holder_peers),
        ],
    )
}

/// Rendezvous string announced via mDNS user data so that peers only talk to
/// instances working on the same key id.
pub fn rendezvous(key_id: &str) -> String {
    let h = sha256(format!("{TOOL_ID}|{key_id}").as_bytes());
    format!("dkls23ctl-{}", hex::encode(&h[..8]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_deterministic_and_order_sensitive() {
        let peers = vec!["a".to_string(), "b".to_string()];
        let i1 = keygen_instance("k", 2, 2, &peers);
        let i2 = keygen_instance("k", 2, 2, &peers);
        assert_eq!(i1, i2);

        let swapped = vec!["b".to_string(), "a".to_string()];
        assert_ne!(i1, keygen_instance("k", 2, 2, &swapped));
        assert_ne!(i1, keygen_instance("k2", 2, 2, &peers));
        assert_ne!(i1, keygen_instance("k", 2, 3, &peers));
    }

    #[test]
    fn join_ids_unambiguous() {
        // ["ab", "c"] must differ from ["a", "bc"]
        let a = join_ids(&["ab".into(), "c".into()]);
        let b = join_ids(&["a".into(), "bc".into()]);
        assert_ne!(a, b);
    }

    #[test]
    fn rendezvous_depends_on_key() {
        assert_ne!(rendezvous("k1"), rendezvous("k2"));
        assert!(rendezvous("k1").len() < 60);
    }
}
