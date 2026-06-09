//! In-process protocol tests: run the real dkls23 protocols over the same
//! `MsgStore`/`NetRelay` bridge the networked tool uses, with an in-memory
//! "bus" instead of iroh connections.

use std::sync::Arc;
use std::time::Duration;

use dkls23ctl::ids;
use dkls23ctl::ops::no_vks;
use dkls23ctl::relay::{MsgStore, NetRelay};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::VerifyingKey;
use k256::{NonZeroScalar, ProjectivePoint, Scalar};
use sl_dkls23::keygen::key_refresh::KeyshareForRefresh;
use sl_dkls23::keygen::Keyshare;
use sl_dkls23::setup::NoSigningKey;
use sl_mpc_mate::message::InstanceId;
use tokio::sync::mpsc;

/// Create n relays whose published messages are delivered to all other
/// parties, mimicking the iroh broadcast mesh.
fn bus(n: usize) -> Vec<NetRelay> {
    let stores: Vec<MsgStore> = (0..n).map(|_| MsgStore::new()).collect();
    let mut relays = Vec::new();
    for i in 0..n {
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let others: Vec<MsgStore> = stores
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, s)| s.clone())
            .collect();
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                for s in &others {
                    s.on_network(msg.clone());
                }
            }
        });
        dkls23ctl::relay::spawn_timeout_checker(stores[i].clone());
        relays.push(NetRelay::new(&stores[i], tx));
    }
    relays
}

fn peer_names(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("peer{i}")).collect()
}

async fn gen_key(t: u8, n: u8, key_id: &str) -> Vec<Keyshare> {
    let peers = peer_names(n as usize);
    let instance = ids::keygen_instance(key_id, t, n, &peers);
    let mut set = tokio::task::JoinSet::new();
    for (idx, relay) in bus(n as usize).into_iter().enumerate() {
        let setup = sl_dkls23::setup::keygen::SetupMessage::new(
            InstanceId::new(instance),
            NoSigningKey,
            idx,
            no_vks(n as usize),
            &vec![0u8; n as usize],
            t as usize,
        );
        set.spawn(sl_dkls23::keygen::run(setup, rand::random(), relay));
    }
    let mut shares: Vec<Keyshare> = Vec::new();
    while let Some(res) = set.join_next().await {
        shares.push(res.unwrap().expect("keygen failed"));
    }
    shares.sort_by_key(|s| s.party_id);
    shares
}

async fn sign_with(shares: &[&Keyshare], key_id: &str, msg: &str) -> k256::ecdsa::Signature {
    let hash = ids::msg_hash(msg);
    let mut order: Vec<(u8, &Keyshare)> = shares.iter().map(|s| (s.party_id, *s)).collect();
    order.sort_by_key(|(pid, _)| *pid);
    let subset_pids: Vec<u8> = order.iter().map(|(pid, _)| *pid).collect();
    let subset_peers: Vec<String> = subset_pids.iter().map(|p| format!("peer{p}")).collect();
    let instance = ids::sign_instance(key_id, &hash, &subset_peers, &subset_pids);

    let vks: Vec<_> = subset_pids
        .iter()
        .map(|pid| sl_dkls23::setup::NoVerifyingKey::new(*pid as usize))
        .collect();

    let mut set = tokio::task::JoinSet::new();
    for ((idx, (_, share)), relay) in order
        .iter()
        .enumerate()
        .zip(bus(order.len()))
    {
        let setup = sl_dkls23::setup::sign::SetupMessage::new(
            InstanceId::new(instance),
            NoSigningKey,
            idx,
            vks.clone(),
            Arc::new(Keyshare::from_bytes(share.as_slice()).unwrap()),
        )
        .with_hash(hash);
        set.spawn(sl_dkls23::sign::run(setup, rand::random(), relay));
    }
    let mut sigs = Vec::new();
    while let Some(res) = set.join_next().await {
        let (sig, _recid) = res.unwrap().expect("sign failed");
        sigs.push(sig);
    }
    assert!(sigs.windows(2).all(|w| w[0] == w[1]), "signers disagree");
    sigs.pop().unwrap()
}

fn verify(share: &Keyshare, msg: &str, sig: &k256::ecdsa::Signature) {
    let vk = VerifyingKey::from_affine(share.public_key().to_affine()).unwrap();
    vk.verify_prehash(&ids::msg_hash(msg), sig).expect("bad signature");
}

#[tokio::test(flavor = "multi_thread")]
async fn keygen_2of3_sign_with_each_pair() {
    let shares = gen_key(2, 3, "test-key").await;
    let pk0 = shares[0].public_key();
    for s in &shares {
        assert_eq!(s.public_key(), pk0, "parties disagree on public key");
    }
    for (a, b) in [(0usize, 1usize), (0, 2), (1, 2)] {
        let sig = sign_with(&[&shares[a], &shares[b]], "test-key", "hello world").await;
        verify(&shares[0], "hello world", &sig);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn quorum_change_2of3_to_3of4_preserves_pubkey() {
    let old_shares = gen_key(2, 3, "qc-key").await;
    let pk = old_shares[0].public_key();

    // 4 participants: 3 holders + 1 fresh, sorted order = peers 0..3
    let total = 4usize;
    let new_t = 3u8;
    let new_n = 4u8;
    let order = peer_names(total);
    let holders: Vec<String> = order[..3].to_vec();
    let instance = ids::reshare_instance("qc-key", "qc", 2, new_t, new_n, &order, &holders);
    let old_parties: Vec<usize> = vec![0, 1, 2];
    let new_parties: Vec<(usize, u8)> = (0..total).map(|i| (i, 0u8)).collect();

    let mut set = tokio::task::JoinSet::new();
    for (idx, relay) in bus(total).into_iter().enumerate() {
        let keyshare = old_shares
            .get(idx)
            .map(|s| Arc::new(Keyshare::from_bytes(s.as_slice()).unwrap()));
        let setup = sl_dkls23::setup::quorum_change::SetupMessage::new(
            InstanceId::new(instance),
            idx,
            &old_parties,
            &new_parties,
            new_t as usize,
            NoSigningKey,
            no_vks(total),
            pk,
        )
        .with_keyshare_opt(keyshare);
        set.spawn(sl_dkls23::keygen::quorum_change::run(
            setup,
            rand::random(),
            relay,
        ));
    }
    let mut new_shares = Vec::new();
    while let Some(res) = set.join_next().await {
        let share = res.unwrap().expect("quorum change failed").expect("kept in quorum");
        assert_eq!(share.public_key(), pk, "public key changed");
        new_shares.push(share);
    }
    assert_eq!(new_shares.len(), 4);

    new_shares.sort_by_key(|s| s.party_id);
    let refs: Vec<&Keyshare> = new_shares[..3].iter().collect();
    let sig = sign_with(&refs, "qc-key", "after reshare").await;
    verify(&new_shares[0], "after reshare", &sig);
}

#[tokio::test(flavor = "multi_thread")]
async fn import_singleton_to_2of2_preserves_pubkey() {
    let mut rng = rand::thread_rng();
    let private_key = NonZeroScalar::random(&mut rng);
    let expected_pk = ProjectivePoint::GENERATOR * *private_key;

    let kfrs = sl_dkls23::key_import::ecdsa_secret_shares(
        2,
        vec![0, 0],
        &private_key,
        rand::random(),
        None,
        &mut rng,
    );
    assert_eq!(kfrs.len(), 2);

    let order = peer_names(2);
    let holders = vec![order[0].clone()];
    let instance = ids::reshare_instance("imp-key", "import", 1, 2, 2, &order, &holders);

    // exercise the serialization used over the wire
    let kfrs: Vec<KeyshareForRefresh> = kfrs
        .iter()
        .map(|k| KeyshareForRefresh::from_bytes(&k.to_bytes()).unwrap())
        .collect();

    let mut set = tokio::task::JoinSet::new();
    for ((idx, relay), kfr) in bus(2).into_iter().enumerate().zip(kfrs) {
        let setup = sl_dkls23::setup::keygen::SetupMessage::new(
            InstanceId::new(instance),
            NoSigningKey,
            idx,
            no_vks(2),
            &[0u8, 0u8],
            2,
        );
        set.spawn(sl_dkls23::keygen::key_refresh::run(
            setup,
            rand::random(),
            relay,
            kfr,
        ));
    }
    let mut shares = Vec::new();
    while let Some(res) = set.join_next().await {
        shares.push(res.unwrap().expect("key refresh failed"));
    }
    for s in &shares {
        assert_eq!(s.public_key(), expected_pk, "import changed the public key");
    }

    shares.sort_by_key(|s| s.party_id);
    let refs: Vec<&Keyshare> = shares.iter().collect();
    let sig = sign_with(&refs, "imp-key", "imported").await;
    verify(&shares[0], "imported", &sig);
}

#[tokio::test(flavor = "multi_thread")]
async fn export_2of3_to_plain_key() {
    let shares = gen_key(2, 3, "exp-key").await;
    let pk = shares[0].public_key();

    // combine shares of parties 0 and 2 (any t shares work)
    let x_i_list = shares[0].x_i_list();
    let xs: Vec<(NonZeroScalar, usize)> = vec![
        (x_i_list[0], 0),
        (x_i_list[2], 0),
    ];
    let ss: Vec<Scalar> = vec![shares[0].s_i(), shares[2].s_i()];
    let secret =
        sl_dkls23::key_export::combine_shares(&xs, &ss, &pk).expect("combine failed");

    assert_eq!(ProjectivePoint::GENERATOR * secret, pk);

    // the reconstructed plain key signs and verifies against the same pubkey
    let sk = k256::ecdsa::SigningKey::from_slice(&secret.to_bytes()).unwrap();
    let hash = ids::msg_hash("exported");
    let (sig, _) = sk.sign_prehash_recoverable(&hash).unwrap();
    let vk = VerifyingKey::from_affine(pk.to_affine()).unwrap();
    vk.verify_prehash(&hash, &sig).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_peer_times_out() {
    // 2-of-2 keygen but only one party runs; its ask TTL is short
    let peers = peer_names(2);
    let instance = ids::keygen_instance("timeout-key", 2, 2, &peers);
    let relays = bus(2);
    let mut it = relays.into_iter();
    let relay0 = it.next().unwrap();

    let setup = sl_dkls23::setup::keygen::SetupMessage::new(
        InstanceId::new(instance),
        NoSigningKey,
        0,
        no_vks(2),
        &[0u8, 0u8],
        2,
    )
    .with_ttl(Duration::from_secs(2));

    let res = tokio::time::timeout(
        Duration::from_secs(30),
        sl_dkls23::keygen::run(setup, rand::random(), relay0),
    )
    .await
    .expect("did not time out in time");
    assert!(res.is_err(), "keygen should fail when the peer is missing");
}
