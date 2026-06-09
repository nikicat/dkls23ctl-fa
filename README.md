# dkls23ctl

CLI for threshold ECDSA (secp256k1) on localhost/LAN — distributed key
generation, signing and resharing built on
[silence-laboratories/dkls23](https://github.com/silence-laboratories/dkls23)
(the DKLs23 MPC protocol suite) with
[iroh](https://github.com/n0-computer/iroh) for fully peer-to-peer transport.

There is no server and no leader: every running instance is an equal peer.
Peers find each other with mDNS (via `iroh-mdns-address-lookup`), using a
rendezvous string derived from the `--key-id`, build a QUIC full mesh
(iroh relay servers are disabled) and start the MPC protocol once the
required number of participants is online. The current online peer count is
logged by every instance while it waits.

## Usage

```sh
# 2-of-3 distributed key generation: run three of these in parallel
# (same --key-id, distinct --peer-id). Starts when all n are online.
dkls23ctl keygen -t2 -n3 --peer-id p1 --key-id mykey   # prints the pubkey
dkls23ctl keygen -t2 -n3 --peer-id p2 --key-id mykey
dkls23ctl keygen -t2 -n3 --peer-id p3 --key-id mykey

# -n defaults to -t. t=1 generates a plain (singleton) ECDSA key locally:
dkls23ctl keygen -t1 --peer-id solo --key-id mykey2

# show the public key (same for all peers, so no --peer-id)
dkls23ctl pubkey --key-id mykey

# sign SHA-256(msg): run at least t instances with the same --msg
dkls23ctl sign --key-id mykey --peer-id p1 --msg "pay 42"
dkls23ctl sign --key-id mykey --peer-id p3 --msg "pay 42"  # prints 64-byte sig hex

# verify
dkls23ctl verify --key-id mykey --msg "pay 42" --signature <hex>

# reshare to new t-of-n (public key is preserved); starts when
# max(new_n, old_t) instances are running
dkls23ctl reshare --peer-id p1 --key-id mykey -t3 -n4
```

Key shares are stored in `./.secrets/<key_id>/<peer_id>.json` together with
the generation parameters (t, n, public key). Set `DKLS23CTL_SECRETS_DIR` to
relocate the store. Logs go to stderr (`RUST_LOG` to adjust), results
(pubkey/signature) go to stdout.

### Resharing flows

`reshare` picks one of three flows based on the old and new parameters:

| old → new            | mechanism                                                            | who must run |
|----------------------|----------------------------------------------------------------------|--------------|
| t-of-n → t'-of-n'    | dkls23 `quorum_change`                                               | max(n', old t) peers, at least old t of them holders |
| singleton → t-of-n   | dkls23 key import (`ecdsa_secret_shares` + `key_refresh`)            | the holder + n−1 new peers |
| t-of-n → singleton   | dkls23 key export (`combine_shares`); receiver = lowest peer id      | old t holders |

When shrinking, the first `new_n` participants (sorted by `--peer-id`) form
the new quorum; dropped participants delete their share files. Temporary
import/export shares travel only over iroh's end-to-end-encrypted QUIC
connections, directly to their recipient.

## Design notes

* **Party ordering / instance ids.** All participants sort the session's
  peer ids and derive party indices plus the dkls23 `InstanceId` from the
  same canonical data (tool id, key id, parameters, sorted peer list), so no
  coordination round is needed.
* **Transport.** dkls23 abstracts messaging behind the `Relay` trait of
  `sl-mpc-mate` (publish/ask by 32-byte message id). `src/relay.rs`
  implements it with a local message store; publications are broadcast to
  every peer over the mesh and incoming messages are buffered until the
  protocol asks for them. dkls23's own p2p payloads are
  end-to-end encrypted by the protocol itself, so broadcasting them is safe.
* **Timeouts.** Message TTLs use the dkls23 default (100 s). If a peer goes
  offline mid-protocol, pending asks expire and the whole operation fails.
* **Authentication.** dkls23-level message signing is disabled
  (`NoSigningKey`, as in the upstream examples); transport security and peer
  authentication come from iroh's QUIC/TLS with endpoint keys. This matches
  the tool's trusted-LAN scope — don't use it across hostile networks.

## Limitations

* The quorum snapshot is taken after a short settle window. If you start
  *more* instances than required at nearly the same moment for `keygen` or
  `reshare`, peers may disagree on the participant set and the run fails by
  timeout (signing tolerates extras: the t lowest party ids sign, the rest
  exit with "not needed").
* `t=1` requires `n=1` (a singleton key); thresholds ≥ 2 are real MPC.
* One operation per key at a time; peers find each other only by key id.

## Development

```sh
cargo build            # debug build (intended workflow)
cargo test             # unit tests + in-process protocol tests
scripts/qa_all.sh      # end-to-end QA of every scenario over real networking
```

`scripts/run_many.sh <timeout> <cmd>...` is a small helper that runs several
CLI invocations in parallel and collects their stdout — handy for manual QA.
