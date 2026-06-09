use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use k256::ecdsa::signature::hazmat::PrehashVerifier;

use dkls23ctl::{ids, ops, store};

/// Threshold ECDSA (DKLs23) over iroh p2p — key generation, signing and
/// resharing on localhost/LAN without any server.
#[derive(Parser)]
#[command(name = "dkls23ctl", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new t-of-n key. Starts when n instances with the same
    /// --key-id (and distinct --peer-id) are running. t=1 (with n=1)
    /// generates a plain ECDSA singleton key locally.
    Keygen {
        /// Threshold
        #[arg(short = 't', long)]
        t: u8,
        /// Total number of parties (defaults to t)
        #[arg(short = 'n', long)]
        n: Option<u8>,
        /// Unique identifier of this peer
        #[arg(long)]
        peer_id: String,
        /// Identifier of the new key (same on all peers)
        #[arg(long)]
        key_id: String,
    },
    /// Show the public key of a previously generated key.
    Pubkey {
        #[arg(long)]
        key_id: String,
    },
    /// Sign a message (its SHA-256 hash). Starts once at least t instances
    /// with the same --key-id and --msg are running.
    Sign {
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        peer_id: String,
        /// Message to sign
        #[arg(long)]
        msg: String,
    },
    /// Reshare an existing key to new t-of-n parameters; the public key is
    /// preserved. Starts when max(n, old_t) instances are running.
    Reshare {
        #[arg(long)]
        peer_id: String,
        #[arg(long)]
        key_id: String,
        /// New threshold
        #[arg(short = 't', long)]
        t: u8,
        /// New total number of parties (defaults to t)
        #[arg(short = 'n', long)]
        n: Option<u8>,
    },
    /// Verify a signature produced by `sign`.
    Verify {
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        msg: String,
        /// Signature, hex encoded (64 bytes r||s, or 65 with recovery byte)
        #[arg(long)]
        signature: String,
    },
}

fn verify(key_id: &str, msg: &str, signature: &str) -> Result<()> {
    let vk = ops::keygen::load_pubkey(key_id)?;
    let mut sig_bytes = hex::decode(signature).context("signature is not valid hex")?;
    if sig_bytes.len() == 65 {
        sig_bytes.truncate(64); // drop recovery id byte
    }
    if sig_bytes.len() != 64 {
        bail!(
            "expected a 64-byte (or 65-byte) signature, got {} bytes",
            sig_bytes.len()
        );
    }
    let sig = k256::ecdsa::Signature::from_slice(&sig_bytes).context("malformed signature")?;
    let hash = ids::msg_hash(msg);
    match vk.verify_prehash(&hash, &sig) {
        Ok(()) => {
            println!("OK");
            Ok(())
        }
        Err(_) => {
            println!("INVALID");
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,iroh=warn,swarm_discovery=warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen {
            t,
            n,
            peer_id,
            key_id,
        } => ops::keygen::run(&key_id, &peer_id, t, n.unwrap_or(t)).await,
        Cmd::Pubkey { key_id } => {
            println!("{}", store::public_key_hex(&key_id)?);
            Ok(())
        }
        Cmd::Sign {
            key_id,
            peer_id,
            msg,
        } => ops::sign::run(&key_id, &peer_id, &msg).await,
        Cmd::Reshare {
            peer_id,
            key_id,
            t,
            n,
        } => ops::reshare::run(&key_id, &peer_id, t, n.unwrap_or(t)).await,
        Cmd::Verify {
            key_id,
            msg,
            signature,
        } => verify(&key_id, &msg, &signature),
    }
}
