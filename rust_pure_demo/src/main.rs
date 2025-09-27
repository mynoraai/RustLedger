use std::error::Error;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use rust_pure_demo::{Keypair, Ledger};

fn main() -> Result<(), Box<dyn Error>> {
    let Cli { ledger, command } = Cli::parse();

    match command {
        Commands::GenerateKey => {
            let keypair = Keypair::generate();
            let json = serde_json::to_string_pretty(&keypair)?;
            println!("{}", json);
        }
        Commands::Append {
            payload,
            secret_key,
            timestamp,
        } => {
            let mut ledger = Ledger::open(&ledger)?;
            let timestamp = match timestamp {
                Some(value) => value,
                None => SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            };
            let request = ledger.prepare_append(payload, &secret_key, timestamp)?;
            let entry = ledger.append(request)?;
            println!("{}", serde_json::to_string_pretty(entry)?);
        }
        Commands::Show => {
            let ledger = Ledger::open(&ledger)?;
            for entry in ledger.entries() {
                println!("{}", serde_json::to_string_pretty(entry)?);
            }
        }
    }

    Ok(())
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(long, global = true, default_value = "ledger.jsonl")]
    ledger: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a new Ed25519 keypair in base64 form.
    GenerateKey,
    /// Append a payload using the provided secret key.
    Append {
        #[arg(long)]
        payload: String,
        #[arg(long, value_name = "BASE64")]
        secret_key: String,
        #[arg(long)]
        timestamp: Option<u64>,
    },
    /// Print the ledger contents as JSON.
    Show,
}
