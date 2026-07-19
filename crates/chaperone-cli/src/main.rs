// chaperone-cli: scaffold

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "chaperone-cli")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Chaperone CLI tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run a two-instance skeleton ping check
    #[command(name = "skeleton-ping")]
    SkeletonPing,
    /// Bootstrap a new local identity
    #[command(name = "bootstrap")]
    Bootstrap,
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    match args.command {
        Some(Commands::SkeletonPing) => {
            match chaperone_core::mesh_skeleton::run_skeleton_ping().await {
                Ok(_) => {
                    println!("skeleton ping: OK");
                }
                Err(e) => {
                    eprintln!("skeleton ping: FAILED: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Some(Commands::Bootstrap) => {
            use chaperone_core::identity::{IdentityError, LocalIdentity};
            match LocalIdentity::bootstrap() {
                Ok(identity) => {
                    println!("{}", identity.did_key);
                }
                Err(IdentityError::AlreadyBootstrapped) => {
                    match LocalIdentity::get_current() {
                        Ok(identity) => {
                            eprintln!("Identity already bootstrapped.");
                            println!("{}", identity.did_key);
                        }
                        Err(e) => {
                            eprintln!("Error: Identity is already bootstrapped, but failed to load it: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error bootstrapping identity: {}", e);
                    std::process::exit(1);
                }
            }
        }
        None => {
            println!("chaperone-cli {}", env!("CARGO_PKG_VERSION"));
        }
    }
}
