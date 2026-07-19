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
        None => {
            println!("chaperone-cli {}", env!("CARGO_PKG_VERSION"));
        }
    }
}
