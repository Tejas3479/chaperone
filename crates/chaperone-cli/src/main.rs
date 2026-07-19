// chaperone-cli: scaffold

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "chaperone-cli")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Chaperone CLI tool", long_about = None)]
struct Cli {}

fn main() {
    let _args = Cli::parse();
    println!("chaperone-cli {}", env!("CARGO_PKG_VERSION"));
}
