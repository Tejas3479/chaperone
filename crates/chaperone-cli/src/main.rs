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
    /// Run the onboarding sequence
    #[command(name = "onboard")]
    Onboard {
        /// Path to the vault database file
        #[arg(long, default_value = "chaperone.db")]
        vault_path: String,
    },
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
        Some(Commands::Onboard { vault_path }) => {
            use chaperone_core::identity::{IdentityError, LocalIdentity};
            use chaperone_core::rotation::RotationChain;
            use chaperone_core::secret_key::SecretKey;
            use chaperone_core::vault::VaultStore;
            use rand::seq::SliceRandom;
            use std::io::{self, Write};
            use std::path::Path;

            let path = Path::new(&vault_path);

            // 0. Preliminary check: if vault exists, is initialized, and is protected, error out
            if path.exists() {
                if let Ok(store) = VaultStore::open(path).await {
                    if let Ok(true) = store.is_initialized().await {
                        if let Ok(true) = store.is_protected().await {
                            eprintln!(
                                "Error: The vault at {:?} is already onboarded and protected.",
                                path
                            );
                            std::process::exit(1);
                        }
                    }
                }
            }

            // 1. Call LocalIdentity::bootstrap() — print "Identity created."
            let identity = match LocalIdentity::bootstrap() {
                Ok(ident) => {
                    println!("Identity created.");
                    ident
                }
                Err(IdentityError::AlreadyBootstrapped) => match LocalIdentity::get_current() {
                    Ok(ident) => {
                        println!("Identity created.");
                        ident
                    }
                    Err(e) => {
                        eprintln!(
                            "Error: Identity already exists, but failed to load it: {}",
                            e
                        );
                        std::process::exit(1);
                    }
                },
                Err(e) => {
                    eprintln!("Error bootstrapping identity: {}", e);
                    std::process::exit(1);
                }
            };

            // 2. Prompt the user (via CLI stdin prompt) to set a PIN; call VaultStore::open() + KDF chain to initialize vault_header; print "Vault created."
            print!("Enter a PIN to protect your vault: ");
            io::stdout().flush().unwrap();
            let mut pin = String::new();
            io::stdin().read_line(&mut pin).unwrap();
            let pin = pin.trim();
            if pin.is_empty() {
                eprintln!("Error: PIN cannot be empty.");
                std::process::exit(1);
            }

            let store = match VaultStore::open(path).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error opening vault store: {}", e);
                    std::process::exit(1);
                }
            };

            let _vault_key = match store.is_initialized().await {
                Ok(false) => match store.initialize_vault(pin.as_bytes()).await {
                    Ok(key) => key,
                    Err(e) => {
                        eprintln!("Error initializing vault: {}", e);
                        std::process::exit(1);
                    }
                },
                Ok(true) => match store.unlock_key(pin.as_bytes()).await {
                    Ok(key) => key,
                    Err(e) => {
                        eprintln!("Error unlocking existing vault: {}", e);
                        std::process::exit(1);
                    }
                },
                Err(e) => {
                    eprintln!("Error checking vault initialization status: {}", e);
                    std::process::exit(1);
                }
            };
            println!("Vault created.");

            // 3. Generate the Secret Key; display it to the user (as the Base32 string); store only its verifier hash in vault_header.
            let secret_key = SecretKey::generate();
            let formatted_key = secret_key.to_base32();
            println!("Secret Key: {}", formatted_key);

            let verifier_hash = secret_key.verifier_hash();
            if let Err(e) = store.set_secret_key_verifier(&verifier_hash).await {
                eprintln!("Error storing secret key verifier: {}", e);
                std::process::exit(1);
            }

            // 4. Create the genesis RotationRecord (BU-106).
            let _chain = RotationChain::genesis(&identity);

            // 5. Force a backup-verification step: re-prompt the user to type back 3 words or 3 groups from the Secret Key they were just shown
            let groups: Vec<&str> = formatted_key.split('-').collect();
            let mut indices = vec![0, 1, 2, 3, 4, 5, 6];
            let mut rng = rand::thread_rng();
            indices.shuffle(&mut rng);
            let mut chosen = indices[0..3].to_vec();
            chosen.sort();

            for &idx in &chosen {
                print!("Enter group {}: ", idx + 1);
                io::stdout().flush().unwrap();
                let mut answer = String::new();
                io::stdin().read_line(&mut answer).unwrap();
                let answer = answer.trim().to_uppercase();
                if answer.is_empty() || answer != groups[idx].to_uppercase() {
                    eprintln!("Verification failed: incorrect group.");
                    std::process::exit(1);
                }
            }

            // 6. Only after step 5 succeeds, mark the vault as "protected" and print "Onboarding complete."
            if let Err(e) = store.mark_protected().await {
                eprintln!("Error marking vault as protected: {}", e);
                std::process::exit(1);
            }
            println!("Onboarding complete.");
        }
        None => {
            println!("chaperone-cli {}", env!("CARGO_PKG_VERSION"));
        }
    }
}
