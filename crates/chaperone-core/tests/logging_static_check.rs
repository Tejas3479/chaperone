use chaperone_core::logging::Scrubbed;
use chaperone_core::secret_key::SecretKey;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing_appender::non_blocking::WorkerGuard;

#[test]
fn test_scrubbed_known_value_debug_formatting() {
    let raw_bytes: [u8; 32] = [0xa5; 32];
    let scrubbed = Scrubbed(raw_bytes);
    let debug_output = format!("{:?}", scrubbed);

    // Assert it formats to [SCRUBBED]
    assert_eq!(debug_output, "[SCRUBBED]");

    // Assert the raw bytes/hex never appear in the formatted output
    let hex_representation = data_encoding::HEXLOWER.encode(&raw_bytes);
    assert!(!debug_output.contains(&hex_representation));
    assert!(!debug_output.contains("165")); // 0xa5 is 165
}

fn init_logging_for_test(log_dir: &Path) -> (tracing::subscriber::DefaultGuard, WorkerGuard) {
    std::fs::create_dir_all(log_dir).unwrap();
    let file_appender = tracing_appender::rolling::daily(log_dir, "chaperone.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(non_blocking)
        .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
        .finish();

    let default_guard = tracing::subscriber::set_default(subscriber);
    (default_guard, guard)
}

#[test]
fn test_logging_subsystem_writes_locally_and_redacts_keys() {
    let temp_dir = tempfile::tempdir().unwrap();
    let log_dir = temp_dir.path().join("logs");

    // Initialize logging - writes locally to the daily log thread-locally
    let (_dg, guard) = init_logging_for_test(&log_dir);

    // Generate keys
    let secret_key = SecretKey::generate();
    let secret_key_base32 = secret_key.to_base32();

    // Log the secret key
    tracing::info!(key = ?secret_key, "Testing secret key logging");

    // Flush logs by dropping the guard
    drop(guard);

    // Read the log file
    let log_files = fs::read_dir(&log_dir).unwrap();
    let mut found_log = false;
    for file in log_files {
        let file = file.unwrap();
        let content = fs::read_to_string(file.path()).unwrap();
        found_log = true;

        // Verify that the log contains the structure but it's scrubbed
        assert!(content.contains("[SCRUBBED]"), "Log content: {}", content);

        // Confirm the raw key's Base32 string is NOT present in the logs
        assert!(
            !content.contains(&secret_key_base32),
            "Base32 key leaked in logs!"
        );

        // Confirm raw bytes of the key are not in the logs
        let raw_bytes = secret_key.to_bytes();
        let bytes_string = format!("{:?}", raw_bytes);
        assert!(
            !content.contains(&bytes_string),
            "Raw key bytes leaked in logs!"
        );
    }
    assert!(found_log, "No log files were written to the temp directory");
}

#[test]
fn test_logging_subsystem_does_not_make_network_calls() {
    let temp_dir = tempfile::tempdir().unwrap();
    let log_dir = temp_dir.path().join("network_logs");

    // 1. Initial check of active network connections for this process
    let pid = std::process::id();
    let initial_connections = has_active_network_connections(pid);

    // 2. Initialize and trigger logs
    {
        let (_dg, guard) = init_logging_for_test(&log_dir);
        tracing::info!("Triggering some log events to run the logging subsystem");
        tracing::warn!("Another warning event");
        drop(guard);
    }

    // 3. Final check of active network connections
    let final_connections = has_active_network_connections(pid);

    // If there were no network connections initially, there should still be none
    if !initial_connections {
        assert!(
            !final_connections,
            "Network connections were opened by the logging subsystem!"
        );
    }
}

// --- Static Code Analysis Check ---

fn find_crates_dir() -> PathBuf {
    let mut dir = std::env::current_dir().unwrap();
    loop {
        let crates_path = dir.join("crates");
        if crates_path.exists() && crates_path.is_dir() {
            return crates_path;
        }
        if let Some(parent) = dir.parent() {
            dir = parent.to_path_buf();
        } else {
            panic!(
                "Could not find crates directory starting from {:?}",
                std::env::current_dir()
            );
        }
    }
}

#[test]
fn test_sensitive_fields_are_scrubbed_in_structs() {
    // Start from the resolved crates directory
    let crates_dir = find_crates_dir();
    let files = get_rs_files(&crates_dir);
    assert!(!files.is_empty(), "No Rust files found to scan!");

    let mut violations = Vec::new();

    for file in files {
        let content = fs::read_to_string(&file).expect("Failed to read Rust file");
        let stripped = strip_comments(&content);

        let file_violations = scan_file_for_unscrubbed_sensitive_fields(&file, &stripped);
        violations.extend(file_violations);
    }

    if !violations.is_empty() {
        let mut error_msg = String::from("Found sensitive fields not wrapped in Scrubbed<T>:\n");
        for violation in violations {
            error_msg.push_str(&format!(
                "  File: {}, Struct: {}, Field: '{}', Type: '{}'\n",
                violation.file.display(),
                violation.struct_name,
                violation.field_name,
                violation.field_type
            ));
        }
        panic!("{}", error_msg);
    }
}

struct FieldViolation {
    file: PathBuf,
    struct_name: String,
    field_name: String,
    field_type: String,
}

fn get_rs_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if dir.is_dir() {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    files.extend(get_rs_files(&path));
                } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                    files.push(path);
                }
            }
        }
    }
    files
}

fn strip_comments(content: &str) -> String {
    let mut result = String::new();
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut chars = content.chars().peekable();

    while let Some(ch) = chars.next() {
        if in_line_comment {
            if ch == '\n' {
                in_line_comment = false;
                result.push('\n');
            }
        } else if in_block_comment {
            if ch == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block_comment = false;
            }
        } else {
            if ch == '/' && chars.peek() == Some(&'/') {
                chars.next();
                in_line_comment = true;
            } else if ch == '/' && chars.peek() == Some(&'*') {
                chars.next();
                in_block_comment = true;
            } else {
                result.push(ch);
            }
        }
    }
    result
}

fn scan_file_for_unscrubbed_sensitive_fields(file: &Path, content: &str) -> Vec<FieldViolation> {
    let mut violations = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    let mut in_struct = false;
    let mut struct_name = String::new();
    let mut brace_count = 0;

    // List of words that suggest a sensitive field
    let sensitive_keywords = [
        "secret",
        "private",
        "privkey",
        "priv_key",
        "pin",
        "seed",
        "vault_key",
        "passphrase",
        "password",
        "credential",
    ];

    // List of fields that are explicitly whitelisted (e.g. public keys or metadata)
    let whitelist = [
        "new_pubkey",
        "signed_by_previous_key",
        "did_key",
        "store",
        "created_at",
        "rotation_epoch",
        "pool",
    ];

    for line in lines {
        let trimmed = line.trim();

        if !in_struct {
            if trimmed.contains("struct ") && !trimmed.contains(";") {
                // Try parsing struct name
                if let Some(struct_idx) = trimmed.find("struct ") {
                    let after_struct = &trimmed[struct_idx + 7..];
                    let end_idx = after_struct
                        .find(|c: char| !c.is_alphanumeric() && c != '_')
                        .unwrap_or(after_struct.len());
                    struct_name = after_struct[..end_idx].to_string();

                    if trimmed.contains('{') {
                        in_struct = true;
                        brace_count = 1;
                    }
                }
            }
        } else {
            // Count braces to trace structure boundary
            for ch in trimmed.chars() {
                if ch == '{' {
                    brace_count += 1;
                } else if ch == '}' {
                    brace_count -= 1;
                }
            }

            if brace_count == 0 {
                in_struct = false;
                struct_name.clear();
                continue;
            }

            if brace_count == 1 && trimmed.contains(':') {
                let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
                let field_part = parts[0].trim();
                let type_part = parts[1].trim();

                // Extract field name (last word before colon)
                let field_name = field_part
                    .split_whitespace()
                    .last()
                    .unwrap_or("")
                    .trim_start_matches("pub")
                    .trim();

                // Clean type name (up to comma)
                let end_type = type_part.find(',').unwrap_or(type_part.len());
                let field_type = type_part[..end_type].trim().to_string();

                if field_name.is_empty() {
                    continue;
                }

                // Check if field name contains any sensitive keyword
                let is_sensitive = sensitive_keywords
                    .iter()
                    .any(|&keyword| field_name.to_lowercase().contains(keyword));

                if is_sensitive {
                    // Check if it is whitelisted
                    let is_whitelisted = whitelist.iter().any(|&w| field_name == w);

                    if !is_whitelisted {
                        // Check if it is wrapped in Scrubbed
                        let is_scrubbed = field_type.contains("Scrubbed")
                            || field_type.contains("crate::logging::Scrubbed");

                        if !is_scrubbed {
                            violations.push(FieldViolation {
                                file: file.to_path_buf(),
                                struct_name: struct_name.clone(),
                                field_name: field_name.to_string(),
                                field_type,
                            });
                        }
                    }
                }
            }
        }
    }
    violations
}

#[cfg(target_os = "windows")]
fn has_active_network_connections(pid: u32) -> bool {
    let output = Command::new("netstat").arg("-ano").output();
    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(&last) = parts.last() {
                if last == pid.to_string() {
                    let is_loopback = line.contains("127.0.0.1")
                        || line.contains("[::1]")
                        || line.contains("localhost");
                    if !is_loopback {
                        return true;
                    }
                }
            }
        }
    }
    false
}

#[cfg(not(target_os = "windows"))]
fn has_active_network_connections(pid: u32) -> bool {
    let mut detected = false;
    let output = Command::new("ss").args(["-t", "-u", "-p", "-n"]).output();
    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            if line.contains(&format!("pid={}", pid)) {
                let is_loopback = line.contains("127.0.0.1")
                    || line.contains("::1")
                    || line.contains("localhost");
                if !is_loopback {
                    detected = true;
                }
            }
        }
    }
    let output = Command::new("lsof")
        .args(["-a", "-i", "-P", "-n", "-p", &pid.to_string()])
        .output();
    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            if line.contains("COMMAND") || line.trim().is_empty() {
                continue;
            }
            let is_loopback =
                line.contains("127.0.0.1") || line.contains("::1") || line.contains("localhost");
            if !is_loopback {
                detected = true;
            }
        }
    }
    detected
}
