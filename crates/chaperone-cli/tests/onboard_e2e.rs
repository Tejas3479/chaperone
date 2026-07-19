use chaperone_core::secret_key::SecretKey;
use chaperone_core::vault::VaultStore;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn get_cli_executable() -> PathBuf {
    let mut exe_path = std::env::current_exe().unwrap();
    exe_path.pop();
    if exe_path.file_name().map(|n| n.to_str().unwrap()) == Some("deps") {
        exe_path.pop();
    }
    let mut cli_exe = exe_path.join("chaperone-cli");
    if cfg!(windows) {
        cli_exe.set_extension("exe");
    }
    if !cli_exe.exists() {
        let mut p = std::env::current_dir().unwrap();
        loop {
            let target_debug = p.join("target").join("debug").join(if cfg!(windows) {
                "chaperone-cli.exe"
            } else {
                "chaperone-cli"
            });
            if target_debug.exists() {
                return target_debug;
            }
            if !p.pop() {
                break;
            }
        }
    }
    cli_exe
}

async fn read_until<R: tokio::io::AsyncRead + Unpin>(reader: &mut R, suffix: &str) -> String {
    let mut buffer = Vec::new();
    let mut temp = [0u8; 1];
    let start = Instant::now();
    loop {
        if start.elapsed() > Duration::from_secs(10) {
            panic!("Timeout waiting for suffix: {:?}", suffix);
        }
        let n = tokio::io::AsyncReadExt::read(reader, &mut temp)
            .await
            .unwrap();
        if n == 0 {
            break;
        }
        buffer.push(temp[0]);
        let s = String::from_utf8_lossy(&buffer);
        if s.contains(suffix) {
            return s.into_owned();
        }
    }
    String::from_utf8_lossy(&buffer).into_owned()
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
    // Try ss command
    let output = Command::new("ss").args(["-t", "-u", "-p", "-n"]).output();
    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            if line.contains(&format!("pid={}", pid)) {
                let is_loopback = line.contains("127.0.0.1")
                    || line.contains("::1")
                    || line.contains("localhost");
                if !is_loopback {
                    eprintln!("DEBUG ss matched: {}", line);
                    detected = true;
                }
            }
        }
    }
    // Try lsof command as fallback
    let output = Command::new("lsof")
        .args(["-i", "-P", "-n", "-p", &pid.to_string()])
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
                eprintln!("DEBUG lsof matched: {}", line);
                detected = true;
            }
        }
    }
    detected
}

#[tokio::test]
async fn test_successful_onboarding_e2e_and_offline() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("onboard.db");

    let cli_path = get_cli_executable();
    let mut child = tokio::process::Command::new(&cli_path)
        .arg("onboard")
        .arg("--vault-path")
        .arg(&db_path)
        .env("CHAPERONE_MOCK_KEYCHAIN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    let pid = child.id().unwrap();
    let mut network_detected = false;

    // Read until PIN prompt
    let out = read_until(&mut stdout, "protect your vault: ").await;
    assert!(out.contains("Identity created."));

    // Check network
    if has_active_network_connections(pid) {
        network_detected = true;
    }

    // Write PIN
    tokio::io::AsyncWriteExt::write_all(&mut stdin, b"correctPIN123\n")
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::flush(&mut stdin).await.unwrap();

    // Read until Secret Key label
    let out = read_until(&mut stdout, "Secret Key: ").await;
    assert!(out.contains("Vault created."));

    // Read Secret Key itself (until newline)
    let key_line = read_until(&mut stdout, "\n").await;
    let secret_key_str = key_line.trim();

    // Verify key length
    assert_eq!(secret_key_str.len(), 32); // 26 chars + 6 hyphens

    let groups: Vec<&str> = secret_key_str.split('-').collect();
    assert_eq!(groups.len(), 7);

    // Prompt for 3 groups
    for _ in 0..3 {
        let _prompt_prefix = read_until(&mut stdout, "Enter group ").await;
        let prompt_suffix = read_until(&mut stdout, ": ").await;
        let group_num_str = prompt_suffix.split(':').next().unwrap().trim();
        let group_idx: usize = group_num_str.parse::<usize>().unwrap() - 1;

        if has_active_network_connections(pid) {
            network_detected = true;
        }

        let answer = format!("{}\n", groups[group_idx]);
        tokio::io::AsyncWriteExt::write_all(&mut stdin, answer.as_bytes())
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::flush(&mut stdin).await.unwrap();
    }

    // Read remainder of stdout to get complete confirmation
    let mut remainder = String::new();
    tokio::io::AsyncReadExt::read_to_string(&mut stdout, &mut remainder)
        .await
        .unwrap();
    assert!(remainder.contains("Onboarding complete."));

    // Verify process exited successfully
    let status = child.wait().await.unwrap();
    assert!(status.success());

    // Assert that absolutely zero network calls occurred
    assert!(
        !network_detected,
        "Network calls were detected during onboarding!"
    );

    // Verify database file is marked protected and contains correct Secret Key verifier
    let store = VaultStore::open(&db_path).await.unwrap();
    assert!(store.is_protected().await.unwrap());

    let verifier = store.get_secret_key_verifier().await.unwrap();
    let secret_key = SecretKey::from_base32(secret_key_str).unwrap();
    assert!(secret_key.verify(&verifier));
}

#[tokio::test]
async fn test_failed_backup_verification_does_not_protect_vault() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("onboard_fail.db");

    let cli_path = get_cli_executable();
    let mut child = tokio::process::Command::new(&cli_path)
        .arg("onboard")
        .arg("--vault-path")
        .arg(&db_path)
        .env("CHAPERONE_MOCK_KEYCHAIN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    // Read until PIN prompt
    read_until(&mut stdout, "protect your vault: ").await;

    // Write PIN
    tokio::io::AsyncWriteExt::write_all(&mut stdin, b"correctPIN123\n")
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::flush(&mut stdin).await.unwrap();

    // Read until Secret Key
    read_until(&mut stdout, "Secret Key: ").await;
    let _key_line = read_until(&mut stdout, "\n").await;

    // Prompt for the first group and supply incorrect value
    let _prompt_prefix = read_until(&mut stdout, "Enter group ").await;
    let _prompt_suffix = read_until(&mut stdout, ": ").await;
    tokio::io::AsyncWriteExt::write_all(&mut stdin, b"WRONG\n")
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::flush(&mut stdin).await.unwrap();

    // Verify process exits with failure
    let status = child.wait().await.unwrap();
    assert!(!status.success());

    // Read stderr
    let mut stderr_content = String::new();
    let mut stderr = child.stderr.take().unwrap();
    tokio::io::AsyncReadExt::read_to_string(&mut stderr, &mut stderr_content)
        .await
        .unwrap();
    assert!(stderr_content.contains("Verification failed"));

    // Verify database exists but is NOT marked protected
    let store = VaultStore::open(&db_path).await.unwrap();
    assert!(!store.is_protected().await.unwrap());
}

#[tokio::test]
async fn test_duplicate_onboarding_errors_clearly() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("onboard_dup.db");

    let cli_path = get_cli_executable();

    // First onboarding run - successful completion
    {
        let mut child = tokio::process::Command::new(&cli_path)
            .arg("onboard")
            .arg("--vault-path")
            .arg(&db_path)
            .env("CHAPERONE_MOCK_KEYCHAIN", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let mut stdin = child.stdin.take().unwrap();
        let mut stdout = child.stdout.take().unwrap();

        read_until(&mut stdout, "protect your vault: ").await;
        tokio::io::AsyncWriteExt::write_all(&mut stdin, b"correctPIN123\n")
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::flush(&mut stdin).await.unwrap();

        read_until(&mut stdout, "Secret Key: ").await;
        let key_line = read_until(&mut stdout, "\n").await;
        let secret_key_str = key_line.trim();
        let groups: Vec<&str> = secret_key_str.split('-').collect();

        for _ in 0..3 {
            let _prompt_prefix = read_until(&mut stdout, "Enter group ").await;
            let prompt_suffix = read_until(&mut stdout, ": ").await;
            let group_num_str = prompt_suffix.split(':').next().unwrap().trim();
            let group_idx: usize = group_num_str.parse::<usize>().unwrap() - 1;

            let answer = format!("{}\n", groups[group_idx]);
            tokio::io::AsyncWriteExt::write_all(&mut stdin, answer.as_bytes())
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::flush(&mut stdin).await.unwrap();
        }

        let status = child.wait().await.unwrap();
        assert!(status.success());
    }

    // Second onboarding run on the same database path - must fail immediately
    {
        let child = tokio::process::Command::new(&cli_path)
            .arg("onboard")
            .arg("--vault-path")
            .arg(&db_path)
            .env("CHAPERONE_MOCK_KEYCHAIN", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let output = child.wait_with_output().await.unwrap();
        assert!(!output.status.success());

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("already onboarded and protected"));
    }
}
