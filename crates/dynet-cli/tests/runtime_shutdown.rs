#![cfg(unix)]

use std::{
    fs,
    io::Read,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use tempfile::TempDir;

#[test]
fn sigterm_exits_cleanly() {
    let directory = TempDir::new().expect("tempdir");
    let config = directory.path().join("dynet.toml");
    let database = directory.path().join("dynet.sqlite");
    fs::write(
        &config,
        format!(
            r#"[control]
bind = "127.0.0.1:0"

[ingress.dns]
bind = "127.0.0.1:0"

[ingress.tcp]
bind = "127.0.0.1:0"

[ingress.udp]
bind = "127.0.0.1:0"

[ingress.socks5]
bind = "127.0.0.1:0"

[service]
runtime_database = "{}"
"#,
            database.display()
        ),
    )
    .expect("write config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_dynet"))
        .arg("run")
        .arg("--config")
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dynet");
    thread::sleep(Duration::from_millis(300));
    assert!(child.try_wait().expect("try wait").is_none());

    let signal = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .expect("send SIGTERM");
    assert!(signal.success());

    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try wait") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "dynet did not exit after SIGTERM"
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert!(status.success(), "dynet exited with {status}");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(stderr.contains("SIGTERM received"), "stderr: {stderr}");
    assert!(
        stderr.contains("runtime shutdown complete"),
        "stderr: {stderr}"
    );
    assert!(database.is_file());
}
