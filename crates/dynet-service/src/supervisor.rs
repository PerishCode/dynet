use std::{os::unix::process::CommandExt, process::ExitStatus, time::Duration};

use tokio::{process::Command, time::timeout};

use crate::{resolve_identity_with, runner::run_required, HostRunner, ServiceRunner, ServiceSpec};

pub async fn supervise(
    spec: &ServiceSpec,
    cleanup: impl Fn() -> Result<(), String>,
) -> Result<(), String> {
    supervise_with(spec, &HostRunner, cleanup).await
}

pub async fn supervise_with(
    spec: &ServiceSpec,
    runner: &impl ServiceRunner,
    cleanup: impl Fn() -> Result<(), String>,
) -> Result<(), String> {
    let identity = resolve_identity_with(&spec.user, runner)?;
    cleanup().map_err(|error| format!("dynet service startup cleanup failed: {error}"))?;
    let executable = spec.executable.to_str().ok_or_else(|| {
        format!(
            "service executable {} is not UTF-8",
            spec.executable.display()
        )
    })?;
    run_required(
        runner,
        executable,
        &["apply".to_string(), "--auto".to_string()],
    )?;
    let mut command = Command::new(&spec.executable);
    command
        .arg("run")
        .arg("--config")
        .arg(&spec.config)
        .kill_on_drop(true);
    command.as_std_mut().uid(identity.uid).gid(identity.gid);
    let mut child = command
        .spawn()
        .map_err(|error| format!("failed starting supervised dynet runtime: {error}"))?;
    let pid = child
        .id()
        .ok_or_else(|| "supervised dynet runtime has no process id".to_string())?;

    let outcome = wait_for_child(pid, &mut child).await;
    let cleanup_result = cleanup();
    if let Err(error) = cleanup_result {
        return Err(format!("dynet service fail-open cleanup failed: {error}"));
    }
    let (status, terminated) = outcome?;
    if terminated || status.success() {
        Ok(())
    } else {
        Err(format!("supervised dynet runtime exited with {status}"))
    }
}

async fn wait_for_child(
    pid: u32,
    child: &mut tokio::process::Child,
) -> Result<(ExitStatus, bool), String> {
    let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .map_err(|error| format!("failed registering supervisor SIGHUP handler: {error}"))?;
    let mut terminate =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|error| format!("failed registering supervisor SIGTERM handler: {error}"))?;
    let mut interrupt =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .map_err(|error| format!("failed registering supervisor SIGINT handler: {error}"))?;
    loop {
        tokio::select! {
            status = child.wait() => {
                return status
                    .map(|status| (status, false))
                    .map_err(|error| format!("failed waiting for supervised dynet runtime: {error}"));
            }
            signal = hangup.recv() => {
                if signal.is_none() {
                    return Err("supervisor SIGHUP stream closed".to_string());
                }
                send_signal(pid, libc::SIGHUP)?;
            }
            signal = terminate.recv() => {
                if signal.is_none() {
                    return Err("supervisor SIGTERM stream closed".to_string());
                }
                return terminate_child(pid, child).await.map(|status| (status, true));
            }
            signal = interrupt.recv() => {
                if signal.is_none() {
                    return Err("supervisor SIGINT stream closed".to_string());
                }
                return terminate_child(pid, child).await.map(|status| (status, true));
            }
        }
    }
}

async fn terminate_child(
    pid: u32,
    child: &mut tokio::process::Child,
) -> Result<ExitStatus, String> {
    send_signal(pid, libc::SIGTERM)?;
    match timeout(Duration::from_secs(8), child.wait()).await {
        Ok(result) => result.map_err(|error| format!("failed waiting for dynet shutdown: {error}")),
        Err(_) => {
            child
                .start_kill()
                .map_err(|error| format!("failed killing timed-out dynet runtime: {error}"))?;
            child
                .wait()
                .await
                .map_err(|error| format!("failed reaping killed dynet runtime: {error}"))
        }
    }
}

fn send_signal(pid: u32, signal: libc::c_int) -> Result<(), String> {
    let pid = i32::try_from(pid).map_err(|_| format!("process id {pid} does not fit i32"))?;
    let result = unsafe { libc::kill(pid, signal) };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "failed sending signal {signal} to dynet pid {pid}: {}",
            std::io::Error::last_os_error()
        ))
    }
}
