use std::{
    fs::{File, OpenOptions},
    io,
    os::{fd::AsRawFd, unix::process::CommandExt},
    path::Path,
    process::ExitStatus,
    time::Duration,
};

use dynet_state::AppState;
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
    let inherited_tun = inherited_tun_device(spec)?;
    let mut command = Command::new(&spec.executable);
    command
        .arg("run")
        .arg("--config")
        .arg(&spec.config)
        .kill_on_drop(true);
    if let Some(file) = inherited_tun.as_ref() {
        command.env(INHERITED_TUN_FD_ENV, file.as_raw_fd().to_string());
    }
    let uid = identity.uid;
    let gid = identity.gid;
    unsafe {
        command
            .as_std_mut()
            .pre_exec(move || configure_child_identity(uid, gid));
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("failed starting supervised dynet runtime: {error}"))?;
    drop(inherited_tun);
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

const TUN_DEVICE: &str = "/dev/net/tun";
const INHERITED_TUN_FD_ENV: &str = "DYNET_INHERITED_TUN_FD";

fn inherited_tun_device(spec: &ServiceSpec) -> Result<Option<File>, String> {
    let state = AppState::from_config_path(Some(&spec.config))?;
    if !state.config.capture.tun.enabled {
        return Ok(None);
    }
    preopen_tun(Path::new(TUN_DEVICE))
        .map(Some)
        .map_err(|error| {
            format!("failed pre-opening {TUN_DEVICE} for the supervised runtime: {error}")
        })
}

#[doc(hidden)]
pub fn preopen_tun(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    let flags = unsafe {
        // SAFETY: F_GETFD only reads descriptor flags for this valid file.
        libc::fcntl(file.as_raw_fd(), libc::F_GETFD)
    };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = unsafe {
        // SAFETY: F_SETFD updates descriptor flags for this valid file. Clearing
        // FD_CLOEXEC is required only across the immediately following spawn.
        libc::fcntl(file.as_raw_fd(), libc::F_SETFD, flags & !libc::FD_CLOEXEC)
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

fn configure_child_identity(uid: u32, gid: u32) -> io::Result<()> {
    let current_uid = unsafe { libc::geteuid() };
    let current_gid = unsafe { libc::getegid() };
    if current_uid != 0 {
        return if current_uid == uid && current_gid == gid {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "non-root dynet supervisor cannot change child identity",
            ))
        };
    }

    cvt(unsafe { libc::setgroups(0, std::ptr::null()) })?;
    cvt(unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) })?;
    cvt(unsafe { libc::setgid(gid) })?;
    cvt(unsafe { libc::setuid(uid) })?;
    retain_net_admin_capability()?;
    cvt(unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_RAISE,
            CAP_NET_ADMIN,
            0,
            0,
        )
    })?;
    cvt(unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) })?;
    Ok(())
}

const CAP_NET_ADMIN: libc::c_ulong = 12;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn retain_net_admin_capability() -> io::Result<()> {
    let header = CapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mask = 1_u32 << CAP_NET_ADMIN;
    let data = [
        CapabilityData {
            effective: mask,
            permitted: mask,
            inheritable: mask,
        },
        CapabilityData::default(),
    ];
    let result = unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn cvt(result: libc::c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
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
