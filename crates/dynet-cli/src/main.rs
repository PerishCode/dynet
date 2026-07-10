use std::{env, time::Duration};

use dynet_capture::{
    ApplyOptions, CheckState, LinuxTakeover, TakeoverPlan, TakeoverReport, TakeoverStatus,
    TunProbeRead,
};
use dynet_cli::{Args, Command, ConfigAction, ReloadResult, RuntimeReload};
use dynet_ingress::{IngressConfig, ReloadableEgress};
use dynet_runtime::{ConfigReloadTrigger, RuntimeState, RuntimeStore};
use dynet_state::AppState;
use tokio::{
    net::TcpListener,
    sync::mpsc,
    task::JoinHandle,
    time::{timeout, Instant},
};
use tokio_util::sync::CancellationToken;

mod paths;
mod service;
mod service_runtime;
mod tun;

use paths::resolve_runtime_path;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("dynet: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let args = Args::parse(env::args_os().skip(1))?;
    let config = args.config.clone();
    match args.command {
        Command::Run => run_runtime(args).await,
        Command::Plan => run_plan(),
        Command::Doctor => run_doctor(),
        Command::Status => run_status(),
        Command::Apply { auto } => run_apply(auto),
        Command::Reconcile => run_reconcile(),
        Command::Cleanup => run_cleanup(),
        Command::Config { action } => run_config(action, config.as_deref()),
        Command::Hooks { action } => service::run_hooks(action, config.as_deref()),
        Command::RouterHooks { action } => service::run_router_hooks(action, config.as_deref()),
        Command::DnsMapping { action } => service::run_dns_mapping(action, config.as_deref()),
        Command::Service { action } => service::run(action, config.as_deref()).await,
        Command::IpStackPoc {
            interface,
            max_tcp,
            max_udp,
            idle_ms,
            udp_response_ms,
        } => tun::run_poc(interface, max_tcp, max_udp, idle_ms, udp_response_ms).await,
        Command::IpStackRuntimePoc {
            interface,
            max_tcp,
            max_udp,
            idle_ms,
            udp_response_ms,
            tcp_idle_ms,
        } => {
            tun::run_runtime_poc(
                config,
                interface,
                max_tcp,
                max_udp,
                idle_ms,
                udp_response_ms,
                tcp_idle_ms,
            )
            .await
        }
        Command::TunProbe { interface, wait_ms } => run_tun_probe(interface.as_deref(), wait_ms),
    }
}

fn run_config(action: ConfigAction, config_path: Option<&std::path::Path>) -> Result<(), String> {
    let state = AppState::from_config_path(config_path)?;
    match action {
        ConfigAction::Summary => {
            for line in dynet_state::redacted_summary_lines(&state.config) {
                println!("{line}");
            }
        }
        ConfigAction::Validate => println!("dynet config validate: ok"),
    }
    Ok(())
}

fn run_plan() -> Result<(), String> {
    print_takeover_plan(&LinuxTakeover::default().plan());
    Ok(())
}

async fn run_runtime(args: Args) -> Result<(), String> {
    let state = AppState::from_config_path(args.config.as_deref())?;
    let config_path = args.config.clone();
    let control = state.config.control;
    let ingress = state.config.ingress;
    let runtime_seed = state.config.forwarding.seed.clone();
    let store = RuntimeStore::open_with_policy(
        resolve_runtime_path(
            &state.config.service.runtime_database,
            config_path.as_deref(),
        )?,
        state.config.persistence,
    )
    .await
    .map_err(|error| format!("failed to open runtime store: {error}"))?;
    let runtime = RuntimeState::from_store_seed(store.clone(), runtime_seed)
        .await
        .map_err(|error| format!("failed to initialize runtime state: {error}"))?;
    let reload = RuntimeReload::new(state.config, config_path, runtime.clone(), store)?;
    let listener = TcpListener::bind(control.bind)
        .await
        .map_err(|error| format!("failed to bind control plane {}: {error}", control.bind))?;
    let local_addr = listener
        .local_addr()
        .map_err(|error| format!("failed to read control plane address: {error}"))?;
    let shutdown = CancellationToken::new();
    let (failure_tx, mut failure_rx) = mpsc::unbounded_channel();
    let mut tasks = spawn_ingress(
        ingress,
        reload.egress(),
        runtime.clone(),
        shutdown.clone(),
        failure_tx.clone(),
    );
    if let Some(capture) = tun::spawn_capture(
        reload.tun_config(),
        reload.egress(),
        runtime.clone(),
        shutdown.clone(),
    ) {
        tasks.push(monitor_joined_task(
            "TUN capture",
            capture,
            shutdown.clone(),
            failure_tx.clone(),
        ));
    }
    tasks.push(spawn_signal_control(reload.clone(), shutdown.clone())?);
    eprintln!("dynet: control plane listening on http://{local_addr}/api/v1");
    eprintln!(
        "dynet: ingress listening on dns={} tcp={} udp={} socks5={}",
        ingress.dns.bind, ingress.tcp.bind, ingress.udp.bind, ingress.socks5.bind
    );
    let config_status = reload.audit().status();
    eprintln!(
        "dynet: runtime config generation={} fingerprint={} source={}",
        config_status.generation, config_status.fingerprint, config_status.source
    );
    let api_shutdown = shutdown.clone();
    let server = dynet_api::serve_with_audit_shutdown(
        listener,
        runtime.clone(),
        reload.audit(),
        async move { api_shutdown.cancelled().await },
    );
    tokio::pin!(server);
    let server_result = tokio::select! {
        result = &mut server => result
            .map_err(|error| format!("control plane failed: {error}")),
        _ = shutdown.cancelled() => match timeout(Duration::from_secs(1), &mut server).await {
            Ok(result) => result.map_err(|error| format!("control plane failed: {error}")),
            Err(_) => Err("control plane graceful shutdown timed out".to_string()),
        },
    };
    shutdown.cancel();
    drain_runtime_tasks(tasks, Duration::from_secs(4)).await;
    timeout(Duration::from_secs(2), runtime.flush_persistence())
        .await
        .map_err(|_| "runtime persistence flush timed out".to_string())??;
    eprintln!("dynet: runtime shutdown complete");
    if let Ok(error) = failure_rx.try_recv() {
        return Err(error);
    }
    server_result
}

#[cfg(unix)]
fn spawn_signal_control(
    reload: RuntimeReload,
    shutdown: CancellationToken,
) -> Result<JoinHandle<()>, String> {
    let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .map_err(|error| format!("failed to register SIGHUP handler: {error}"))?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|error| format!("failed to register SIGTERM handler: {error}"))?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|error| format!("failed to register SIGINT handler: {error}"))?;
    Ok(tokio::spawn(async move {
        loop {
            tokio::select! {
                signal = hangup.recv() => {
                    if signal.is_none() {
                        return;
                    }
                    log_reload_result(reload.reload(ConfigReloadTrigger::Sighup).await);
                }
                _ = terminate.recv() => {
                    eprintln!("dynet: SIGTERM received, beginning graceful shutdown");
                    shutdown.cancel();
                    return;
                }
                _ = interrupt.recv() => {
                    eprintln!("dynet: SIGINT received, beginning graceful shutdown");
                    shutdown.cancel();
                    return;
                }
                _ = shutdown.cancelled() => return,
            }
        }
    }))
}

#[cfg(not(unix))]
fn spawn_signal_control(
    _reload: RuntimeReload,
    shutdown: CancellationToken,
) -> Result<JoinHandle<()>, String> {
    Ok(tokio::spawn(async move {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => shutdown.cancel(),
            _ = shutdown.cancelled() => {},
        }
    }))
}

fn log_reload_result(result: ReloadResult) {
    match result {
        ReloadResult::Applied {
            generation,
            changed_fields,
        } => eprintln!(
            "dynet: config reload applied generation={} changed={}",
            generation,
            changed_fields.join(",")
        ),
        ReloadResult::Noop { generation } => {
            eprintln!("dynet: config reload no-op generation={generation}")
        }
        ReloadResult::RestartRequired { generation, fields } => eprintln!(
            "dynet: config reload rejected generation={} restart-required={}",
            generation,
            fields.join(",")
        ),
        ReloadResult::Invalid { generation } => {
            eprintln!("dynet: config reload rejected generation={generation} reason=invalid-config")
        }
        ReloadResult::Failed { generation } => {
            eprintln!("dynet: config reload failed generation={generation} reason=runtime-commit")
        }
    }
}

fn run_doctor() -> Result<(), String> {
    let report = LinuxTakeover::default().doctor();
    print_takeover_report("doctor", &report);
    if report.has_hard_failures() {
        return Err(report.failure_summary());
    }
    Ok(())
}

fn run_status() -> Result<(), String> {
    let status = LinuxTakeover::default().status();
    print_takeover_status("status", &status);
    if status.has_hard_failures() {
        return Err(status.doctor.failure_summary());
    }
    Ok(())
}

fn run_apply(auto: bool) -> Result<(), String> {
    let report = LinuxTakeover::default().apply(ApplyOptions { auto })?;
    for path in &report.created {
        println!("created {}", path.display());
    }
    for action in &report.runtime_actions {
        println!("{action}");
    }
    print_takeover_report("apply", &report.status);
    Ok(())
}

fn run_reconcile() -> Result<(), String> {
    let report = LinuxTakeover::default().apply(ApplyOptions { auto: false })?;
    print_takeover_report("reconcile", &report.status);
    Ok(())
}

fn run_cleanup() -> Result<(), String> {
    let report = LinuxTakeover::default().cleanup()?;
    for action in report.runtime_actions {
        println!("{action}");
    }
    for path in report.removed {
        println!("removed {}", path.display());
    }
    Ok(())
}

fn run_tun_probe(interface: Option<&str>, wait_ms: u64) -> Result<(), String> {
    let wait = Duration::from_millis(wait_ms);
    let report = if wait_ms == 0 {
        match interface {
            Some(interface) => dynet_capture::probe_linux_tun(interface),
            None => dynet_capture::probe_default_linux_tun(),
        }
    } else {
        dynet_capture::probe_linux_tun_wait(interface.unwrap_or("dynet0"), wait)
    }
    .map_err(|error| format!("TUN probe failed: {error}"))?;
    println!(
        "dynet TUN probe: opened {} as {}",
        report.open.device.display(),
        report.open.interface
    );
    match report.nonblocking_read {
        TunProbeRead::WouldBlock => println!("dynet TUN probe: nonblocking read would block"),
        TunProbeRead::Packet(len) => println!("dynet TUN probe: read packet bytes={len}"),
        TunProbeRead::Eof => println!("dynet TUN probe: read EOF"),
    }
    Ok(())
}

fn print_takeover_plan(plan: &TakeoverPlan) {
    println!("dynet takeover plan:");
    for item in &plan.items {
        println!(
            "- {} [{} {}]: {}",
            item.id,
            item.phase.label(),
            item.safety.label(),
            item.action
        );
    }
}

fn print_takeover_status(label: &str, status: &TakeoverStatus) {
    print_takeover_report(label, &status.doctor);
    println!("dynet runtime {label}:");
    print_check_lines(&status.runtime);
}

fn print_takeover_report(label: &str, report: &TakeoverReport) {
    println!("dynet takeover {label}:");
    print_check_lines(&report.checks);
}

fn print_checks(label: &str, checks: &[dynet_capture::TakeoverCheck]) {
    println!("dynet {label}:");
    print_check_lines(checks);
}

fn print_check_lines(checks: &[dynet_capture::TakeoverCheck]) {
    for check in checks {
        let path = check
            .path
            .as_ref()
            .map(|path| format!(" {}", path.display()))
            .unwrap_or_default();
        let action = check
            .auto_action
            .filter(|_| matches!(check.state, CheckState::MissingAutoCreatable))
            .map(|action| format!(" auto={action}"))
            .unwrap_or_default();
        println!("- {}: {}{}{}", check.id, check.state.label(), path, action);
    }
}

fn spawn_ingress(
    config: IngressConfig,
    egress: ReloadableEgress,
    runtime: RuntimeState,
    shutdown: CancellationToken,
    failure_tx: mpsc::UnboundedSender<String>,
) -> Vec<JoinHandle<()>> {
    let dns_config = config.dns;
    let socks5_config = config.socks5;
    let tcp_config = config.tcp;
    let udp_config = config.udp;

    let dns_runtime = runtime.clone();
    let mut tasks = vec![monitor_runtime_task(
        "DNS ingress",
        dynet_ingress::run_dns_until(dns_config, dns_runtime, shutdown.clone()),
        shutdown.clone(),
        failure_tx.clone(),
    )];

    let socks5_runtime = runtime.clone();
    let socks5_egress = egress.clone();
    tasks.push(monitor_runtime_task(
        "SOCKS5 ingress",
        dynet_ingress::run_socks5_reloadable_until(
            socks5_config,
            socks5_egress,
            socks5_runtime,
            shutdown.clone(),
        ),
        shutdown.clone(),
        failure_tx.clone(),
    ));

    let tcp_runtime = runtime.clone();
    let tcp_egress = egress.clone();
    tasks.push(monitor_runtime_task(
        "TCP ingress",
        dynet_ingress::run_tcp_reloadable_until(
            tcp_config,
            tcp_egress,
            tcp_runtime,
            shutdown.clone(),
        ),
        shutdown.clone(),
        failure_tx.clone(),
    ));

    tasks.push(monitor_runtime_task(
        "UDP ingress",
        dynet_ingress::run_udp_reloadable_until(udp_config, egress, runtime, shutdown.clone()),
        shutdown,
        failure_tx,
    ));
    tasks
}

fn monitor_runtime_task<F>(
    label: &'static str,
    future: F,
    shutdown: CancellationToken,
    failure_tx: mpsc::UnboundedSender<String>,
) -> JoinHandle<()>
where
    F: std::future::Future<Output = Result<(), String>> + Send + 'static,
{
    tokio::spawn(async move {
        match future.await {
            Ok(()) if shutdown.is_cancelled() => {}
            Ok(()) => {
                let error = format!("{label} stopped unexpectedly");
                let _ = failure_tx.send(error);
                shutdown.cancel();
            }
            Err(error) => {
                let error = format!("{label} failed: {error}");
                let _ = failure_tx.send(error);
                shutdown.cancel();
            }
        }
    })
}

fn monitor_joined_task(
    label: &'static str,
    task: JoinHandle<Result<(), String>>,
    shutdown: CancellationToken,
    failure_tx: mpsc::UnboundedSender<String>,
) -> JoinHandle<()> {
    monitor_runtime_task(
        label,
        async move {
            task.await
                .map_err(|error| format!("task join failed: {error}"))?
        },
        shutdown,
        failure_tx,
    )
}

async fn drain_runtime_tasks(tasks: Vec<JoinHandle<()>>, grace: Duration) {
    let deadline = Instant::now() + grace;
    for mut task in tasks {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || timeout(remaining, &mut task).await.is_err() {
            task.abort();
            let _ = task.await;
        }
    }
}
