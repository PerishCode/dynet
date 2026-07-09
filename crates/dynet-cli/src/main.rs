use std::{collections::BTreeMap, env, path::PathBuf, time::Duration};

use dynet_capture::{
    ApplyOptions, CheckState, LinuxTakeover, TakeoverPlan, TakeoverReport, TakeoverStatus,
    TunProbeRead,
};
use dynet_cli::{Args, Command, ConfigAction, HooksAction};
use dynet_ingress::{EgressNodeConfig, IngressConfig};
use dynet_runtime::{RuntimeState, RuntimeStore};
use dynet_state::AppState;
use tokio::net::TcpListener;

mod tun;

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
        Command::Hooks { action } => run_hooks(action),
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
    let control = state.config.control;
    let ingress = state.config.ingress;
    let capture = state.config.capture;
    let execution_nodes = state.config.forwarding.execution_nodes.clone();
    let runtime_seed = state.config.forwarding.seed;
    let store = RuntimeStore::open(runtime_db_path()?)
        .await
        .map_err(|error| format!("failed to open runtime store: {error}"))?;
    let runtime = RuntimeState::from_store_seed(store, runtime_seed)
        .await
        .map_err(|error| format!("failed to initialize runtime state: {error}"))?;
    spawn_ingress(ingress, execution_nodes.clone(), runtime.clone());
    tun::spawn_capture(capture.tun, execution_nodes, runtime.clone());
    let listener = TcpListener::bind(control.bind)
        .await
        .map_err(|error| format!("failed to bind control plane {}: {error}", control.bind))?;
    let local_addr = listener
        .local_addr()
        .map_err(|error| format!("failed to read control plane address: {error}"))?;
    eprintln!("dynet: control plane listening on http://{local_addr}/api/v1");
    eprintln!(
        "dynet: ingress listening on dns={} tcp={} udp={} socks5={}",
        ingress.dns.bind, ingress.tcp.bind, ingress.udp.bind, ingress.socks5.bind
    );
    dynet_api::serve(listener, runtime)
        .await
        .map_err(|error| format!("control plane failed: {error}"))
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

fn run_hooks(action: HooksAction) -> Result<(), String> {
    match action {
        HooksAction::Status => {}
        HooksAction::Apply => {
            for action in LinuxTakeover::default().hooks_apply()? {
                println!("{action}");
            }
        }
        HooksAction::Cleanup => {
            for action in LinuxTakeover::default().hooks_cleanup()? {
                println!("{action}");
            }
        }
    }
    print_checks("hooks status", &LinuxTakeover::default().hooks_status());
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

fn runtime_db_path() -> Result<PathBuf, String> {
    match env::var_os("DYNET_RUNTIME_DB") {
        Some(path) if path.is_empty() => {
            Err("DYNET_RUNTIME_DB requires a non-empty path".to_string())
        }
        Some(path) => Ok(PathBuf::from(path)),
        None => env::current_dir()
            .map(|directory| directory.join("dynet.sqlite"))
            .map_err(|error| format!("failed to resolve runtime store path: {error}")),
    }
}

fn spawn_ingress(
    config: IngressConfig,
    execution_nodes: BTreeMap<String, EgressNodeConfig>,
    runtime: RuntimeState,
) {
    let dns_config = config.dns;
    let socks5_config = config.socks5;
    let tcp_config = config.tcp;
    let udp_config = config.udp;

    let dns_runtime = runtime.clone();
    tokio::spawn(async move {
        if let Err(error) = dynet_ingress::run_dns(dns_config, dns_runtime).await {
            eprintln!("dynet: dns ingress stopped: {error}");
        }
    });

    let socks5_runtime = runtime.clone();
    let socks5_nodes = execution_nodes.clone();
    tokio::spawn(async move {
        if let Err(error) =
            dynet_ingress::run_socks5_graph(socks5_config, socks5_nodes, socks5_runtime).await
        {
            eprintln!("dynet: socks5 ingress stopped: {error}");
        }
    });

    let tcp_runtime = runtime.clone();
    let tcp_nodes = execution_nodes.clone();
    tokio::spawn(async move {
        if let Err(error) = dynet_ingress::run_tcp_graph(tcp_config, tcp_nodes, tcp_runtime).await {
            eprintln!("dynet: tcp ingress stopped: {error}");
        }
    });

    tokio::spawn(async move {
        if let Err(error) = dynet_ingress::run_udp_graph(udp_config, execution_nodes, runtime).await
        {
            eprintln!("dynet: udp ingress stopped: {error}");
        }
    });
}
