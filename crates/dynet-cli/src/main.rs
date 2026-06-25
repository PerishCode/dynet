use std::{collections::BTreeMap, env, path::PathBuf};

use dynet_cli::Args;
use dynet_ingress::{EgressNodeConfig, IngressConfig};
use dynet_runtime::{RuntimeState, RuntimeStore};
use dynet_state::AppState;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("dynet: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let args = Args::parse(env::args_os().skip(1))?;
    let state = AppState::from_config_path(args.config.as_deref())?;
    let ingress = state.config.ingress;
    let execution_nodes = state.config.forwarding.execution_nodes.clone();
    let runtime_seed = state.config.forwarding.seed;
    let store = RuntimeStore::open(runtime_db_path()?)
        .await
        .map_err(|error| format!("failed to open runtime store: {error}"))?;
    let runtime = RuntimeState::from_store_seed(store, runtime_seed)
        .await
        .map_err(|error| format!("failed to initialize runtime state: {error}"))?;
    spawn_ingress(ingress, execution_nodes, runtime.clone());
    let listener = TcpListener::bind(state.config.control.bind)
        .await
        .map_err(|error| {
            format!(
                "failed to bind control plane {}: {error}",
                state.config.control.bind
            )
        })?;
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
