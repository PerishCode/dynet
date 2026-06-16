use std::env;

use dynet_cli::Args;
use dynet_ingress::{IngressConfig, OutboundConfig};
use dynet_runtime::RuntimeState;
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
    let outbound = state.config.outbound;
    let runtime = RuntimeState::single_node(outbound.tag());
    spawn_ingress(ingress, outbound, runtime.clone());
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
        "dynet: ingress listening on dns={} tcp={} udp={}",
        ingress.dns.bind, ingress.tcp.bind, ingress.udp.bind
    );
    dynet_api::serve(listener, runtime)
        .await
        .map_err(|error| format!("control plane failed: {error}"))
}

fn spawn_ingress(config: IngressConfig, outbound: OutboundConfig, runtime: RuntimeState) {
    tokio::spawn(dynet_ingress::run_dns(config.dns, runtime.clone()));
    tokio::spawn(dynet_ingress::run_tcp_with_outbound(
        config.tcp,
        outbound.clone(),
        runtime.clone(),
    ));
    tokio::spawn(dynet_ingress::run_udp_with_outbound(
        config.udp, outbound, runtime,
    ));
}
