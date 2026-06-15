use std::env;

use dynet_cli::Args;
use dynet_ingress::{EventStore, IngressConfig, OutboundConfig};
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
    let events = EventStore::default();
    spawn_ingress(ingress, outbound, events.clone());
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
    dynet_api::serve(listener, events)
        .await
        .map_err(|error| format!("control plane failed: {error}"))
}

fn spawn_ingress(config: IngressConfig, outbound: OutboundConfig, events: EventStore) {
    tokio::spawn(dynet_ingress::run_dns(config.dns, events.clone()));
    tokio::spawn(dynet_ingress::run_tcp_with_outbound(
        config.tcp,
        outbound.clone(),
        events.clone(),
    ));
    tokio::spawn(dynet_ingress::run_udp_with_outbound(
        config.udp, outbound, events,
    ));
}
