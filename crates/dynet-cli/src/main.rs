use dynet_ingress::{EventStore, IngressConfig};
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
    let state = AppState::from_env()?;
    let ingress = state.config.ingress;
    let events = EventStore::default();
    spawn_ingress(ingress, events.clone());
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

fn spawn_ingress(config: IngressConfig, events: EventStore) {
    tokio::spawn(dynet_ingress::run_dns(config.dns, events.clone()));
    tokio::spawn(dynet_ingress::run_tcp(config.tcp, events.clone()));
    tokio::spawn(dynet_ingress::run_udp(config.udp, events));
}
