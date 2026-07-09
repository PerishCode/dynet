use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};

use dynet_capture::IpStackPocOptions;
use dynet_ingress::EgressNodeConfig;
use dynet_runtime::RuntimeState;
use dynet_state::{AppState, TunCaptureConfig};

pub(crate) fn spawn_capture(
    config: TunCaptureConfig,
    execution_nodes: BTreeMap<String, EgressNodeConfig>,
    runtime: RuntimeState,
) {
    if !config.enabled {
        return;
    }

    let interface = config.interface.clone();
    let tcp_idle_timeout = config.tcp_idle_timeout;
    let udp_idle_timeout = config.udp_idle_timeout;
    let udp_response_timeout = config.udp_response_timeout;
    eprintln!(
        "dynet: TUN capture enabled on {} tcp_idle_ms={} udp_idle_ms={} udp_response_ms={}",
        interface,
        tcp_idle_timeout.as_millis(),
        udp_idle_timeout.as_millis(),
        udp_response_timeout.as_millis()
    );

    tokio::spawn(async move {
        let tcp_nodes = execution_nodes.clone();
        let udp_nodes = execution_nodes;
        let tcp_runtime = runtime.clone();
        let udp_runtime = runtime;

        let handle_tcp: dynet_capture::IpStackTcpCaptureHandler = Arc::new(move |tcp| {
            let egress_nodes = tcp_nodes.clone();
            let runtime = tcp_runtime.clone();
            Box::pin(async move {
                let local = tcp.local_addr();
                let target = tcp.peer_addr();
                if !target.ip().is_ipv4() {
                    eprintln!("dynet: TUN tcp skipped local={local} peer={target} reason=non-ipv4");
                    return Ok(());
                }
                eprintln!("dynet: TUN tcp accepted local={local} peer={target}");
                let outcome = dynet_ingress::relay_captured_tcp_graph(
                    tcp,
                    local,
                    target,
                    egress_nodes,
                    runtime,
                    tcp_idle_timeout,
                )
                .await?;
                eprintln!(
                    "dynet: TUN tcp closed local={local} peer={target} upstream={} client_to_upstream={} upstream_to_client={} close_reason={}",
                    outcome.upstream,
                    outcome.client_to_upstream_bytes,
                    outcome.upstream_to_client_bytes,
                    outcome.close_reason
                );
                Ok(())
            }) as dynet_capture::IpStackCaptureFuture
        });

        let handle_udp: dynet_capture::IpStackUdpCaptureHandler = Arc::new(move |udp| {
            let egress_nodes = udp_nodes.clone();
            let runtime = udp_runtime.clone();
            Box::pin(async move {
                let local = udp.local_addr();
                let target = udp.peer_addr();
                if !target.ip().is_ipv4() {
                    eprintln!("dynet: TUN udp skipped local={local} peer={target} reason=non-ipv4");
                    return Ok(());
                }
                eprintln!("dynet: TUN udp accepted local={local} peer={target}");
                let outcome = dynet_ingress::relay_captured_udp_graph(
                    udp,
                    local,
                    target,
                    egress_nodes,
                    runtime,
                    udp_idle_timeout,
                    udp_response_timeout,
                )
                .await?;
                eprintln!(
                    "dynet: TUN udp closed local={local} peer={target} upstream={} request_bytes={} response_bytes={} close_reason={}",
                    outcome.upstream,
                    outcome.request_bytes,
                    outcome.response_bytes,
                    outcome.close_reason
                );
                Ok(())
            }) as dynet_capture::IpStackCaptureFuture
        });

        if let Err(error) =
            dynet_capture::run_capture_forever("tun-capture", interface, handle_tcp, handle_udp)
                .await
        {
            eprintln!("dynet: TUN capture stopped: {error}");
        }
    });
}

pub(crate) async fn run_poc(
    interface: String,
    max_tcp: usize,
    max_udp: usize,
    idle_ms: u64,
    udp_response_ms: u64,
) -> Result<(), String> {
    dynet_capture::run_ipstack_poc(IpStackPocOptions {
        interface,
        max_tcp,
        max_udp,
        idle_timeout: Duration::from_millis(idle_ms),
        udp_response_timeout: Duration::from_millis(udp_response_ms),
    })
    .await
    .map(|_| ())
}

pub(crate) async fn run_runtime_poc(
    config: Option<PathBuf>,
    interface: String,
    max_tcp: usize,
    max_udp: usize,
    idle_ms: u64,
    udp_response_ms: u64,
    tcp_idle_ms: u64,
) -> Result<(), String> {
    let state = AppState::from_config_path(config.as_deref())?;
    let egress_nodes = state.config.forwarding.execution_nodes;
    let runtime = RuntimeState::from_seed(state.config.forwarding.seed);
    let tcp_idle_timeout = Duration::from_millis(tcp_idle_ms);
    let udp_response_timeout = Duration::from_millis(udp_response_ms);
    dynet_capture::run_capture_once(
        "ipstack-runtime-poc",
        IpStackPocOptions {
            interface,
            max_tcp,
            max_udp,
            idle_timeout: Duration::from_millis(idle_ms),
            udp_response_timeout,
        },
        {
            let egress_nodes = egress_nodes.clone();
            let runtime = runtime.clone();
            move |tcp| {
                let egress_nodes = egress_nodes.clone();
                let runtime = runtime.clone();
                async move {
                    let local = tcp.local_addr();
                    let target = tcp.peer_addr();
                    if !target.ip().is_ipv4() {
                        println!(
                            "ipstack-runtime-poc: skipped tcp local={local} peer={target} reason=non-ipv4"
                        );
                        return Ok(false);
                    }
                    println!("ipstack-runtime-poc: accepted tcp local={local} peer={target}");
                    let outcome = dynet_ingress::relay_captured_tcp_graph(
                        tcp,
                        local,
                        target,
                        egress_nodes,
                        runtime,
                        tcp_idle_timeout,
                    )
                    .await?;
                    println!(
                        "ipstack-runtime-poc: tcp-close local={local} peer={target} upstream={} client_to_upstream={} upstream_to_client={} close_reason={}",
                        outcome.upstream,
                        outcome.client_to_upstream_bytes,
                        outcome.upstream_to_client_bytes,
                        outcome.close_reason
                    );
                    Ok(outcome.client_to_upstream_bytes > 0 && outcome.upstream_to_client_bytes > 0)
                }
            }
        },
        {
            let egress_nodes = egress_nodes.clone();
            let runtime = runtime.clone();
            move |udp| {
                let egress_nodes = egress_nodes.clone();
                let runtime = runtime.clone();
                async move {
                    let local = udp.local_addr();
                    let target = udp.peer_addr();
                    if !target.ip().is_ipv4() {
                        println!(
                            "ipstack-runtime-poc: skipped udp local={local} peer={target} reason=non-ipv4"
                        );
                        return Ok(false);
                    }
                    println!("ipstack-runtime-poc: accepted udp local={local} peer={target}");
                    let outcome = dynet_ingress::relay_captured_udp_graph(
                        udp,
                        local,
                        target,
                        egress_nodes,
                        runtime,
                        Duration::from_millis(idle_ms),
                        udp_response_timeout,
                    )
                    .await?;
                    println!(
                        "ipstack-runtime-poc: udp-close local={local} peer={target} upstream={} request_bytes={} response_bytes={} close_reason={}",
                        outcome.upstream,
                        outcome.request_bytes,
                        outcome.response_bytes,
                        outcome.close_reason
                    );
                    Ok(outcome.request_bytes > 0 && outcome.response_bytes > 0)
                }
            }
        },
    )
    .await
    .map(|_| ())
}
