mod dns;
mod outbound;
mod probe;
mod resolver;
mod settings;
mod socket;
mod takeover;
mod tun;
mod vmess;

mod event {
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
        time::{SystemTime, UNIX_EPOCH},
    };

    use serde::Serialize;
    use tracing::debug;

    #[derive(Debug, Clone, Eq, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct RuntimeEvent {
        pub schema: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sequence: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub emitted_at_unix_ms: Option<u128>,
        pub kind: RuntimeEventKind,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        pub fields: BTreeMap<String, String>,
    }

    #[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum RuntimeEventKind {
        DnsQueryReceived,
        DnsResolveCompleted,
        DnsResolveFailed,
        ProbeStarted,
        ProbeAttemptStarted,
        ProbeAttemptFinished,
        ProbeCompleted,
        RuleMatched,
        PlanBypassed,
        RouteMatched,
        OutboundAdmissionPassed,
        OutboundCandidateSet,
        OutboundGraphSelected,
        OutboundEgressPassed,
        DialerCascadeSelected,
        DialerCascadeAttemptStarted,
        DialerCascadeAttemptFinished,
        OutboundAttemptStarted,
        OutboundStageFinished,
        OutboundAttemptFinished,
        DnsProxyForward,
        DnsReverseRecord,
        IpPacketDenied,
        TcpSessionStarted,
        TcpSessionAttributed,
        TcpSessionDenied,
        TcpSessionOutboundConnecting,
        TcpSessionEstablished,
        TcpSessionPayloadFirstWrite,
        TcpSessionPayloadReceived,
        TcpSessionClosed,
        TcpSessionFailed,
        TcpForwarderCapacity,
        TcpForwarderPacket,
        TcpForwarderPacketTerminal,
        TcpForwarderPreflowCandidate,
        TcpForwarderPreflowMissed,
        TcpForwarderPreflow,
        TcpForwarderPressure,
        UdpSessionStarted,
        UdpSessionAttributed,
        UdpSessionDenied,
        UdpSessionOutboundConnecting,
        UdpSessionEstablished,
        UdpSessionPayloadSent,
        UdpSessionPayloadReceived,
        UdpSessionClosed,
        UdpSessionFailed,
    }

    #[derive(Debug, Clone, Default)]
    pub(crate) struct EventBus {
        events: Arc<Mutex<Vec<RuntimeEvent>>>,
    }

    impl RuntimeEvent {
        pub(crate) fn new(kind: RuntimeEventKind) -> Self {
            Self {
                schema: "dynet-runtime-event/v1alpha1".to_string(),
                sequence: None,
                emitted_at_unix_ms: None,
                kind,
                fields: BTreeMap::new(),
            }
        }

        pub(crate) fn field(mut self, key: impl Into<String>, value: impl ToString) -> Self {
            self.fields.insert(key.into(), value.to_string());
            self
        }
    }

    impl EventBus {
        pub(crate) fn emit(&self, mut event: RuntimeEvent) -> Result<(), String> {
            let emitted_at_unix_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| format!("runtime event clock went backwards: {error}"))?
                .as_millis();
            let mut events = self
                .events
                .lock()
                .map_err(|_| "runtime event bus lock poisoned".to_string())?;
            event.sequence = Some(
                u64::try_from(events.len())
                    .map_err(|_| "runtime event sequence overflow".to_string())?
                    + 1,
            );
            event.emitted_at_unix_ms = Some(emitted_at_unix_ms);
            debug!(kind = ?event.kind, fields = ?event.fields, "runtime.event");
            events.push(event);
            Ok(())
        }

        pub(crate) fn snapshot(&self) -> Result<Vec<RuntimeEvent>, String> {
            self.events
                .lock()
                .map_err(|_| "runtime event bus lock poisoned".to_string())
                .map(|events| events.clone())
        }
    }
}

use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use dynet_core::DnsReverseIndex;
use serde::Serialize;

pub use dns::{dns_reverse_from_wire, dns_servfail_from_wire};
pub use event::{RuntimeEvent, RuntimeEventKind};
pub use probe::{
    probe_https_head, probe_tcp_connect, probe_tls_handshake, ProbeAttemptReport,
    ProbeFailureScope, ProbeProtocol, ProbeReadPolicy, ProbeReport, ProbeRetryPolicy,
    ProbeRetryReport, ProbeSettings, ProbeTarget,
};
pub use settings::{
    DnsRuntimeChain, OutboundTcpSettings, RunLimits, RuntimePolicy, RuntimeSettings,
    TakeoverSettings, TcpForwardingSettings, UdpForwardingSettings,
};
pub use takeover::{
    apply_takeover, uninstall_takeover, TakeoverAction, TakeoverApplyReport, TakeoverStatus,
    TakeoverStepReport,
};

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeReport {
    pub schema: String,
    pub status: RuntimeStatus,
    pub reason: String,
    pub tun_packets: usize,
    pub dns_queries: usize,
    pub route_decisions: usize,
    pub proxied_dns_queries: usize,
    pub dns_records: usize,
    pub ipv6_packets_denied: usize,
    pub tcp_sessions: usize,
    pub tcp_session_failures: usize,
    pub tcp_closed_sessions: usize,
    pub tcp_upstream_bytes: usize,
    pub tcp_downstream_bytes: usize,
    pub tcp_listen_ports: Vec<u16>,
    pub tcp_listen_slots_per_port: usize,
    pub tcp_listen_capacity: usize,
    pub tcp_active_slots_max: usize,
    pub tcp_slot_pressure_events: usize,
    pub udp_sessions: usize,
    pub udp_session_failures: usize,
    pub udp_upstream_bytes: usize,
    pub udp_downstream_bytes: usize,
    pub udp_dropped_packets: usize,
    pub dns_reverse: DnsReverseIndex,
    pub events: Vec<RuntimeEvent>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeStatus {
    Pass,
    Deny,
}

struct RuntimeCounters {
    tun_packets: AtomicUsize,
    dns_queries: AtomicUsize,
    route_decisions: AtomicUsize,
    proxied_dns_queries: AtomicUsize,
    ipv6_packets_denied: AtomicUsize,
    tcp_sessions: AtomicUsize,
    tcp_session_failures: AtomicUsize,
    tcp_closed_sessions: AtomicUsize,
    tcp_upstream_bytes: AtomicUsize,
    tcp_downstream_bytes: AtomicUsize,
    tcp_active_slots_max: AtomicUsize,
    tcp_slot_pressure_events: AtomicUsize,
    udp_sessions: AtomicUsize,
    udp_session_failures: AtomicUsize,
    udp_upstream_bytes: AtomicUsize,
    udp_downstream_bytes: AtomicUsize,
    udp_dropped_packets: AtomicUsize,
    dns_reverse: Mutex<DnsReverseIndex>,
    ebus: event::EventBus,
}

impl RuntimeCounters {
    fn new() -> Self {
        Self {
            tun_packets: AtomicUsize::new(0),
            dns_queries: AtomicUsize::new(0),
            route_decisions: AtomicUsize::new(0),
            proxied_dns_queries: AtomicUsize::new(0),
            ipv6_packets_denied: AtomicUsize::new(0),
            tcp_sessions: AtomicUsize::new(0),
            tcp_session_failures: AtomicUsize::new(0),
            tcp_closed_sessions: AtomicUsize::new(0),
            tcp_upstream_bytes: AtomicUsize::new(0),
            tcp_downstream_bytes: AtomicUsize::new(0),
            tcp_active_slots_max: AtomicUsize::new(0),
            tcp_slot_pressure_events: AtomicUsize::new(0),
            udp_sessions: AtomicUsize::new(0),
            udp_session_failures: AtomicUsize::new(0),
            udp_upstream_bytes: AtomicUsize::new(0),
            udp_downstream_bytes: AtomicUsize::new(0),
            udp_dropped_packets: AtomicUsize::new(0),
            dns_reverse: Mutex::new(DnsReverseIndex::default()),
            ebus: event::EventBus::default(),
        }
    }

    fn emit(&self, event: RuntimeEvent) -> Result<(), String> {
        self.ebus.emit(event)
    }
}

pub fn run(settings: RuntimeSettings, limits: RunLimits) -> Result<RuntimeReport, String> {
    settings.validate()?;
    let counters = Arc::new(RuntimeCounters::new());
    let stop = Arc::new(AtomicBool::new(false));
    let tun = tun::TunDevice::open(&settings.tun_name)?;
    let udp_dns = dns::UdpDnsServer::bind(settings.dns_bind)?;
    let tcp_dns = dns::TcpDnsServer::bind(settings.dns_bind)?;

    let tun_thread = if settings.tcp_forwarding.enabled || settings.udp_forwarding.enabled {
        spawn_tcp_forwarder(tun, settings.clone(), counters.clone(), stop.clone())
    } else {
        spawn_tun_reader(tun, counters.clone(), stop.clone())
    };
    let udp_thread = spawn_udp_dns(udp_dns, settings.clone(), counters.clone(), stop.clone());
    let tcp_thread = spawn_tcp_dns(tcp_dns, settings.clone(), counters.clone(), stop.clone());
    let started = Instant::now();
    let reason = wait_for_limits(&limits, &counters, &stop, started);

    stop.store(true, Ordering::SeqCst);
    join_runtime_thread("tun runtime", tun_thread)?;
    join_runtime_thread("udp dns", udp_thread)?;
    join_runtime_thread("tcp dns", tcp_thread)?;

    let dns_reverse = counters
        .dns_reverse
        .lock()
        .map_err(|_| "dns reverse index lock poisoned".to_string())?
        .clone();
    let events = counters.ebus.snapshot()?;
    Ok(RuntimeReport {
        schema: "dynet-runtime/v1alpha1".to_string(),
        status: RuntimeStatus::Pass,
        reason,
        tun_packets: counters.tun_packets.load(Ordering::SeqCst),
        dns_queries: counters.dns_queries.load(Ordering::SeqCst),
        route_decisions: counters.route_decisions.load(Ordering::SeqCst),
        proxied_dns_queries: counters.proxied_dns_queries.load(Ordering::SeqCst),
        dns_records: dns_reverse.records.len(),
        ipv6_packets_denied: counters.ipv6_packets_denied.load(Ordering::SeqCst),
        tcp_sessions: counters.tcp_sessions.load(Ordering::SeqCst),
        tcp_session_failures: counters.tcp_session_failures.load(Ordering::SeqCst),
        tcp_closed_sessions: counters.tcp_closed_sessions.load(Ordering::SeqCst),
        tcp_upstream_bytes: counters.tcp_upstream_bytes.load(Ordering::SeqCst),
        tcp_downstream_bytes: counters.tcp_downstream_bytes.load(Ordering::SeqCst),
        tcp_listen_ports: settings.tcp_forwarding.listen_ports(),
        tcp_listen_slots_per_port: settings.tcp_forwarding.listen_slots_per_port,
        tcp_listen_capacity: settings.tcp_forwarding.listen_capacity(),
        tcp_active_slots_max: counters.tcp_active_slots_max.load(Ordering::SeqCst),
        tcp_slot_pressure_events: counters.tcp_slot_pressure_events.load(Ordering::SeqCst),
        udp_sessions: counters.udp_sessions.load(Ordering::SeqCst),
        udp_session_failures: counters.udp_session_failures.load(Ordering::SeqCst),
        udp_upstream_bytes: counters.udp_upstream_bytes.load(Ordering::SeqCst),
        udp_downstream_bytes: counters.udp_downstream_bytes.load(Ordering::SeqCst),
        udp_dropped_packets: counters.udp_dropped_packets.load(Ordering::SeqCst),
        dns_reverse,
        events,
    })
}

fn spawn_tun_reader(
    tun: tun::TunDevice,
    counters: Arc<RuntimeCounters>,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<Result<(), String>> {
    thread::spawn(move || tun::read_packets(tun, counters, stop))
}

fn spawn_tcp_forwarder(
    tun: tun::TunDevice,
    settings: RuntimeSettings,
    counters: Arc<RuntimeCounters>,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<Result<(), String>> {
    thread::spawn(move || tun::tcp_forward::run(tun, settings, counters, stop))
}

fn spawn_udp_dns(
    server: dns::UdpDnsServer,
    settings: RuntimeSettings,
    counters: Arc<RuntimeCounters>,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<Result<(), String>> {
    thread::spawn(move || dns::serve_udp(server, &settings, counters, stop))
}

fn spawn_tcp_dns(
    server: dns::TcpDnsServer,
    settings: RuntimeSettings,
    counters: Arc<RuntimeCounters>,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<Result<(), String>> {
    thread::spawn(move || dns::serve_tcp(server, &settings, counters, stop))
}

fn wait_for_limits(
    limits: &RunLimits,
    counters: &RuntimeCounters,
    stop: &AtomicBool,
    started: Instant,
) -> String {
    loop {
        if runtime_limits_reached(limits, counters) {
            return "runtime limits reached".to_string();
        }
        if let Some(timeout) = limits.timeout {
            if started.elapsed() >= timeout {
                return format!("runtime timeout reached after {}s", timeout.as_secs());
            }
        }
        if stop.load(Ordering::SeqCst) {
            return "runtime stop requested".to_string();
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn runtime_limits_reached(limits: &RunLimits, counters: &RuntimeCounters) -> bool {
    let any_limit = limits.max_dns_queries.is_some()
        || limits.max_tun_packets.is_some()
        || limits.max_tcp_sessions.is_some()
        || limits.max_tcp_closed_sessions.is_some()
        || limits.max_tcp_terminal_sessions.is_some()
        || limits.max_udp_sessions.is_some()
        || limits.max_udp_downstream_bytes.is_some();
    any_limit
        && limits
            .max_dns_queries
            .is_none_or(|max| counters.dns_queries.load(Ordering::SeqCst) >= max)
        && limits
            .max_tun_packets
            .is_none_or(|max| counters.tun_packets.load(Ordering::SeqCst) >= max)
        && limits
            .max_tcp_sessions
            .is_none_or(|max| counters.tcp_sessions.load(Ordering::SeqCst) >= max)
        && limits
            .max_tcp_closed_sessions
            .is_none_or(|max| counters.tcp_closed_sessions.load(Ordering::SeqCst) >= max)
        && limits.max_tcp_terminal_sessions.is_none_or(|max| {
            counters.tcp_closed_sessions.load(Ordering::SeqCst)
                + counters.tcp_session_failures.load(Ordering::SeqCst)
                >= max
        })
        && limits
            .max_udp_sessions
            .is_none_or(|max| counters.udp_sessions.load(Ordering::SeqCst) >= max)
        && limits
            .max_udp_downstream_bytes
            .is_none_or(|max| counters.udp_downstream_bytes.load(Ordering::SeqCst) >= max)
}

fn join_runtime_thread(
    name: &str,
    handle: thread::JoinHandle<Result<(), String>>,
) -> Result<(), String> {
    match handle.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(format!("{name} failed: {error}")),
        Err(_) => Err(format!("{name} panicked")),
    }
}
