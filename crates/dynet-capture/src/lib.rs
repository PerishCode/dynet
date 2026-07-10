mod flow;
mod ipstack_poc;
mod linux;
mod linux_checks;
#[path = "linux/dns_mapping.rs"]
mod linux_dns_mapping;
#[path = "linux/hooks.rs"]
mod linux_hooks;
#[path = "linux/nft.rs"]
mod linux_nft;
mod linux_plan;
#[path = "linux/router_ingress.rs"]
mod linux_router_ingress;
#[path = "linux/scope.rs"]
mod linux_scope;
mod linux_tun;
mod linux_types;
mod packet;

pub use flow::{
    CaptureBackendInfo, CapturePlatform, CapturedFlow, CapturedTarget, CapturedTransport,
    TakeoverKind, TargetCaptureSource,
};
pub use ipstack::{IpStackTcpStream, IpStackUdpStream};
pub use ipstack_poc::{
    run_capture_forever, run_capture_once, run_ipstack_poc, IpStackCaptureFuture,
    IpStackPocOptions, IpStackPocReport, IpStackTcpCaptureHandler, IpStackUdpCaptureHandler,
};
pub use linux::{LinuxTakeover, LinuxTakeoverPaths};
pub use linux_dns_mapping::{DnsMappingOptions, DYNET_NFT_DNS_MAPPING_PRIORITY};
pub use linux_hooks::{
    HookOptions, DYNET_CAPTURE_MARK_MASK, DYNET_CAPTURE_MARK_VALUE, DYNET_NFT_OUTPUT_PRIORITY,
    DYNET_ROUTE_RULE_PRIORITY, DYNET_ROUTE_TABLE_ID,
};
pub use linux_router_ingress::{RouterHookOptions, DYNET_NFT_ROUTER_INGRESS_PRIORITY};
pub use linux_scope::TrafficScope;
pub use linux_tun::{
    probe as probe_linux_tun, probe_default as probe_default_linux_tun,
    probe_wait as probe_linux_tun_wait, validate_inherited_fd, LinuxTun, TunOpenReport,
    TunProbeRead, TunProbeReport,
};
pub use linux_types::{
    ApplyOptions, ApplyReport, CheckState, CleanupReport, CommandOutput, HostRunner, PlanPhase,
    PlanSafety, SystemRunner, TakeoverCheck, TakeoverPlan, TakeoverPlanItem, TakeoverReport,
    TakeoverStatus,
};
pub use packet::{
    parse_ip_packet, parse_ipv4_packet, parse_ipv6_packet, PacketFlow, PacketParseError,
};

pub trait CaptureBackend {
    fn info(&self) -> CaptureBackendInfo;
    fn doctor(&self) -> TakeoverReport;
}
