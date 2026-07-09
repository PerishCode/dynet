mod flow;
mod ipstack_poc;
mod linux;
mod linux_checks;
#[path = "linux/hooks.rs"]
mod linux_hooks;
#[path = "linux/nft.rs"]
mod linux_nft;
mod linux_plan;
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
pub use linux_tun::{
    probe as probe_linux_tun, probe_default as probe_default_linux_tun,
    probe_wait as probe_linux_tun_wait, LinuxTun, TunOpenReport, TunProbeRead, TunProbeReport,
};
pub use linux_types::{
    ApplyOptions, ApplyReport, CheckState, CleanupReport, CommandOutput, HostRunner, PlanPhase,
    PlanSafety, SystemRunner, TakeoverCheck, TakeoverPlan, TakeoverPlanItem, TakeoverReport,
    TakeoverStatus,
};
pub use packet::{parse_ipv4_packet, PacketFlow, PacketParseError};

pub trait CaptureBackend {
    fn info(&self) -> CaptureBackendInfo;
    fn doctor(&self) -> TakeoverReport;
}
