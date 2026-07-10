use crate::{LinuxTakeover, PlanPhase, PlanSafety, TakeoverPlan, TakeoverPlanItem};

impl LinuxTakeover {
    pub fn plan(&self) -> TakeoverPlan {
        TakeoverPlan {
            items: vec![
                plan_item(
                    "sysctl.fragment",
                    PlanPhase::IsolatedFragments,
                    "/etc/sysctl.d/90-dynet.conf",
                    PlanSafety::LocalSafe,
                ),
                plan_item(
                    "rt_tables.fragment",
                    PlanPhase::IsolatedFragments,
                    "/etc/iproute2/rt_tables.d/dynet.conf",
                    PlanSafety::LocalSafe,
                ),
                plan_item(
                    "tun.interface",
                    PlanPhase::RuntimeSkeleton,
                    "create dynet0 TUN interface",
                    PlanSafety::VmOnly,
                ),
                plan_item(
                    "nft.table",
                    PlanPhase::RuntimeSkeleton,
                    "create inet dynet table",
                    PlanSafety::VmOnly,
                ),
                plan_item(
                    "nft.chain.bypass",
                    PlanPhase::RuntimeSkeleton,
                    "create inert bypass chain without hook",
                    PlanSafety::VmOnly,
                ),
                plan_item(
                    "nft.chain.dns",
                    PlanPhase::RuntimeSkeleton,
                    "create inert DNS chain without hook",
                    PlanSafety::VmOnly,
                ),
                plan_item(
                    "nft.chain.tcp",
                    PlanPhase::RuntimeSkeleton,
                    "create inert TCP chain without hook",
                    PlanSafety::VmOnly,
                ),
                plan_item(
                    "nft.chain.udp",
                    PlanPhase::RuntimeSkeleton,
                    "create inert UDP chain without hook",
                    PlanSafety::VmOnly,
                ),
                plan_item(
                    "packet.parser",
                    PlanPhase::VmOnlyCapture,
                    "parse IPv4/IPv6 TCP/UDP/DNS packet metadata from captured bytes",
                    PlanSafety::LocalSafe,
                ),
                plan_item(
                    "tun.io",
                    PlanPhase::VmOnlyCapture,
                    "bind dynet0 through /dev/net/tun and expose packet read/write",
                    PlanSafety::VmOnly,
                ),
                plan_item(
                    "capture.hooks",
                    PlanPhase::VmOnlyCapture,
                    "install VM-only nft output hook and fwmark route rules",
                    PlanSafety::VmOnly,
                ),
            ],
        }
    }
}

fn plan_item(
    id: &'static str,
    phase: PlanPhase,
    action: impl Into<String>,
    safety: PlanSafety,
) -> TakeoverPlanItem {
    TakeoverPlanItem {
        id,
        phase,
        action: action.into(),
        safety,
    }
}
