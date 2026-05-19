use std::path::Path;

use super::{
    command::{command_status, command_stdout},
    OwnedResource, NFT_TABLE, ROUTE_MARK, ROUTE_TABLE, RUNTIME_DIR, STATE_DIR, TUN_NAME,
};

pub(super) fn owned_resources() -> Vec<OwnedResource> {
    vec![
        OwnedResource {
            kind: "nft-table".to_string(),
            name: NFT_TABLE.to_string(),
            owned: true,
            present: command_status("nft", &["list", "table", "inet", "dynet"]),
            detail: "exclusive dynet nftables table".to_string(),
        },
        OwnedResource {
            kind: "tun".to_string(),
            name: TUN_NAME.to_string(),
            owned: true,
            present: Path::new("/sys/class/net").join(TUN_NAME).exists(),
            detail: "dynet-owned tun interface".to_string(),
        },
        OwnedResource {
            kind: "ip-rule".to_string(),
            name: format!("fwmark {ROUTE_MARK}"),
            owned: true,
            present: command_stdout("ip", &["rule", "show"])
                .map(|output| output.contains(ROUTE_MARK))
                .unwrap_or(false),
            detail: "dynet-owned packet mark".to_string(),
        },
        OwnedResource {
            kind: "route-table".to_string(),
            name: ROUTE_TABLE.to_string(),
            owned: true,
            present: command_stdout("ip", &["route", "show", "table", ROUTE_TABLE])
                .map(|output| !output.trim().is_empty())
                .unwrap_or(false),
            detail: "dynet policy route table".to_string(),
        },
        OwnedResource {
            kind: "runtime-dir".to_string(),
            name: RUNTIME_DIR.to_string(),
            owned: true,
            present: Path::new(RUNTIME_DIR).exists(),
            detail: "runtime state directory".to_string(),
        },
        OwnedResource {
            kind: "state-dir".to_string(),
            name: STATE_DIR.to_string(),
            owned: true,
            present: Path::new(STATE_DIR).exists(),
            detail: "persistent dynet state directory".to_string(),
        },
    ]
}
