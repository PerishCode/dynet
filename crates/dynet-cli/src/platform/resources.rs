use std::path::Path;

use super::{
    command::{command_status, command_stdout},
    takeover::TakeoverConfig,
    OwnedResource,
};

pub(super) fn owned_resources(config: &TakeoverConfig) -> Vec<OwnedResource> {
    let (nft_family, nft_name) = config.nft_family_name();
    vec![
        OwnedResource {
            kind: "nft-dropin".to_string(),
            name: config.nft_dropin_path.clone(),
            owned: true,
            present: Path::new(&config.nft_dropin_path).exists(),
            detail: "dynet-owned nftables drop-in".to_string(),
        },
        OwnedResource {
            kind: "nft-table".to_string(),
            name: config.nft_table.clone(),
            owned: true,
            present: command_status("nft", &["list", "table", nft_family, nft_name]),
            detail: "exclusive dynet nftables table".to_string(),
        },
        OwnedResource {
            kind: "tun".to_string(),
            name: config.tun_name.clone(),
            owned: true,
            present: Path::new("/sys/class/net").join(&config.tun_name).exists(),
            detail: "dynet-owned tun interface".to_string(),
        },
        OwnedResource {
            kind: "ip-rule".to_string(),
            name: format!("fwmark {}", config.route_mark),
            owned: true,
            present: command_stdout("ip", &["rule", "show"])
                .map(|output| output.contains(&config.route_mark))
                .unwrap_or(false),
            detail: "dynet-owned packet mark".to_string(),
        },
        OwnedResource {
            kind: "route-table".to_string(),
            name: config.route_table.clone(),
            owned: true,
            present: command_stdout("ip", &["route", "show", "table", &config.route_table])
                .map(|output| !output.trim().is_empty())
                .unwrap_or(false),
            detail: "dynet policy route table".to_string(),
        },
        OwnedResource {
            kind: "runtime-dir".to_string(),
            name: config.runtime_dir.clone(),
            owned: true,
            present: Path::new(&config.runtime_dir).exists(),
            detail: "runtime state directory".to_string(),
        },
        OwnedResource {
            kind: "state-dir".to_string(),
            name: config.state_dir.clone(),
            owned: true,
            present: Path::new(&config.state_dir).exists(),
            detail: "persistent dynet state directory".to_string(),
        },
    ]
}
