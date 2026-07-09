use crate::SystemRunner;

pub(crate) const NFT_CHAINS: &[&str] = &["dynet_bypass", "dynet_dns", "dynet_tcp", "dynet_udp"];

pub(crate) fn nft_chain_id(chain: &str) -> &'static str {
    match chain {
        "dynet_bypass" => "nft.chain.bypass",
        "dynet_dns" => "nft.chain.dns",
        "dynet_tcp" => "nft.chain.tcp",
        "dynet_udp" => "nft.chain.udp",
        _ => "nft.chain.unknown",
    }
}

pub(crate) fn nft_chain_label(chain: &str) -> &'static str {
    match chain {
        "dynet_bypass" => "dynet bypass nftables chain",
        "dynet_dns" => "dynet DNS nftables chain",
        "dynet_tcp" => "dynet TCP nftables chain",
        "dynet_udp" => "dynet UDP nftables chain",
        _ => "dynet unknown nftables chain",
    }
}

pub(crate) fn nft_chain_action(chain: &str) -> &'static str {
    match chain {
        "dynet_bypass" => "create inert bypass nftables chain",
        "dynet_dns" => "create inert DNS nftables chain",
        "dynet_tcp" => "create inert TCP nftables chain",
        "dynet_udp" => "create inert UDP nftables chain",
        _ => "create inert nftables chain",
    }
}

pub(crate) fn run_required(
    runner: &impl SystemRunner,
    command: &str,
    args: &[&str],
) -> Result<(), String> {
    let output = runner.run(command, args)?;
    if output.success {
        return Ok(());
    }
    let joined = args.join(" ");
    Err(format!("{command} {joined} failed: {}", output.stderr))
}
