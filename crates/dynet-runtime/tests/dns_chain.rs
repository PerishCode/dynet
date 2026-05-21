use dynet_runtime::DnsRuntimeChain;

#[test]
fn validates_doh_chain() {
    let chain = DnsRuntimeChain::Doh {
        endpoint: "https://dns.alidns.com/dns-query".to_string(),
        bootstrap_ips: vec!["223.5.5.5".parse().unwrap()],
    };

    assert!(chain.validate().is_ok());
}

#[test]
fn denies_empty_bootstrap() {
    let chain = DnsRuntimeChain::Doh {
        endpoint: "https://cloudflare-dns.com/dns-query".to_string(),
        bootstrap_ips: Vec::new(),
    };

    assert!(chain.validate().unwrap_err().contains("bootstrap IPs"));
}
