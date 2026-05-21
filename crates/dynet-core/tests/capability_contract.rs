use dynet_core::{node_supports_transport, validate_config, DynetConfig, Severity, Transport};

#[test]
fn current_udp_contract() {
    let config: DynetConfig = serde_json::from_str(
        r#"{
            "outbounds": [
                { "tag": "direct", "type": "direct" },
                {
                    "tag": "vmess",
                    "type": "vmess",
                    "payload": {
                        "server": "vmess.example.com",
                        "port": 443,
                        "uuid": "00000000-0000-0000-0000-000000000000",
                        "alterId": 0
                    }
                },
                {
                    "tag": "ss",
                    "type": "ss",
                    "payload": {
                        "server": "ss.example.com",
                        "port": 443,
                        "cipher": "aes-128-gcm",
                        "password": "secret"
                    }
                },
                {
                    "tag": "trojan",
                    "type": "trojan",
                    "payload": {
                        "server": "trojan.example.com",
                        "port": 443,
                        "password": "secret"
                    }
                }
            ],
            "routes": [{ "outbound": "direct" }]
        }"#,
    )
    .unwrap();

    assert!(validate_config(&config).is_empty());
    let outbound = |tag: &str| {
        config
            .outbounds
            .iter()
            .find(|outbound| outbound.tag == tag)
            .unwrap()
    };

    assert!(node_supports_transport(outbound("direct"), Transport::Udp));
    assert!(node_supports_transport(outbound("direct"), Transport::Tcp));
    for tag in ["vmess", "ss", "trojan"] {
        assert!(node_supports_transport(outbound(tag), Transport::Tcp));
        assert!(!node_supports_transport(outbound(tag), Transport::Udp));
    }
}

#[test]
fn denies_false_udp_caps() {
    let config: DynetConfig = serde_json::from_str(
        r#"{
            "outbounds": [
                {
                    "tag": "vmess",
                    "type": "vmess",
                    "capabilities": ["udp"],
                    "payload": {
                        "server": "vmess.example.com",
                        "port": 443,
                        "uuid": "00000000-0000-0000-0000-000000000000",
                        "alterId": 0
                    }
                },
                {
                    "tag": "ss",
                    "type": "ss",
                    "capabilities": ["udp"],
                    "payload": {
                        "server": "ss.example.com",
                        "port": 443,
                        "cipher": "aes-128-gcm",
                        "password": "secret"
                    }
                },
                {
                    "tag": "trojan",
                    "type": "trojan",
                    "capabilities": ["udp"],
                    "payload": {
                        "server": "trojan.example.com",
                        "port": 443,
                        "password": "secret"
                    }
                },
                { "tag": "direct", "type": "direct" },
                {
                    "tag": "dialer",
                    "type": "dialer",
                    "capabilities": ["udp"],
                    "payload": { "bound": "direct", "target": "vmess" }
                }
            ]
        }"#,
    )
    .unwrap();

    let diagnostics = validate_config(&config);

    for path in [
        "outbounds[0].capabilities[0]",
        "outbounds[1].capabilities[0]",
        "outbounds[2].capabilities[0]",
        "outbounds[4].capabilities[0]",
    ] {
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.severity == Severity::Deny
                && diagnostic.path == path
                && diagnostic
                    .message
                    .contains("does not currently support capability `udp`")
        }));
    }
}

#[test]
fn route_transport_cap() {
    let config: DynetConfig = serde_json::from_str(
        r#"{
            "inbounds": [{ "tag": "tun-in", "type": "tun" }],
            "outbounds": [{ "tag": "tcp-out", "type": "tcp", "payload": { "server": "example.com", "serverPort": 443 } }],
            "routes": [{ "inbound": "tun-in", "transport": "udp", "outbound": "tcp-out" }]
        }"#,
    )
    .unwrap();

    let diagnostics = validate_config(&config);

    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic.severity == Severity::Deny
            && diagnostic.path == "routes[0].transport"
            && diagnostic
                .message
                .contains("route transport `udp` is not supported by outbound `tcp-out`")
    }));
}
