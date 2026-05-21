use dynet_core::{validate_config, DynetConfig};

#[test]
fn validates_trojan_payloads() {
    let config: DynetConfig = serde_json::from_str(
        r#"{
            "outbounds": [
                {
                    "tag": "proxy",
                    "type": "trojan",
                    "payload": {
                        "server": "node.example.com",
                        "serverIp": "203.0.113.10",
                        "port": 443,
                        "password": "secret",
                        "sni": "cdn.example.com",
                        "skipCertVerify": true
                    }
                }
            ],
            "routes": [{ "outbound": "proxy" }]
        }"#,
    )
    .unwrap();

    let diagnostics = validate_config(&config);
    assert!(diagnostics.is_empty());
    let model = config.network_model();
    assert!(model.outbounds[0].capabilities.contains(&"tcp".to_string()));
    assert!(model.outbounds[0].capabilities.contains(&"dns".to_string()));
}

#[test]
fn denies_unsupported_trojan() {
    let config: DynetConfig = serde_json::from_str(
        r#"{
            "outbounds": [
                {
                    "tag": "proxy",
                    "type": "trojan",
                    "payload": {
                        "server": "node.example.com",
                        "password": "secret",
                        "network": "ws",
                        "skipCertVerify": "yes"
                    }
                }
            ],
            "routes": [{ "outbound": "proxy" }]
        }"#,
    )
    .unwrap();

    let diagnostics = validate_config(&config);
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.path == "outbounds[0].payload.serverPort|port"));
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.path == "outbounds[0].payload.network"));
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.path == "outbounds[0].payload.skipCertVerify"));
}
