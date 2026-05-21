use dynet_core::{validate_config, DynetConfig};

#[test]
fn validates_vmess_payloads() {
    let config: DynetConfig = serde_json::from_str(
        r#"{
            "outbounds": [
                {
                    "tag": "proxy",
                    "type": "vmess",
                    "payload": {
                        "server": "node.example.com",
                        "serverIp": "203.0.113.10",
                        "port": 443,
                        "uuid": "11111111-1111-1111-1111-111111111111",
                        "alterId": 0,
                        "cipher": "auto"
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
fn denies_unsupported_vmess() {
    let config: DynetConfig = serde_json::from_str(
        r#"{
            "outbounds": [
                {
                    "tag": "proxy",
                    "type": "vmess",
                    "payload": {
                        "server": "node.example.com",
                        "uuid": "11111111-1111-1111-1111-111111111111",
                        "alterId": 1,
                        "network": "ws"
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
        .any(|diagnostic| diagnostic.path == "outbounds[0].payload.alterId"));
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.path == "outbounds[0].payload.network"));
}
