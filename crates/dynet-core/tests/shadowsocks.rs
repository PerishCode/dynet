use dynet_core::{validate_config, DynetConfig};

#[test]
fn validates_shadowsocks_payloads() {
    let config: DynetConfig = serde_json::from_str(
        r#"{
            "outbounds": [
                {
                    "tag": "private",
                    "type": "ss",
                    "payload": {
                        "server": "private.example.com",
                        "serverIp": "198.51.100.10",
                        "port": 8388,
                        "cipher": "aes-128-gcm",
                        "password": "secret"
                    }
                }
            ],
            "routes": [{ "outbound": "private" }]
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
fn denies_unsupported_shadowsocks() {
    let config: DynetConfig = serde_json::from_str(
        r#"{
            "outbounds": [
                {
                    "tag": "private",
                    "type": "ss",
                    "payload": {
                        "server": "private.example.com",
                        "cipher": "chacha20-ietf-poly1305"
                    }
                }
            ],
            "routes": [{ "outbound": "private" }]
        }"#,
    )
    .unwrap();

    let diagnostics = validate_config(&config);
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.path == "outbounds[0].payload.serverPort|port"));
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.path == "outbounds[0].payload.password"));
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.path == "outbounds[0].payload.cipher"));
}
