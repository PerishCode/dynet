use dynet_core::DynetConfig;

pub(crate) const VMESS_UUID: &str = "00000000-0000-0000-0000-000000000001";

pub(crate) fn ss_plan_config(server_port: u16) -> DynetConfig {
    serde_json::from_value(serde_json::json!({
        "outbounds": [
            ss_outbound(server_port),
            {
                "tag": "auto",
                "type": "plan",
                "capabilities": ["tcp", "ip-target", "domain-target", "probeable"],
                "payload": {
                    "selection": {
                        "edges": [{ "type": "candidate", "to": "private-ss" }]
                    }
                }
            }
        ],
        "routes": [{ "domain": "target.example", "outbound": "auto" }]
    }))
    .expect("valid Shadowsocks plan config")
}

pub(crate) fn vmess_plan_config(server_port: u16) -> DynetConfig {
    serde_json::from_value(serde_json::json!({
        "outbounds": [
            vmess_outbound(server_port),
            {
                "tag": "auto",
                "type": "plan",
                "capabilities": ["tcp", "ip-target", "domain-target", "probeable"],
                "payload": {
                    "selection": {
                        "edges": [{ "type": "candidate", "to": "private-vmess" }]
                    }
                }
            }
        ],
        "routes": [{ "domain": "target.example", "outbound": "auto" }]
    }))
    .expect("valid VMess plan config")
}

pub(crate) fn trojan_plan_config(server_port: u16) -> DynetConfig {
    serde_json::from_value(serde_json::json!({
        "outbounds": [
            trojan_outbound(server_port),
            {
                "tag": "auto",
                "type": "plan",
                "capabilities": ["tcp", "ip-target", "domain-target", "probeable"],
                "payload": {
                    "selection": {
                        "edges": [{ "type": "candidate", "to": "private-trojan" }]
                    }
                }
            }
        ],
        "routes": [{ "domain": "target.example", "outbound": "auto" }]
    }))
    .expect("valid Trojan plan config")
}

pub(crate) fn direct_config(domain: &str) -> DynetConfig {
    serde_json::from_value(serde_json::json!({
        "outbounds": [{ "tag": "direct", "type": "direct" }],
        "routes": [{ "domain": domain, "outbound": "direct" }]
    }))
    .expect("valid direct config")
}

pub(crate) fn dialer_config(server_port: u16) -> DynetConfig {
    serde_json::from_value(serde_json::json!({
        "outbounds": [
            { "tag": "direct", "type": "direct" },
            bound_direct_plan(),
            ss_outbound(server_port),
            {
                "tag": "private-via-bound",
                "type": "dialer",
                "payload": {
                    "bound": "bound-plan",
                    "target": "private-ss"
                }
            }
        ],
        "rules": [identity_rule()],
        "routes": [{ "outbound": "direct" }]
    }))
    .expect("valid dialer config")
}

pub(crate) fn dialer_vmess_config(server_port: u16) -> DynetConfig {
    serde_json::from_value(serde_json::json!({
        "outbounds": [
            { "tag": "direct", "type": "direct" },
            bound_direct_plan(),
            vmess_outbound(server_port),
            {
                "tag": "private-via-bound",
                "type": "dialer",
                "payload": {
                    "bound": "bound-plan",
                    "target": "private-vmess"
                }
            }
        ],
        "rules": [identity_rule()],
        "routes": [{ "outbound": "direct" }]
    }))
    .expect("valid VMess dialer config")
}

pub(crate) fn vmess_ss_config(vmess_port: u16) -> DynetConfig {
    serde_json::from_value(serde_json::json!({
        "outbounds": [
            vmess_bound_outbound(vmess_port),
            {
                "tag": "bound-plan",
                "type": "plan",
                "capabilities": ["tcp", "ip-target", "domain-target", "probeable"],
                "payload": {
                    "selection": {
                        "edges": [{ "type": "candidate", "to": "bound-vmess" }]
                    }
                }
            },
            ss_outbound_with_tag("private-ss", 1),
            {
                "tag": "private-via-bound",
                "type": "dialer",
                "payload": {
                    "bound": "bound-plan",
                    "target": "private-ss"
                }
            }
        ],
        "rules": [{
            "tag": "identity-private",
            "domain": "localhost",
            "outbound": "private-via-bound"
        }],
        "routes": [{ "outbound": "bound-vmess" }]
    }))
    .expect("valid VMess-to-SS dialer config")
}

pub(crate) fn bound_then_downstream_config(vmess_port: u16) -> DynetConfig {
    serde_json::from_value(serde_json::json!({
        "outbounds": [
            { "tag": "direct", "type": "direct" },
            vmess_bound_outbound(vmess_port),
            {
                "tag": "bound-plan",
                "type": "plan",
                "capabilities": ["tcp", "ip-target", "domain-target", "probeable"],
                "payload": {
                    "selection": {
                        "edges": [
                            { "type": "candidate", "to": "direct" },
                            { "type": "candidate", "to": "bound-vmess" }
                        ]
                    }
                }
            },
            ss_outbound_with_tag("private-ss", 1),
            {
                "tag": "private-via-bound",
                "type": "dialer",
                "payload": {
                    "bound": "bound-plan",
                    "target": "private-ss"
                }
            }
        ],
        "rules": [{
            "tag": "identity-private",
            "domain": "localhost",
            "outbound": "private-via-bound"
        }],
        "routes": [{ "outbound": "direct" }]
    }))
    .expect("valid bound-then-downstream dialer config")
}

pub(crate) fn dialer_trojan_config(server_port: u16) -> DynetConfig {
    serde_json::from_value(serde_json::json!({
        "outbounds": [
            { "tag": "direct", "type": "direct" },
            bound_direct_plan(),
            trojan_outbound(server_port),
            {
                "tag": "private-via-bound",
                "type": "dialer",
                "payload": {
                    "bound": "bound-plan",
                    "target": "private-trojan"
                }
            }
        ],
        "rules": [identity_rule()],
        "routes": [{ "outbound": "direct" }]
    }))
    .expect("valid Trojan dialer config")
}

fn bound_direct_plan() -> serde_json::Value {
    serde_json::json!({
        "tag": "bound-plan",
        "type": "plan",
        "capabilities": ["tcp", "ip-target", "domain-target", "probeable"],
        "payload": {
            "selection": {
                "edges": [{ "type": "candidate", "to": "direct" }]
            }
        }
    })
}

fn identity_rule() -> serde_json::Value {
    serde_json::json!({
        "tag": "identity-private",
        "domain": "target.example",
        "outbound": "private-via-bound"
    })
}

fn ss_outbound(server_port: u16) -> serde_json::Value {
    ss_outbound_with_tag("private-ss", server_port)
}

fn ss_outbound_with_tag(tag: &str, server_port: u16) -> serde_json::Value {
    serde_json::json!({
        "tag": tag,
        "type": "ss",
        "payload": {
            "server": "127.0.0.1",
            "port": server_port,
            "cipher": "aes-128-gcm",
            "password": "secret"
        }
    })
}

fn vmess_outbound(server_port: u16) -> serde_json::Value {
    serde_json::json!({
        "tag": "private-vmess",
        "type": "vmess",
        "payload": {
            "server": "127.0.0.1",
            "port": server_port,
            "uuid": VMESS_UUID,
            "cipher": "aes-128-gcm"
        }
    })
}

fn vmess_bound_outbound(server_port: u16) -> serde_json::Value {
    serde_json::json!({
        "tag": "bound-vmess",
        "type": "vmess",
        "payload": {
            "server": "127.0.0.1",
            "port": server_port,
            "uuid": VMESS_UUID,
            "cipher": "aes-128-gcm"
        }
    })
}

fn trojan_outbound(server_port: u16) -> serde_json::Value {
    serde_json::json!({
        "tag": "private-trojan",
        "type": "trojan",
        "payload": {
            "server": "localhost",
            "serverIp": "127.0.0.1",
            "port": server_port,
            "password": "secret",
            "sni": "localhost",
            "skipCertVerify": true
        }
    })
}
