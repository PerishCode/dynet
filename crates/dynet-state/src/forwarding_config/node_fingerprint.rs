use sha2::{Digest, Sha256};

use super::FileForwardNodeConfig;

impl FileForwardNodeConfig {
    pub(super) fn stable_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        for (key, value) in self.fingerprint_parts() {
            hasher.update(key.as_bytes());
            hasher.update(b"=");
            hasher.update(value.as_bytes());
            hasher.update(b"\n");
        }
        format!("node-config-sha256:{:x}", hasher.finalize())
    }

    fn fingerprint_parts(&self) -> Vec<(&'static str, String)> {
        let kind = match self.kind.as_str() {
            "ss" => "shadowsocks",
            other => other,
        };
        let mut parts = vec![
            ("type", kind.to_string()),
            ("ipv6", self.ipv6.unwrap_or(true).to_string()),
            (
                "server",
                self.server
                    .as_deref()
                    .unwrap_or_default()
                    .to_ascii_lowercase(),
            ),
            (
                "port",
                self.port.map(|port| port.to_string()).unwrap_or_default(),
            ),
        ];
        match kind {
            "shadowsocks" => self.push_shadowsocks_parts(&mut parts),
            "trojan" => self.push_trojan_parts(&mut parts),
            "vmess" => self.push_vmess_parts(&mut parts),
            "vless" => self.push_vless_parts(&mut parts),
            _ => {}
        }
        parts
    }

    fn push_shadowsocks_parts(&self, parts: &mut Vec<(&'static str, String)>) {
        parts.push((
            "method",
            self.method
                .as_deref()
                .or(self.cipher.as_deref())
                .unwrap_or_default()
                .to_string(),
        ));
        parts.push((
            "password",
            self.password.as_deref().unwrap_or_default().to_string(),
        ));
    }

    fn push_trojan_parts(&self, parts: &mut Vec<(&'static str, String)>) {
        parts.push((
            "password",
            self.password.as_deref().unwrap_or_default().to_string(),
        ));
        parts.push(("sni", self.tls_server_name().unwrap_or_default()));
    }

    fn push_vmess_parts(&self, parts: &mut Vec<(&'static str, String)>) {
        parts.push(("uuid", self.uuid.as_deref().unwrap_or_default().to_string()));
        parts.push((
            "cipher",
            self.cipher.as_deref().unwrap_or("auto").to_string(),
        ));
        parts.push((
            "alterId",
            self.alter_id
                .map(|alter_id| alter_id.to_string())
                .unwrap_or_else(|| "0".to_string()),
        ));
    }

    fn push_vless_parts(&self, parts: &mut Vec<(&'static str, String)>) {
        parts.push(("uuid", self.uuid.as_deref().unwrap_or_default().to_string()));
        parts.push(("flow", self.flow.as_deref().unwrap_or_default().to_string()));
        parts.push(("servername", self.tls_server_name().unwrap_or_default()));
        if let Some(reality_opts) = &self.reality_opts {
            parts.push((
                "reality.public-key",
                reality_opts
                    .public_key
                    .as_deref()
                    .unwrap_or_default()
                    .to_string(),
            ));
            parts.push((
                "reality.short-id",
                reality_opts
                    .short_id
                    .as_deref()
                    .unwrap_or_default()
                    .to_string(),
            ));
        }
    }

    fn tls_server_name(&self) -> Option<String> {
        self.sni
            .as_deref()
            .or(self.servername.as_deref())
            .map(str::to_ascii_lowercase)
    }
}
