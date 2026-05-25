use serde::Serialize;

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeTarget {
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl ProbeTarget {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.host.trim() != self.host || self.host.is_empty() {
            return Err("probe host must not be empty or padded".to_string());
        }
        if self.port == 0 {
            return Err("probe port must not be zero".to_string());
        }
        if !self.path.starts_with('/') {
            return Err("probe path must start with `/`".to_string());
        }
        Ok(())
    }

    pub(crate) fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub(crate) fn host_header(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            self.address()
        }
    }
}
