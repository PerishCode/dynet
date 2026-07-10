use std::net::IpAddr;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Ipv6RulePolicy {
    Inherit,
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum IpFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Ipv6PolicySource {
    Global,
    Rule,
}

impl Ipv6RulePolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inherit => "inherit",
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

impl IpFamily {
    pub fn from_address(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

impl Ipv6PolicySource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Rule => "rule",
        }
    }
}
