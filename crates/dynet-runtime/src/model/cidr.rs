use std::net::IpAddr;

pub(super) fn ip_matches_cidr(address: IpAddr, cidr: &str) -> bool {
    let Some((base, prefix)) = cidr.split_once('/') else {
        return false;
    };
    match (address, base.parse::<IpAddr>(), prefix.parse::<u8>()) {
        (IpAddr::V4(address), Ok(IpAddr::V4(base)), Ok(prefix)) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(address) & mask == u32::from(base) & mask
        }
        (IpAddr::V6(address), Ok(IpAddr::V6(base)), Ok(prefix)) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(address) & mask == u128::from(base) & mask
        }
        _ => false,
    }
}
