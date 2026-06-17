use dynet_ingress::ShadowsocksMethod;

pub(crate) fn parse_shadowsocks_method(value: &str) -> Result<ShadowsocksMethod, String> {
    match value {
        "aes-256-gcm" => Ok(ShadowsocksMethod::Aes256Gcm),
        "2022-blake3-aes-128-gcm" => Ok(ShadowsocksMethod::Blake3Aes128Gcm2022),
        _ => Err(format!("unsupported shadowsocks cipher: {value}")),
    }
}
