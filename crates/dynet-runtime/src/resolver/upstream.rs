use std::{
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpStream, UdpSocket},
    sync::Arc,
    time::Duration,
};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use tracing::debug;

use crate::{settings::validate_doh_endpoint, socket};

const DNS_BUFFER_LEN: usize = 4096;
const DOH_MAX_RESPONSE_LEN: usize = 128 * 1024;

#[derive(Debug, Clone, Eq, PartialEq)]
struct HttpsEndpoint {
    host: String,
    port: u16,
    path: String,
}

pub(super) fn resolve_udp(
    query: &[u8],
    upstream_dns: SocketAddr,
    mark: u32,
) -> Result<Vec<u8>, String> {
    let bind = udp_bind_for(upstream_dns.ip());
    let socket = UdpSocket::bind(bind)
        .map_err(|error| format!("failed to bind DNS upstream socket: {error}"))?;
    socket::set_socket_mark(&socket, mark)?;
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| format!("failed to set upstream DNS read timeout: {error}"))?;
    socket
        .send_to(query, upstream_dns)
        .map_err(|error| format!("failed to send upstream DNS query: {error}"))?;
    let mut response = [0_u8; DNS_BUFFER_LEN];
    let (size, _) = socket
        .recv_from(&mut response)
        .map_err(|error| format!("failed to receive upstream DNS response: {error}"))?;
    Ok(response[..size].to_vec())
}

pub(super) fn resolve_doh(
    query: &[u8],
    endpoint: &str,
    bootstrap_ips: &[IpAddr],
    mark: u32,
) -> Result<Vec<u8>, String> {
    let parsed = parse_https_endpoint(endpoint)?;
    let mut last_error = None;
    for bootstrap_ip in bootstrap_ips {
        match resolve_doh_once(query, &parsed, *bootstrap_ip, mark) {
            Ok(response) => return Ok(response),
            Err(error) => last_error = Some(error),
        }
    }
    Err(format!(
        "DoH query failed for {} via {} bootstrap IP(s): {}",
        endpoint,
        bootstrap_ips.len(),
        last_error.unwrap_or_else(|| "no bootstrap IPs tried".to_string())
    ))
}

fn resolve_doh_once(
    query: &[u8],
    endpoint: &HttpsEndpoint,
    bootstrap_ip: IpAddr,
    mark: u32,
) -> Result<Vec<u8>, String> {
    let address = SocketAddr::new(bootstrap_ip, endpoint.port);
    let tcp = TcpStream::connect_timeout(&address, Duration::from_secs(5))
        .map_err(|error| format!("failed to connect DoH bootstrap {address}: {error}"))?;
    socket::set_socket_mark(&tcp, mark)?;
    tcp.set_read_timeout(Some(Duration::from_secs(8)))
        .map_err(|error| format!("failed to set DoH read timeout: {error}"))?;
    tcp.set_write_timeout(Some(Duration::from_secs(8)))
        .map_err(|error| format!("failed to set DoH write timeout: {error}"))?;

    let server_name = ServerName::try_from(endpoint.host.clone())
        .map_err(|error| format!("invalid DoH server name `{}`: {error}", endpoint.host))?;
    let connection = ClientConnection::new(tls_config(), server_name)
        .map_err(|error| format!("failed to create DoH TLS connection: {error}"))?;
    let mut tls = StreamOwned::new(connection, tcp);
    let request = doh_request(query, endpoint);
    tls.write_all(&request)
        .map_err(|error| format!("failed to write DoH request: {error}"))?;
    tls.flush()
        .map_err(|error| format!("failed to flush DoH request: {error}"))?;

    let mut response = Vec::new();
    tls.read_to_end(&mut response)
        .map_err(|error| format!("failed to read DoH response: {error}"))?;
    let dns_message = parse_http_response(&response)?;
    debug!(
        host = %endpoint.host,
        bootstrap = %bootstrap_ip,
        bytes = dns_message.len(),
        "dns.doh.query"
    );
    Ok(dns_message)
}

fn tls_config() -> Arc<ClientConfig> {
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

fn doh_request(query: &[u8], endpoint: &HttpsEndpoint) -> Vec<u8> {
    let headers = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        endpoint.path,
        endpoint.host,
        query.len()
    );
    let mut request = headers.into_bytes();
    request.extend_from_slice(query);
    request
}

fn parse_http_response(response: &[u8]) -> Result<Vec<u8>, String> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .ok_or_else(|| "DoH HTTP response has no header terminator".to_string())?;
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|error| format!("DoH HTTP headers are not UTF-8: {error}"))?;
    let mut lines = headers.lines();
    let status = lines
        .next()
        .ok_or_else(|| "DoH HTTP response is empty".to_string())?;
    if !status.contains(" 200 ") {
        return Err(format!("DoH HTTP status was `{status}`"));
    }
    let body = &response[header_end..];
    if headers
        .lines()
        .any(|line| line.eq_ignore_ascii_case("transfer-encoding: chunked"))
    {
        return decode_chunked(body);
    }
    if let Some(length) = content_length(headers)? {
        if body.len() < length {
            return Err(format!(
                "DoH body shorter than Content-Length: {} < {length}",
                body.len()
            ));
        }
        return Ok(body[..length].to_vec());
    }
    if body.len() > DOH_MAX_RESPONSE_LEN {
        return Err(format!("DoH body too large: {} bytes", body.len()));
    }
    Ok(body.to_vec())
}

fn content_length(headers: &str) -> Result<Option<usize>, String> {
    for line in headers.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            return value
                .trim()
                .parse::<usize>()
                .map(Some)
                .map_err(|error| format!("invalid DoH Content-Length `{value}`: {error}"));
        }
    }
    Ok(None)
}

fn decode_chunked(body: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoded = Vec::new();
    let mut offset = 0;
    loop {
        let Some(line_end) = find_crlf(body, offset) else {
            return Err("chunked DoH body ended before chunk size".to_string());
        };
        let size_line = std::str::from_utf8(&body[offset..line_end])
            .map_err(|error| format!("chunk size is not UTF-8: {error}"))?;
        let size_hex = size_line.split(';').next().unwrap_or(size_line).trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|error| format!("invalid chunk size `{size_hex}`: {error}"))?;
        offset = line_end + 2;
        if size == 0 {
            return Ok(decoded);
        }
        let data_end = offset
            .checked_add(size)
            .ok_or_else(|| "chunked DoH offset overflow".to_string())?;
        if data_end + 2 > body.len() {
            return Err("chunked DoH body ended inside chunk".to_string());
        }
        decoded.extend_from_slice(&body[offset..data_end]);
        if decoded.len() > DOH_MAX_RESPONSE_LEN {
            return Err(format!(
                "decoded DoH body too large: {} bytes",
                decoded.len()
            ));
        }
        if &body[data_end..data_end + 2] != b"\r\n" {
            return Err("chunked DoH chunk missing trailing CRLF".to_string());
        }
        offset = data_end + 2;
    }
}

fn find_crlf(body: &[u8], start: usize) -> Option<usize> {
    body.get(start..)?
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|relative| start + relative)
}

fn parse_https_endpoint(endpoint: &str) -> Result<HttpsEndpoint, String> {
    validate_doh_endpoint(endpoint)?;
    let rest = endpoint
        .strip_prefix("https://")
        .expect("validated endpoint has https prefix");
    let (host_port, path) = rest
        .split_once('/')
        .expect("validated endpoint has absolute path");
    let (host, port) = match host_port.rsplit_once(':') {
        Some((host, port)) if !host.contains(']') => {
            let port = port
                .parse::<u16>()
                .map_err(|error| format!("invalid DoH endpoint port `{port}`: {error}"))?;
            (host.to_string(), port)
        }
        _ => (host_port.to_string(), 443),
    };
    Ok(HttpsEndpoint {
        host,
        port,
        path: format!("/{path}"),
    })
}

fn udp_bind_for(address: IpAddr) -> SocketAddr {
    match address {
        IpAddr::V4(_) => "0.0.0.0:0".parse().expect("valid IPv4 bind"),
        IpAddr::V6(_) => "[::]:0".parse().expect("valid IPv6 bind"),
    }
}
