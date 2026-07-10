use native_tls::TlsConnector as NativeTlsConnector;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time,
};
use tokio_native_tls::TlsConnector;

use crate::DnsUpstream;

use super::{
    sniff_dns_response, validate_response_info, DnsQueryInfo, DnsResolution, DnsResolveError,
};

const HTTP_HEADER_LIMIT: usize = 64 * 1024;

pub(super) async fn query_https_upstream(
    upstream: DnsUpstream,
    host: String,
    path: String,
    query: Vec<u8>,
    query_info: Option<DnsQueryInfo>,
    timeout: std::time::Duration,
) -> Result<DnsResolution, DnsResolveError> {
    let response = time::timeout(
        timeout,
        query_https_upstream_inner(&upstream, &host, &path, &query),
    )
    .await
    .map_err(|_| {
        DnsResolveError::new(format!(
            "timed out waiting for DNS upstream {} ({})",
            upstream.id, upstream.address
        ))
    })??;
    let response_info = sniff_dns_response(&response);
    validate_response_info(&upstream, &query_info, &response_info)?;
    Ok(DnsResolution {
        response,
        source: upstream.address,
        upstream,
        query_info,
        response_info,
        ipv6_filtered: false,
        matched_rule_id: None,
    })
}

async fn query_https_upstream_inner(
    upstream: &DnsUpstream,
    host: &str,
    path: &str,
    query: &[u8],
) -> Result<Vec<u8>, DnsResolveError> {
    let tcp = TcpStream::connect(upstream.address)
        .await
        .map_err(|error| {
            DnsResolveError::new(format!(
                "failed connecting DNS-over-HTTPS upstream {} ({}): {error}",
                upstream.id, upstream.address
            ))
        })?;
    let connector = NativeTlsConnector::new()
        .map(TlsConnector::from)
        .map_err(|error| {
            DnsResolveError::new(format!(
                "failed creating TLS connector for DNS upstream {}: {error}",
                upstream.id
            ))
        })?;
    let mut tls = connector.connect(host, tcp).await.map_err(|error| {
        DnsResolveError::new(format!(
            "failed TLS handshake with DNS-over-HTTPS upstream {} ({}): {error}",
            upstream.id, upstream.address
        ))
    })?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        query.len()
    );
    tls.write_all(request.as_bytes()).await.map_err(|error| {
        DnsResolveError::new(format!(
            "failed writing DNS-over-HTTPS request to upstream {}: {error}",
            upstream.id
        ))
    })?;
    tls.write_all(query).await.map_err(|error| {
        DnsResolveError::new(format!(
            "failed writing DNS-over-HTTPS body to upstream {}: {error}",
            upstream.id
        ))
    })?;
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.map_err(|error| {
        DnsResolveError::new(format!(
            "failed reading DNS-over-HTTPS response from upstream {}: {error}",
            upstream.id
        ))
    })?;
    parse_https_dns_response(&upstream.id.to_string(), &response)
}

fn parse_https_dns_response(
    upstream_id: &str,
    response: &[u8],
) -> Result<Vec<u8>, DnsResolveError> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| {
            DnsResolveError::new(format!(
                "invalid DNS-over-HTTPS response from upstream {upstream_id}: missing HTTP headers"
            ))
        })?;
    if header_end > HTTP_HEADER_LIMIT {
        return Err(DnsResolveError::new(format!(
            "invalid DNS-over-HTTPS response from upstream {upstream_id}: headers too large"
        )));
    }
    let headers = std::str::from_utf8(&response[..header_end]).map_err(|error| {
        DnsResolveError::new(format!(
            "invalid DNS-over-HTTPS response headers from upstream {upstream_id}: {error}"
        ))
    })?;
    let mut lines = headers.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if !status.contains(" 200 ") {
        return Err(DnsResolveError::new(format!(
            "DNS-over-HTTPS upstream {upstream_id} returned {status:?}"
        )));
    }
    let body = &response[header_end + 4..];
    if has_chunked_transfer_encoding(headers) {
        return decode_chunked_body(upstream_id, body);
    }
    Ok(body.to_vec())
}

fn has_chunked_transfer_encoding(headers: &str) -> bool {
    headers.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
    })
}

fn decode_chunked_body(upstream_id: &str, body: &[u8]) -> Result<Vec<u8>, DnsResolveError> {
    let mut cursor = 0;
    let mut decoded = Vec::new();
    loop {
        let line_end = body[cursor..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|offset| cursor + offset)
            .ok_or_else(|| {
                DnsResolveError::new(format!(
                    "invalid chunked DNS-over-HTTPS body from upstream {upstream_id}"
                ))
            })?;
        let size_line = std::str::from_utf8(&body[cursor..line_end]).map_err(|error| {
            DnsResolveError::new(format!(
                "invalid chunk size from DNS-over-HTTPS upstream {upstream_id}: {error}"
            ))
        })?;
        let size = usize::from_str_radix(size_line.split(';').next().unwrap_or_default(), 16)
            .map_err(|error| {
                DnsResolveError::new(format!(
                    "invalid chunk size from DNS-over-HTTPS upstream {upstream_id}: {error}"
                ))
            })?;
        cursor = line_end + 2;
        if size == 0 {
            return Ok(decoded);
        }
        let chunk_end = cursor.checked_add(size).ok_or_else(|| {
            DnsResolveError::new(format!(
                "invalid chunked DNS-over-HTTPS body from upstream {upstream_id}"
            ))
        })?;
        let trailer_end = chunk_end.checked_add(2).ok_or_else(|| {
            DnsResolveError::new(format!(
                "invalid chunked DNS-over-HTTPS body from upstream {upstream_id}"
            ))
        })?;
        if body.get(chunk_end..trailer_end) != Some(b"\r\n") {
            return Err(DnsResolveError::new(format!(
                "invalid chunked DNS-over-HTTPS body from upstream {upstream_id}"
            )));
        }
        decoded.extend_from_slice(body.get(cursor..chunk_end).ok_or_else(|| {
            DnsResolveError::new(format!(
                "invalid chunked DNS-over-HTTPS body from upstream {upstream_id}"
            ))
        })?);
        cursor = trailer_end;
    }
}
