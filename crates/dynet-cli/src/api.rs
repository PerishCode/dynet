use std::{
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream},
};

use crate::{cli::ApiServeOptions, model::ApiCapabilityReport, output::json_string};

pub(crate) fn serve(options: ApiServeOptions) -> Result<i32, String> {
    let address: SocketAddr = options
        .bind
        .parse()
        .map_err(|error| format!("invalid API bind address {}: {error}", options.bind))?;
    if !options.allow_non_loopback && !is_loopback(address.ip()) {
        return Err(
            "api serve only binds loopback by default; pass --allow-non-loopback explicitly"
                .to_string(),
        );
    }

    let listener = TcpListener::bind(address)
        .map_err(|error| format!("failed to bind API listener {address}: {error}"))?;
    let bound = listener
        .local_addr()
        .map_err(|error| format!("failed to read API listener address: {error}"))?;
    eprintln!("dynet: api listening on http://{bound}");

    for stream in listener.incoming() {
        let stream = stream.map_err(|error| format!("failed to accept API request: {error}"))?;
        handle_stream(stream)?;
        if options.once {
            break;
        }
    }
    Ok(0)
}

fn is_loopback(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_loopback(),
        IpAddr::V6(address) => address.is_loopback(),
    }
}

fn handle_stream(mut stream: TcpStream) -> Result<(), String> {
    let mut buffer = [0_u8; 8192];
    let count = stream
        .read(&mut buffer)
        .map_err(|error| format!("failed to read API request: {error}"))?;
    let request = String::from_utf8_lossy(&buffer[..count]);
    let first_line = request.lines().next().unwrap_or_default();
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();

    let (status, body) = match (method, path) {
        ("GET", "/health") => (
            "200 OK",
            r#"{"status":"ok","service":"dynet-api"}"#.to_string(),
        ),
        ("GET", "/v1/capabilities") => ("200 OK", json_string(&ApiCapabilityReport::current())?),
        _ => ("404 Not Found", r#"{"error":"not found"}"#.to_string()),
    };

    write_response(&mut stream, status, &body)
}

fn write_response(stream: &mut TcpStream, status: &str, body: &str) -> Result<(), String> {
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .map_err(|error| format!("failed to write API response: {error}"))
}
