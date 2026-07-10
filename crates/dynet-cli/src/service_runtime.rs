use std::{net::SocketAddr, time::Duration};

use serde::Deserialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{sleep, Instant},
};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RuntimeConfigStatus {
    pub generation: u64,
    pub fingerprint: String,
    pub last_reload_outcome: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReloadAudit {
    pub id: u64,
    pub outcome: String,
    pub generation_after: u64,
    pub changed_fields: Vec<String>,
    pub restart_required_fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ReloadsResponse {
    reloads: Vec<ReloadAudit>,
}

pub(crate) async fn status(bind: SocketAddr) -> Result<RuntimeConfigStatus, String> {
    get_json(bind, "/api/v1/runtime/config").await
}

pub(crate) async fn wait_ready(
    bind: SocketAddr,
    wait: Duration,
) -> Result<RuntimeConfigStatus, String> {
    let deadline = Instant::now() + wait;
    loop {
        match status(bind).await {
            Ok(status) => return Ok(status),
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(format!("dynet runtime did not become ready: {error}")),
        }
    }
}

pub(crate) async fn latest_reload(bind: SocketAddr) -> Result<Option<ReloadAudit>, String> {
    let response = get_json::<ReloadsResponse>(bind, "/api/v1/runtime/reloads?limit=1").await?;
    Ok(response.reloads.into_iter().last())
}

pub(crate) async fn wait_reload_after(
    bind: SocketAddr,
    after_id: u64,
    wait: Duration,
) -> Result<ReloadAudit, String> {
    let deadline = Instant::now() + wait;
    loop {
        let path = format!("/api/v1/runtime/reloads?afterId={after_id}&limit=1");
        let response = get_json::<ReloadsResponse>(bind, &path).await?;
        if let Some(audit) = response.reloads.into_iter().last() {
            return Ok(audit);
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for dynet reload audit".to_string());
        }
        sleep(Duration::from_millis(50)).await;
    }
}

async fn get_json<T>(bind: SocketAddr, path: &str) -> Result<T, String>
where
    T: for<'de> Deserialize<'de>,
{
    let mut stream = TcpStream::connect(bind)
        .await
        .map_err(|error| format!("failed connecting to dynet control plane {bind}: {error}"))?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {bind}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| format!("failed writing dynet control request: {error}"))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|error| format!("failed reading dynet control response: {error}"))?;
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .ok_or_else(|| "dynet control response has no HTTP header terminator".to_string())?;
    let headers = String::from_utf8_lossy(&response[..header_end]);
    let status_line = headers.lines().next().unwrap_or_default();
    if !status_line.contains(" 200 ") {
        return Err(format!("dynet control request failed: {status_line}"));
    }
    serde_json::from_slice(&response[header_end..])
        .map_err(|error| format!("failed decoding dynet control response: {error}"))
}
