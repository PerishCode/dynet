use std::{
    io::{self, Read, Write},
    net::SocketAddr,
    sync::Arc,
    thread::sleep,
    time::{Duration, Instant},
};

pub(super) mod adapter;

use dynet_core::{payload_as, NetworkNode};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
    StreamOwned,
};
use serde::Deserialize;
use sha2::{Digest, Sha224};

use crate::settings::OutboundTcpSettings;

use super::{connect_tcp_socket_bound, ProxiedTcpStream, TcpTarget};

const TLS_PENDING_BUDGET: Duration = Duration::from_millis(250);
const TLS_PENDING_SLEEP: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct TrojanSpec {
    pub(super) tag: String,
    pub(super) server: String,
    pub(super) server_port: u16,
    pub(super) password: String,
    pub(super) sni: String,
    pub(super) skip_cert_verify: bool,
    pub(super) interface_name: Option<String>,
}

pub(crate) struct TrojanTcpStream {
    stream: StreamOwned<ClientConnection, Box<dyn TrojanTransport>>,
    close_notify_sent: bool,
}

pub(super) fn tls_pending_budget_ms() -> u128 {
    TLS_PENDING_BUDGET.as_millis()
}

pub(super) fn tls_pending_sleep_ms() -> u128 {
    TLS_PENDING_SLEEP.as_millis()
}

pub(super) trait TrojanTransport: Read + Write + Send {
    #[allow(dead_code)]
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

impl TrojanTransport for std::net::TcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        std::net::TcpStream::set_read_timeout(self, timeout)
    }
}

impl TrojanTransport for ProxiedTcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        ProxiedTcpStream::set_read_timeout(self, timeout)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrojanPayload {
    server: String,
    #[serde(default)]
    server_ip: Option<String>,
    #[serde(default)]
    server_port: Option<u16>,
    #[serde(default)]
    port: Option<u16>,
    password: String,
    #[serde(default)]
    sni: Option<String>,
    #[serde(default)]
    skip_cert_verify: bool,
    #[serde(default)]
    interface_name: Option<String>,
}

#[derive(Debug)]
struct NoCertificateVerifier;

pub(super) fn spec_from_node(node: &NetworkNode) -> Result<TrojanSpec, String> {
    let payload = payload_as::<TrojanPayload>(node)?;
    let server_port = payload.server_port.or(payload.port).ok_or_else(|| {
        format!(
            "Trojan outbound `{}` requires payload.serverPort or payload.port",
            node.tag
        )
    })?;
    let server = payload
        .server_ip
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(payload.server.as_str())
        .to_string();
    let sni = payload
        .sni
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(payload.server.as_str())
        .to_string();
    let interface_name = payload
        .interface_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    Ok(TrojanSpec {
        tag: node.tag.clone(),
        server,
        server_port,
        password: payload.password,
        sni,
        skip_cert_verify: payload.skip_cert_verify,
        interface_name,
    })
}

pub(super) fn connect_transport(
    spec: &TrojanSpec,
    mark: u32,
    settings: OutboundTcpSettings,
) -> Result<Box<dyn TrojanTransport>, String> {
    connect_tcp_socket_bound(
        &spec.server,
        spec.server_port,
        mark,
        spec.interface_name.as_deref(),
        settings,
    )
    .map(|stream| Box::new(stream) as Box<dyn TrojanTransport>)
}

pub(super) fn connect_tcp_on_stream(
    spec: &TrojanSpec,
    destination: &TcpTarget,
    tcp: Box<dyn TrojanTransport>,
) -> Result<TrojanTcpStream, String> {
    let stream = tls_handshake(spec, tcp)?;
    write_request(spec, destination, stream)
}

pub(super) fn tls_handshake(
    spec: &TrojanSpec,
    tcp: Box<dyn TrojanTransport>,
) -> Result<StreamOwned<ClientConnection, Box<dyn TrojanTransport>>, String> {
    let server_name = ServerName::try_from(spec.sni.clone())
        .map_err(|error| format!("invalid Trojan TLS server name `{}`: {error}", spec.sni))?;
    let connection = ClientConnection::new(tls_config(spec.skip_cert_verify), server_name)
        .map_err(|error| format!("failed to create Trojan TLS connection: {error}"))?;
    let mut stream = StreamOwned::new(connection, tcp);
    let started = Instant::now();
    let mut pending_retries = 0;
    while stream.conn.is_handshaking() {
        match stream.conn.complete_io(&mut stream.sock) {
            Ok(_) => {}
            Err(error) if pending_io_error(&error) && started.elapsed() < TLS_PENDING_BUDGET => {
                pending_retries += 1;
                sleep(TLS_PENDING_SLEEP);
            }
            Err(error) => {
                let pending_elapsed_ms = started.elapsed().as_millis();
                return Err(tls_handshake_error(
                    spec,
                    error,
                    pending_retries,
                    pending_elapsed_ms,
                ));
            }
        }
    }
    Ok(stream)
}

fn pending_io_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

fn tls_handshake_error(
    spec: &TrojanSpec,
    error: io::Error,
    pending_retries: usize,
    pending_elapsed_ms: u128,
) -> String {
    let wait_class = pending_wait_class(&error, pending_retries, pending_elapsed_ms);
    format!(
        "failed Trojan TLS handshake with `{}` after pendingRetries={pending_retries} pendingElapsedMs={pending_elapsed_ms} pendingWaitClass={wait_class}: {error}",
        spec.sni
    )
}

fn pending_wait_class(
    error: &io::Error,
    pending_retries: usize,
    pending_elapsed_ms: u128,
) -> &'static str {
    let pending = pending_io_error(error);
    let over_budget = pending_elapsed_ms >= TLS_PENDING_BUDGET.as_millis();
    if pending && pending_retries == 0 && over_budget {
        "socket-read-timeout"
    } else if pending && pending_retries > 0 {
        "poll-budget-exhausted"
    } else if pending {
        "pending-io"
    } else if pending_retries > 0 {
        "error-after-pending"
    } else if over_budget {
        "error-after-wait"
    } else {
        "immediate-error"
    }
}

pub(super) fn write_request(
    spec: &TrojanSpec,
    destination: &TcpTarget,
    mut stream: StreamOwned<ClientConnection, Box<dyn TrojanTransport>>,
) -> Result<TrojanTcpStream, String> {
    stream
        .write_all(&trojan_request(&spec.password, destination)?)
        .map_err(|error| format!("failed to write Trojan request: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("failed to flush Trojan request: {error}"))?;
    Ok(TrojanTcpStream {
        stream,
        close_notify_sent: false,
    })
}

pub(super) fn server_target(spec: &TrojanSpec) -> TcpTarget {
    match spec.server.parse::<std::net::IpAddr>() {
        Ok(address) => TcpTarget::Socket(SocketAddr::new(address, spec.server_port)),
        Err(_) => TcpTarget::Domain {
            host: spec.server.clone(),
            port: spec.server_port,
        },
    }
}

impl Read for TrojanTcpStream {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(output)
    }
}

impl Write for TrojanTcpStream {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        self.stream.write(input)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

impl Drop for TrojanTcpStream {
    fn drop(&mut self) {
        let _ = self.close_notify();
    }
}

impl TrojanTcpStream {
    #[allow(dead_code)]
    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.sock.set_read_timeout(timeout)
    }

    pub(crate) fn close_notify(&mut self) -> io::Result<()> {
        if !self.close_notify_sent {
            self.stream.conn.send_close_notify();
            self.close_notify_sent = true;
        }
        self.stream.flush()
    }
}

impl ServerCertVerifier for NoCertificateVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
        ]
    }
}

fn tls_config(skip_cert_verify: bool) -> Arc<ClientConfig> {
    if skip_cert_verify {
        return Arc::new(
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerifier))
                .with_no_client_auth(),
        );
    }
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

fn trojan_request(password: &str, target: &TcpTarget) -> Result<Vec<u8>, String> {
    let mut output = hex_sha224(password).into_bytes();
    output.extend_from_slice(b"\r\n");
    output.push(1);
    write_target(&mut output, target)?;
    output.extend_from_slice(b"\r\n");
    Ok(output)
}

fn hex_sha224(password: &str) -> String {
    let digest = Sha224::digest(password.as_bytes());
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn write_target(output: &mut Vec<u8>, target: &TcpTarget) -> Result<(), String> {
    match target {
        TcpTarget::Socket(address) => match address {
            SocketAddr::V4(address) => {
                output.push(1);
                output.extend_from_slice(&address.ip().octets());
                output.extend_from_slice(&address.port().to_be_bytes());
            }
            SocketAddr::V6(address) => {
                output.push(4);
                output.extend_from_slice(&address.ip().octets());
                output.extend_from_slice(&address.port().to_be_bytes());
            }
        },
        TcpTarget::Domain { host, port } => {
            let host = host.as_bytes();
            let host_len = u8::try_from(host.len())
                .map_err(|_| format!("Trojan target host is too long: {}", host.len()))?;
            output.push(3);
            output.push(host_len);
            output.extend_from_slice(host);
            output.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}
