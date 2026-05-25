use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::Duration,
};

use crate::outbound_server::Target;
use crate::vmess_crypto::{
    first_16, instruction_key, kdf, open_aes_gcm, seal_aes_gcm, sha256, shadowsocks_response,
    AeadSequence, LengthMask, VmessNonce, AEAD_TAG_LEN,
};

pub(crate) struct VmessHeaderServer {
    address: SocketAddr,
    receiver: Receiver<Result<ObservedVmessHeader, String>>,
    handle: JoinHandle<()>,
}

pub(crate) struct VmessFrameEofServer {
    address: SocketAddr,
    receiver: Receiver<Result<ObservedVmessRequest, String>>,
    handle: JoinHandle<()>,
}

pub(crate) struct VmessResponseServer {
    address: SocketAddr,
    receiver: Receiver<Result<ObservedVmessRequest, String>>,
    handle: JoinHandle<()>,
}

pub(crate) struct ObservedVmessHeader {
    pub(crate) target: Target,
}

pub(crate) struct ObservedVmessRequest {
    pub(crate) target: Target,
    pub(crate) first_payload_len: usize,
}

struct RequestHeader {
    data_iv: [u8; 16],
    data_key: [u8; 16],
    response_auth: u8,
    target: Target,
}

impl VmessHeaderServer {
    pub(crate) fn spawn(uuid: &str) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("VMess header server binds localhost");
        let address = listener
            .local_addr()
            .expect("VMess header server has local address");
        let uuid = uuid.to_string();
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            let result = serve_header_only(listener, &uuid);
            let _ = sender.send(result);
        });
        Self {
            address,
            receiver,
            handle,
        }
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) fn request(self) -> Result<ObservedVmessHeader, String> {
        let result = self
            .receiver
            .recv_timeout(Duration::from_secs(3))
            .map_err(|error| format!("timed out waiting for VMess header server: {error}"))?;
        self.handle
            .join()
            .map_err(|_| "VMess header server panicked".to_string())?;
        result
    }
}

impl VmessFrameEofServer {
    pub(crate) fn spawn(uuid: &str) -> Self {
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("VMess EOF server binds localhost");
        let address = listener
            .local_addr()
            .expect("VMess EOF server has local address");
        let uuid = uuid.to_string();
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            let result = serve_frame_then_eof(listener, &uuid);
            let _ = sender.send(result);
        });
        Self {
            address,
            receiver,
            handle,
        }
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) fn request(self) -> Result<ObservedVmessRequest, String> {
        let result = self
            .receiver
            .recv_timeout(Duration::from_secs(3))
            .map_err(|error| format!("timed out waiting for VMess EOF server: {error}"))?;
        self.handle
            .join()
            .map_err(|_| "VMess EOF server panicked".to_string())?;
        result
    }
}

impl VmessResponseServer {
    pub(crate) fn spawn(uuid: &str, ss_password: &str, ss_plain_response: &[u8]) -> Self {
        Self::spawn_delayed(
            uuid,
            ss_password,
            ss_plain_response,
            Duration::from_millis(0),
        )
    }

    pub(crate) fn spawn_delayed(
        uuid: &str,
        ss_password: &str,
        ss_plain_response: &[u8],
        response_delay: Duration,
    ) -> Self {
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("VMess responder binds localhost");
        let address = listener
            .local_addr()
            .expect("VMess responder has local address");
        let uuid = uuid.to_string();
        let ss_password = ss_password.to_string();
        let ss_plain_response = ss_plain_response.to_vec();
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            let result = serve_one(
                listener,
                &uuid,
                &ss_password,
                &ss_plain_response,
                response_delay,
            );
            let _ = sender.send(result);
        });
        Self {
            address,
            receiver,
            handle,
        }
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) fn request(self) -> Result<ObservedVmessRequest, String> {
        let result = self
            .receiver
            .recv_timeout(Duration::from_secs(3))
            .map_err(|error| format!("timed out waiting for VMess responder: {error}"))?;
        self.handle
            .join()
            .map_err(|_| "VMess responder panicked".to_string())?;
        result
    }
}

fn serve_header_only(listener: TcpListener, uuid: &str) -> Result<ObservedVmessHeader, String> {
    let (mut stream, _) = listener
        .accept()
        .map_err(|error| format!("failed to accept VMess client: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| format!("failed to set VMess read timeout: {error}"))?;
    let header = read_request_header(&mut stream, uuid)?;
    Ok(ObservedVmessHeader {
        target: header.target,
    })
}

fn serve_frame_then_eof(listener: TcpListener, uuid: &str) -> Result<ObservedVmessRequest, String> {
    let (mut stream, _) = listener
        .accept()
        .map_err(|error| format!("failed to accept VMess client: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| format!("failed to set VMess read timeout: {error}"))?;
    let header = read_request_header(&mut stream, uuid)?;
    let mut read_mask = LengthMask::new(&header.data_iv);
    let mut opener = AeadSequence::new(&header.data_key, VmessNonce::new(&header.data_iv))?;
    let first_payload = read_frame(&mut stream, &mut read_mask, &mut opener)?;
    Ok(ObservedVmessRequest {
        target: header.target,
        first_payload_len: first_payload.len(),
    })
}

fn serve_one(
    listener: TcpListener,
    uuid: &str,
    ss_password: &str,
    ss_plain_response: &[u8],
    response_delay: Duration,
) -> Result<ObservedVmessRequest, String> {
    let (mut stream, _) = listener
        .accept()
        .map_err(|error| format!("failed to accept VMess client: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| format!("failed to set VMess read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| format!("failed to set VMess write timeout: {error}"))?;
    let header = read_request_header(&mut stream, uuid)?;
    let mut read_mask = LengthMask::new(&header.data_iv);
    let mut opener = AeadSequence::new(&header.data_key, VmessNonce::new(&header.data_iv))?;
    let first_payload = read_frame(&mut stream, &mut read_mask, &mut opener)?;
    let ss_response = shadowsocks_response(ss_password, ss_plain_response)?;
    thread::sleep(response_delay);
    write_response(&mut stream, &header, &ss_response)?;
    Ok(ObservedVmessRequest {
        target: header.target,
        first_payload_len: first_payload.len(),
    })
}

fn read_request_header(stream: &mut TcpStream, uuid: &str) -> Result<RequestHeader, String> {
    let instruction_key = instruction_key(uuid)?;
    let auth_id = read_exact(stream, 16, "auth id")?;
    let mut encrypted_len = read_exact(stream, 2 + AEAD_TAG_LEN, "header length")?;
    let nonce = read_exact(stream, 8, "header nonce")?;
    let len_key = kdf(
        &instruction_key,
        &[b"VMess Header AEAD Key_Length", &auth_id, &nonce],
    );
    let len_nonce = kdf(
        &instruction_key,
        &[b"VMess Header AEAD Nonce_Length", &auth_id, &nonce],
    );
    let length = open_aes_gcm(
        &len_key[..16],
        &len_nonce[..12],
        &auth_id,
        &mut encrypted_len,
    )?;
    if length.len() != 2 {
        return Err(format!(
            "VMess header length plaintext was {} bytes",
            length.len()
        ));
    }
    let header_len = usize::from(u16::from_be_bytes([length[0], length[1]]));
    let mut encrypted_header = read_exact(stream, header_len + AEAD_TAG_LEN, "header")?;
    let header_key = kdf(
        &instruction_key,
        &[b"VMess Header AEAD Key", &auth_id, &nonce],
    );
    let header_nonce = kdf(
        &instruction_key,
        &[b"VMess Header AEAD Nonce", &auth_id, &nonce],
    );
    let header = open_aes_gcm(
        &header_key[..16],
        &header_nonce[..12],
        &auth_id,
        &mut encrypted_header,
    )?;
    parse_header(&header)
}

fn parse_header(header: &[u8]) -> Result<RequestHeader, String> {
    if header.len() < 41 {
        return Err(format!("VMess request header too short: {}", header.len()));
    }
    let security = header[35] & 0x0f;
    if security != 3 {
        return Err(format!(
            "VMess responder only supports AES-128-GCM, got {security}"
        ));
    }
    if header[37] != 1 {
        return Err(format!(
            "VMess responder only supports TCP command {}",
            header[37]
        ));
    }
    Ok(RequestHeader {
        data_iv: header[1..17].try_into().expect("slice is exactly 16 bytes"),
        data_key: header[17..33]
            .try_into()
            .expect("slice is exactly 16 bytes"),
        response_auth: header[33],
        target: parse_destination(header)?,
    })
}

fn parse_destination(header: &[u8]) -> Result<Target, String> {
    let port = u16::from_be_bytes([header[38], header[39]]);
    match header[40] {
        1 => parse_ipv4_target(header, port),
        2 => parse_domain_target(header, port),
        3 => parse_ipv6_target(header, port),
        other => Err(format!("unsupported VMess address type {other}")),
    }
}

fn parse_ipv4_target(header: &[u8], port: u16) -> Result<Target, String> {
    if header.len() < 45 {
        return Err("VMess IPv4 target header is truncated".to_string());
    }
    let address = Ipv4Addr::new(header[41], header[42], header[43], header[44]);
    Ok(Target::Socket(SocketAddr::new(IpAddr::V4(address), port)))
}

fn parse_domain_target(header: &[u8], port: u16) -> Result<Target, String> {
    let Some(host_len) = header.get(41).copied().map(usize::from) else {
        return Err("VMess domain length is missing".to_string());
    };
    let end = 42 + host_len;
    if header.len() < end {
        return Err("VMess domain target header is truncated".to_string());
    }
    let host = std::str::from_utf8(&header[42..end])
        .map_err(|error| format!("VMess domain target is not UTF-8: {error}"))?
        .to_string();
    Ok(Target::Domain { host, port })
}

fn parse_ipv6_target(header: &[u8], port: u16) -> Result<Target, String> {
    if header.len() < 57 {
        return Err("VMess IPv6 target header is truncated".to_string());
    }
    let mut octets = [0_u8; 16];
    octets.copy_from_slice(&header[41..57]);
    Ok(Target::Socket(SocketAddr::new(
        IpAddr::V6(Ipv6Addr::from(octets)),
        port,
    )))
}

fn read_frame(
    stream: &mut TcpStream,
    mask: &mut LengthMask,
    opener: &mut AeadSequence<VmessNonce>,
) -> Result<Vec<u8>, String> {
    let length_bytes = read_exact(stream, 2, "VMess frame length")?;
    let frame_len =
        usize::from(u16::from_be_bytes([length_bytes[0], length_bytes[1]]) ^ mask.next());
    if frame_len < AEAD_TAG_LEN {
        return Err(format!("VMess frame length shorter than tag: {frame_len}"));
    }
    let mut frame = read_exact(stream, frame_len, "VMess frame payload")?;
    opener.open(&mut frame)
}

fn write_response(
    stream: &mut TcpStream,
    header: &RequestHeader,
    payload: &[u8],
) -> Result<(), String> {
    let response_iv = first_16(&sha256(&header.data_iv));
    let response_key = first_16(&sha256(&header.data_key));
    write_response_header(stream, &response_key, &response_iv, header.response_auth)?;
    let mut sealer = AeadSequence::new(&response_key, VmessNonce::new(&response_iv))?;
    let mut mask = LengthMask::new(&response_iv);
    let mut frame = payload.to_vec();
    sealer.seal(&mut frame)?;
    let length = u16::try_from(frame.len())
        .map_err(|_| format!("VMess response frame too large: {}", frame.len()))?;
    stream
        .write_all(&(length ^ mask.next()).to_be_bytes())
        .map_err(|error| format!("failed to write VMess response frame length: {error}"))?;
    stream
        .write_all(&frame)
        .map_err(|error| format!("failed to write VMess response frame: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("failed to flush VMess response: {error}"))
}

fn write_response_header(
    stream: &mut TcpStream,
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
    response_auth: u8,
) -> Result<(), String> {
    let mut body = vec![response_auth, 0, 0, 0];
    let len_key = kdf(response_key, &[b"AEAD Resp Header Len Key"]);
    let len_nonce = kdf(response_iv, &[b"AEAD Resp Header Len IV"]);
    let mut length = (body.len() as u16).to_be_bytes().to_vec();
    seal_aes_gcm(&len_key[..16], &len_nonce[..12], &[], &mut length)?;
    let body_key = kdf(response_key, &[b"AEAD Resp Header Key"]);
    let body_nonce = kdf(response_iv, &[b"AEAD Resp Header IV"]);
    seal_aes_gcm(&body_key[..16], &body_nonce[..12], &[], &mut body)?;
    stream
        .write_all(&length)
        .map_err(|error| format!("failed to write VMess response header length: {error}"))?;
    stream
        .write_all(&body)
        .map_err(|error| format!("failed to write VMess response header: {error}"))
}

fn read_exact(stream: &mut TcpStream, len: usize, label: &str) -> Result<Vec<u8>, String> {
    let mut output = vec![0_u8; len];
    stream
        .read_exact(&mut output)
        .map_err(|error| format!("failed to read VMess {label}: {error}"))?;
    Ok(output)
}
