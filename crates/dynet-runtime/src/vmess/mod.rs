use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    time::Duration,
};

mod crypto;
mod target;

use rand::RngCore;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, CHACHA20_POLY1305, NONCE_LEN};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};
use tracing::debug;

use crate::outbound::{
    self,
    buffered_read::{self, BufferedRead},
};

use self::crypto::{
    chacha_key, encrypted_auth_id, first_16, fnv1a32, instruction_key, kdf, open_aes_gcm,
    seal_header, seal_header_length, sha256,
};
use self::target::write_destination;
pub(crate) use self::target::VmessTarget;

const AEAD_TAG_LEN: usize = 16;
const MAX_HEADER_LEN: usize = 316;
const MAX_FRAME_PAYLOAD_LEN: usize = 8192;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct VmessSpec {
    pub(crate) tag: String,
    pub(crate) server: String,
    pub(crate) server_port: u16,
    pub(crate) uuid: String,
    pub(crate) cipher: String,
}

pub(crate) struct VmessTcpStream {
    stream: Box<dyn VmessTransport>,
    response_header: Option<ResponseHeaderInfo>,
    response_header_content_len: Option<usize>,
    opener: FrameAead,
    sealer: FrameAead,
    read_mask: LengthMask,
    write_mask: LengthMask,
    encrypted_read: VecDeque<u8>,
    pending_frame_len: Option<usize>,
    plain_read: VecDeque<u8>,
    eof: bool,
}

pub(crate) trait VmessTransport: Read + Write {
    #[allow(dead_code)]
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

impl VmessTransport for std::net::TcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        std::net::TcpStream::set_read_timeout(self, timeout)
    }
}

impl VmessTransport for outbound::ProxiedTcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(timeout)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum DataCipher {
    Aes128Gcm,
    Chacha20Poly1305,
}

struct FrameAead {
    key: LessSafeKey,
    nonce: VmessNonceSequence,
}

struct LengthMask {
    reader: Box<dyn XofReader>,
    buffer: [u8; 2],
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ResponseHeaderInfo {
    key: [u8; 16],
    iv: [u8; 16],
    auth: u8,
}

#[derive(Debug, Clone)]
struct VmessNonceSequence {
    count: u16,
    nonce: [u8; NONCE_LEN],
}

pub(crate) fn connect_tcp(
    spec: &VmessSpec,
    destination: VmessTarget,
    mark: u32,
) -> Result<VmessTcpStream, String> {
    let stream = outbound::connect_tcp_socket(&spec.server, spec.server_port, mark)?;
    connect_tcp_on_stream(spec, destination, Box::new(stream))
}

pub(crate) fn connect_tcp_on_stream(
    spec: &VmessSpec,
    destination: VmessTarget,
    mut stream: Box<dyn VmessTransport>,
) -> Result<VmessTcpStream, String> {
    let request = ClientRequest::build(spec, &destination)?;
    stream
        .write_all(&request.header)
        .map_err(|error| format!("failed to write VMess request header: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("failed to flush VMess request header: {error}"))?;
    debug!(
        outbound = %spec.tag,
        destination = %destination,
        "vmess.tcp.connected"
    );
    Ok(VmessTcpStream {
        stream,
        response_header: Some(request.response_header),
        response_header_content_len: None,
        opener: request.opener,
        sealer: request.sealer,
        read_mask: request.read_mask,
        write_mask: request.write_mask,
        encrypted_read: VecDeque::new(),
        pending_frame_len: None,
        plain_read: VecDeque::new(),
        eof: false,
    })
}

impl Read for VmessTcpStream {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while self.plain_read.is_empty() && !self.eof {
            self.read_next_frame()?;
        }
        let count = output.len().min(self.plain_read.len());
        for slot in &mut output[..count] {
            *slot = self
                .plain_read
                .pop_front()
                .expect("plain_read has enough bytes");
        }
        Ok(count)
    }
}

impl Write for VmessTcpStream {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        let count = input.len().min(MAX_FRAME_PAYLOAD_LEN);
        let mut payload = input[..count].to_vec();
        self.sealer
            .seal(&mut payload)
            .map_err(std::io::Error::other)?;
        let length = u16::try_from(payload.len())
            .map_err(|_| std::io::Error::other("VMess frame too large"))?;
        let masked = length ^ self.write_mask.next_u16();
        self.stream.write_all(&masked.to_be_bytes())?;
        self.stream.write_all(&payload)?;
        Ok(count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

impl VmessTcpStream {
    #[allow(dead_code)]
    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(timeout)
    }

    fn read_next_frame(&mut self) -> io::Result<()> {
        if self.response_header.is_some() {
            self.read_response_header()?;
            if self.response_header.is_some() {
                return Err(buffered_read::pending("VMess response header is not ready"));
            }
        }
        let frame_len = match self.pending_frame_len {
            Some(frame_len) => frame_len,
            None => {
                let length_bytes = match self.read_buffered(2, "VMess frame length")? {
                    BufferedRead::Ready(bytes) => bytes,
                    BufferedRead::Pending => {
                        return Err(buffered_read::pending("VMess frame length is not ready"));
                    }
                    BufferedRead::Eof => {
                        self.eof = true;
                        return Ok(());
                    }
                };
                let frame_len = u16::from_be_bytes([length_bytes[0], length_bytes[1]])
                    ^ self.read_mask.next_u16();
                let frame_len = usize::from(frame_len);
                self.pending_frame_len = Some(frame_len);
                frame_len
            }
        };
        if frame_len < AEAD_TAG_LEN {
            return Err(buffered_read::invalid_data(format!(
                "VMess frame length shorter than tag: {frame_len}"
            )));
        }
        if frame_len == AEAD_TAG_LEN {
            self.eof = true;
            self.pending_frame_len = None;
            return Ok(());
        }
        let mut frame = match self.read_buffered(frame_len, "VMess frame payload")? {
            BufferedRead::Ready(bytes) => bytes,
            BufferedRead::Pending => {
                return Err(buffered_read::pending("VMess frame payload is not ready"));
            }
            BufferedRead::Eof => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "failed to read VMess frame payload: unexpected EOF",
                ))
            }
        };
        self.pending_frame_len = None;
        let plaintext = self
            .opener
            .open(&mut frame)
            .map_err(buffered_read::invalid_data)?;
        self.plain_read.extend(plaintext);
        Ok(())
    }

    fn read_response_header(&mut self) -> io::Result<()> {
        let Some(info) = self.response_header.as_ref().cloned() else {
            return Ok(());
        };
        let content_len = match self.response_header_content_len {
            Some(content_len) => content_len,
            None => self.read_response_header_len(&info)?,
        };
        let mut encrypted_header =
            match self.read_buffered(content_len + AEAD_TAG_LEN, "VMess response header")? {
                BufferedRead::Ready(bytes) => bytes,
                BufferedRead::Pending => {
                    return Err(buffered_read::pending("VMess response header is not ready"));
                }
                BufferedRead::Eof => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "failed to read VMess response header: unexpected EOF",
                    ))
                }
            };
        let header_key = kdf(&info.key, &[b"AEAD Resp Header Key"]);
        let header_nonce = kdf(&info.iv, &[b"AEAD Resp Header IV"]);
        let header = open_aes_gcm(
            &header_key[..16],
            &header_nonce[..12],
            &[],
            &mut encrypted_header,
        )
        .map_err(buffered_read::invalid_data)?;
        if header.len() < 4 {
            return Err(buffered_read::invalid_data(format!(
                "VMess response header too short: {}",
                header.len()
            )));
        }
        if header[0] != info.auth {
            return Err(buffered_read::invalid_data(format!(
                "VMess response authentication mismatch: expected {}, got {}",
                info.auth, header[0]
            )));
        }
        self.response_header = None;
        self.response_header_content_len = None;
        Ok(())
    }

    fn read_response_header_len(&mut self, info: &ResponseHeaderInfo) -> io::Result<usize> {
        let mut encrypted_len =
            match self.read_buffered(2 + AEAD_TAG_LEN, "VMess response header length")? {
                BufferedRead::Ready(bytes) => bytes,
                BufferedRead::Pending => {
                    return Err(buffered_read::pending(
                        "VMess response header length is not ready",
                    ));
                }
                BufferedRead::Eof => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "failed to read VMess response header length: unexpected EOF",
                    ))
                }
            };
        let len_key = kdf(&info.key, &[b"AEAD Resp Header Len Key"]);
        let len_nonce = kdf(&info.iv, &[b"AEAD Resp Header Len IV"]);
        let length_plain = open_aes_gcm(&len_key[..16], &len_nonce[..12], &[], &mut encrypted_len)
            .map_err(buffered_read::invalid_data)?;
        if length_plain.len() != 2 {
            return Err(buffered_read::invalid_data(format!(
                "VMess response header length plaintext was {} bytes",
                length_plain.len()
            )));
        }
        let content_len = usize::from(u16::from_be_bytes([length_plain[0], length_plain[1]]));
        self.response_header_content_len = Some(content_len);
        Ok(content_len)
    }

    fn read_buffered(&mut self, len: usize, label: &str) -> io::Result<BufferedRead> {
        buffered_read::read_exact(&mut *self.stream, &mut self.encrypted_read, len, label)
    }
}

struct ClientRequest {
    header: Vec<u8>,
    response_header: ResponseHeaderInfo,
    opener: FrameAead,
    sealer: FrameAead,
    read_mask: LengthMask,
    write_mask: LengthMask,
}

impl ClientRequest {
    fn build(spec: &VmessSpec, destination: &VmessTarget) -> Result<Self, String> {
        let cipher = DataCipher::from_name(&spec.cipher)?;
        let instruction_key = instruction_key(&spec.uuid)?;
        let auth_id = encrypted_auth_id(&instruction_key);

        let mut header = [0_u8; MAX_HEADER_LEN + AEAD_TAG_LEN];
        header[0] = 1;
        rand::thread_rng().fill_bytes(&mut header[1..34]);
        let data_iv: [u8; 16] = header[1..17].try_into().expect("slice is exactly 16 bytes");
        let data_key: [u8; 16] = header[17..33]
            .try_into()
            .expect("slice is exactly 16 bytes");
        let response_auth = header[33];

        let response_iv = first_16(&sha256(&data_iv));
        let response_key = first_16(&sha256(&data_key));
        let opener = FrameAead::new(cipher, &response_key, &response_iv)?;
        let sealer = FrameAead::new(cipher, &data_key, &data_iv)?;
        let read_mask = LengthMask::new(&response_iv);
        let write_mask = LengthMask::new(&data_iv);

        header[34] = 0x01 | 0x04;
        let margin_len = rand::random::<u8>() & 0x0f;
        header[35] = (margin_len << 4) | cipher.security_byte();
        header[37] = 1;
        let mut cursor = write_destination(&mut header, destination)?;
        if margin_len > 0 {
            let end = cursor + usize::from(margin_len);
            rand::thread_rng().fill_bytes(&mut header[cursor..end]);
            cursor = end;
        }
        let checksum = fnv1a32(&header[..cursor]).to_be_bytes();
        header[cursor..cursor + 4].copy_from_slice(&checksum);
        cursor += 4;

        let mut nonce = [0_u8; 8];
        rand::thread_rng().fill_bytes(&mut nonce);
        let encrypted_length = seal_header_length(cursor, &instruction_key, &auth_id, &nonce)?;
        let mut encrypted_header = header[..cursor].to_vec();
        seal_header(&mut encrypted_header, &instruction_key, &auth_id, &nonce)?;

        let mut request =
            Vec::with_capacity(16 + encrypted_length.len() + nonce.len() + encrypted_header.len());
        request.extend_from_slice(&auth_id);
        request.extend_from_slice(&encrypted_length);
        request.extend_from_slice(&nonce);
        request.extend_from_slice(&encrypted_header);

        Ok(Self {
            header: request,
            response_header: ResponseHeaderInfo {
                key: response_key,
                iv: response_iv,
                auth: response_auth,
            },
            opener,
            sealer,
            read_mask,
            write_mask,
        })
    }
}

impl DataCipher {
    fn from_name(name: &str) -> Result<Self, String> {
        match name.trim().to_ascii_lowercase().as_str() {
            "" | "auto" | "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => Ok(Self::Chacha20Poly1305),
            other => Err(format!("unsupported VMess cipher `{other}`")),
        }
    }

    fn security_byte(self) -> u8 {
        match self {
            Self::Aes128Gcm => 3,
            Self::Chacha20Poly1305 => 4,
        }
    }

    fn algorithm(self) -> &'static ring::aead::Algorithm {
        match self {
            Self::Aes128Gcm => &AES_128_GCM,
            Self::Chacha20Poly1305 => &CHACHA20_POLY1305,
        }
    }

    fn key_bytes(self, key: &[u8; 16]) -> Vec<u8> {
        match self {
            Self::Aes128Gcm => key.to_vec(),
            Self::Chacha20Poly1305 => chacha_key(key).to_vec(),
        }
    }
}

impl FrameAead {
    fn new(cipher: DataCipher, key: &[u8; 16], iv: &[u8; 16]) -> Result<Self, String> {
        let key = UnboundKey::new(cipher.algorithm(), &cipher.key_bytes(key))
            .map_err(|_| "failed to initialize VMess data AEAD key".to_string())?;
        Ok(Self {
            key: LessSafeKey::new(key),
            nonce: VmessNonceSequence::new(iv),
        })
    }

    fn seal(&mut self, payload: &mut Vec<u8>) -> Result<(), String> {
        self.key
            .seal_in_place_append_tag(self.nonce.next(), Aad::empty(), payload)
            .map_err(|_| "failed to seal VMess frame".to_string())
    }

    fn open(&mut self, frame: &mut [u8]) -> Result<Vec<u8>, String> {
        let plaintext = self
            .key
            .open_in_place(self.nonce.next(), Aad::empty(), frame)
            .map_err(|_| "failed to open VMess frame".to_string())?;
        Ok(plaintext.to_vec())
    }
}

impl LengthMask {
    fn new(seed: &[u8]) -> Self {
        let mut hasher = Shake128::default();
        Update::update(&mut hasher, seed);
        Self {
            reader: Box::new(hasher.finalize_xof()),
            buffer: [0_u8; 2],
        }
    }

    fn next_u16(&mut self) -> u16 {
        self.reader.read(&mut self.buffer);
        u16::from_be_bytes(self.buffer)
    }
}

impl VmessNonceSequence {
    fn new(seed: &[u8; 16]) -> Self {
        let mut nonce = [0_u8; NONCE_LEN];
        nonce[2..].copy_from_slice(&seed[2..12]);
        Self { count: 0, nonce }
    }

    fn next(&mut self) -> Nonce {
        let nonce = Nonce::assume_unique_for_key(self.nonce);
        self.count = self.count.wrapping_add(1);
        self.nonce[0] = (self.count >> 8) as u8;
        self.nonce[1] = (self.count & 0xff) as u8;
        nonce
    }
}
