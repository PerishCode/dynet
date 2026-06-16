use std::{collections::HashMap, net::SocketAddr};

use aes_gcm::{aead::Aead, Nonce};
use rand::{rngs::OsRng, RngCore};

use crate::{address, Error};

use super::{
    crypto::{decrypt_separate_header, encrypt_separate_header, session_cipher},
    replay::ReplayWindow,
    unix_timestamp, validate_timestamp, Cipher, HEADER_TYPE_CLIENT_PACKET,
    HEADER_TYPE_SERVER_PACKET, KEY_SIZE, SEPARATE_HEADER_SIZE, SESSION_ID_SIZE, TAG_SIZE,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct UdpSession {
    cipher: Cipher,
    session_id: [u8; SESSION_ID_SIZE],
    packet_id: u64,
    server_windows: HashMap<[u8; SESSION_ID_SIZE], ReplayWindow>,
}

impl UdpSession {
    pub(super) fn new(cipher: Cipher) -> Self {
        let mut session_id = [0_u8; SESSION_ID_SIZE];
        OsRng.fill_bytes(&mut session_id);
        Self {
            cipher,
            session_id,
            packet_id: 0,
            server_windows: HashMap::new(),
        }
    }

    pub(crate) fn encode_udp_datagram(
        &mut self,
        target: SocketAddr,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let packet_id = self.packet_id;
        self.packet_id = self.packet_id.checked_add(1).ok_or_else(|| {
            Error::new("outbound-crypto", "Shadowsocks 2022 UDP packet ID overflow")
        })?;

        let mut separate_header = [0_u8; SEPARATE_HEADER_SIZE];
        separate_header[..SESSION_ID_SIZE].copy_from_slice(&self.session_id);
        separate_header[SESSION_ID_SIZE..].copy_from_slice(&packet_id.to_be_bytes());

        let target_header = address::socks_address(target);
        let mut body = Vec::with_capacity(1 + 8 + 2 + target_header.len() + payload.len());
        body.push(HEADER_TYPE_CLIENT_PACKET);
        body.extend_from_slice(&unix_timestamp().to_be_bytes());
        body.extend_from_slice(&0_u16.to_be_bytes());
        body.extend_from_slice(&target_header);
        body.extend_from_slice(payload);

        self.encrypt_udp_body(&separate_header, &body)
    }

    pub(crate) fn decode_udp_datagram(&mut self, packet: &[u8]) -> Result<Vec<u8>, Error> {
        if packet.len() < SEPARATE_HEADER_SIZE + TAG_SIZE {
            return Err(Error::new(
                "outbound-crypto",
                "Shadowsocks 2022 UDP packet is too short",
            ));
        }
        let (encrypted_header, encrypted_body) = packet.split_at(SEPARATE_HEADER_SIZE);
        let separate_header = decrypt_separate_header(&self.cipher.key, encrypted_header)?;
        let server_session_id: [u8; SESSION_ID_SIZE] = separate_header[..SESSION_ID_SIZE]
            .try_into()
            .expect("server session ID slice");
        if server_session_id == self.session_id {
            return Err(address::packet_error(
                "server reused Shadowsocks 2022 client session ID",
            ));
        }
        let server_packet_id = u64::from_be_bytes(
            separate_header[SESSION_ID_SIZE..]
                .try_into()
                .expect("server packet ID slice"),
        );
        let plaintext = decrypt_udp_body(&self.cipher.key, &separate_header, encrypted_body)?;
        let payload = decode_server_packet(&self.session_id, &plaintext)?;
        self.server_windows
            .entry(server_session_id)
            .or_default()
            .check_and_update(server_packet_id)?;
        Ok(payload)
    }

    fn encrypt_udp_body(
        &self,
        separate_header: &[u8; SEPARATE_HEADER_SIZE],
        body: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let encrypted_header = encrypt_separate_header(&self.cipher.key, separate_header)?;
        let cipher = session_cipher(&self.cipher.key, &separate_header[..SESSION_ID_SIZE])?;
        let encrypted_body = cipher
            .encrypt(Nonce::from_slice(&separate_header[4..]), body)
            .map_err(|error| {
                Error::new(
                    "outbound-crypto",
                    format!("Shadowsocks 2022 UDP encrypt failed: {error:?}"),
                )
            })?;
        Ok([encrypted_header.as_slice(), encrypted_body.as_slice()].concat())
    }
}

fn decode_server_packet(
    client_session_id: &[u8; SESSION_ID_SIZE],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    if plaintext.len() < 1 + 8 + SESSION_ID_SIZE + 2 {
        return Err(address::packet_error(
            "truncated Shadowsocks 2022 UDP header",
        ));
    }
    if plaintext[0] != HEADER_TYPE_SERVER_PACKET {
        return Err(address::packet_error(
            "unsupported Shadowsocks 2022 UDP packet type",
        ));
    }
    validate_timestamp(
        u64::from_be_bytes(plaintext[1..9].try_into().expect("timestamp slice")),
        "UDP packet",
    )?;
    let session_start = 1 + 8;
    let session_end = session_start + SESSION_ID_SIZE;
    if &plaintext[session_start..session_end] != client_session_id {
        return Err(address::packet_error(
            "unexpected Shadowsocks 2022 client session ID",
        ));
    }
    let padding_start = session_end + 2;
    let padding_len = u16::from_be_bytes([plaintext[session_end], plaintext[session_end + 1]]);
    let address_start = padding_start + usize::from(padding_len);
    if plaintext.len() < address_start {
        return Err(address::packet_error(
            "truncated Shadowsocks 2022 UDP padding",
        ));
    }
    let payload_offset =
        address_start + address::socks_payload_offset(&plaintext[address_start..])?;
    Ok(plaintext[payload_offset..].to_vec())
}

fn decrypt_udp_body(
    key: &[u8; KEY_SIZE],
    separate_header: &[u8; SEPARATE_HEADER_SIZE],
    encrypted_body: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = session_cipher(key, &separate_header[..SESSION_ID_SIZE])?;
    cipher
        .decrypt(Nonce::from_slice(&separate_header[4..]), encrypted_body)
        .map_err(|error| {
            Error::new(
                "outbound-crypto",
                format!("Shadowsocks 2022 UDP decrypt failed: {error:?}"),
            )
        })
}
