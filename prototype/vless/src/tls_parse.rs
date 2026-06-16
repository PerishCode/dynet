use std::io;

use crate::buf_reader::BufReader;

const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
const TLS_HEADER_LEN: usize = 5;
const TLS_EXT_SUPPORTED_VERSIONS: u16 = 43;
const RETRY_REQUEST_RANDOM_BYTES: &[u8] = &[
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

pub(crate) struct ParsedServerHello {
    pub(crate) cipher_suite: u16,
    pub(crate) is_tls13: bool,
}

pub(crate) fn parse_server_hello(server_hello_frame: &[u8]) -> io::Result<ParsedServerHello> {
    if server_hello_frame.len() < 47 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ServerHello frame too short",
        ));
    }
    if server_hello_frame[0] != CONTENT_TYPE_HANDSHAKE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected handshake content type",
        ));
    }
    if server_hello_frame[1] != 3 || server_hello_frame[2] != 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected ServerHello record TLS version",
        ));
    }

    let mut reader = BufReader::new(&server_hello_frame[TLS_HEADER_LEN..]);
    if reader.read_u8()? != HANDSHAKE_TYPE_SERVER_HELLO {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected ServerHello handshake type",
        ));
    }
    let message_len = reader.read_u24_be()? as usize;
    if reader.remaining() < message_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ServerHello message length exceeds frame",
        ));
    }
    if reader.read_u8()? != 3 || reader.read_u8()? != 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected ServerHello legacy TLS version 3.3",
        ));
    }
    let server_random = reader.read_slice(32)?;
    if server_random == RETRY_REQUEST_RANDOM_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "server sent HelloRetryRequest",
        ));
    }
    let session_id_len = reader.read_u8()?;
    if session_id_len > 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ServerHello session id length",
        ));
    }
    reader.skip(session_id_len as usize)?;
    let cipher_suite = reader.read_u16_be()?;
    reader.skip(1)?;

    let mut is_tls13 = false;
    if !reader.is_consumed() {
        let extensions_len = reader.read_u16_be()? as usize;
        if reader.remaining() < extensions_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "extensions length exceeds ServerHello",
            ));
        }
        let mut extensions = BufReader::new(reader.read_slice(extensions_len)?);
        while !extensions.is_consumed() {
            let ext_type = extensions.read_u16_be()?;
            let ext_len = extensions.read_u16_be()?;
            if ext_type == TLS_EXT_SUPPORTED_VERSIONS {
                if ext_len != 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid supported_versions length",
                    ));
                }
                let version = extensions.read_slice(2)?;
                is_tls13 = version == [0x03, 0x04];
            } else {
                extensions.skip(ext_len as usize)?;
            }
        }
    }

    Ok(ParsedServerHello {
        cipher_suite,
        is_tls13,
    })
}
