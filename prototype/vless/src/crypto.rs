use std::io::{self, Read, Write};

use crate::reality::{feed_reality_client_connection, RealityClientConnection};

#[derive(Debug, Clone, Copy)]
pub(crate) struct CryptoIoState {
    plaintext_bytes_to_read: usize,
}

impl CryptoIoState {
    fn new(plaintext_bytes_to_read: usize) -> Self {
        Self {
            plaintext_bytes_to_read,
        }
    }

    pub(crate) fn plaintext_bytes_to_read(&self) -> usize {
        self.plaintext_bytes_to_read
    }
}

pub(crate) enum CryptoConnection {
    RealityClient(RealityClientConnection),
}

impl CryptoConnection {
    pub(crate) fn new_reality_client(conn: RealityClientConnection) -> Self {
        Self::RealityClient(conn)
    }

    pub(crate) fn is_client(&self) -> bool {
        matches!(self, Self::RealityClient(_))
    }

    pub(crate) fn read_tls(&mut self, reader: &mut dyn Read) -> io::Result<usize> {
        match self {
            Self::RealityClient(conn) => conn.read_tls(reader),
        }
    }

    pub(crate) fn process_new_packets(&mut self) -> io::Result<CryptoIoState> {
        match self {
            Self::RealityClient(conn) => conn
                .process_new_packets()
                .map(|state| CryptoIoState::new(state.plaintext_bytes_to_read())),
        }
    }

    pub(crate) fn reader(&mut self) -> crate::reality::RealityReader<'_> {
        match self {
            Self::RealityClient(conn) => conn.reader(),
        }
    }

    pub(crate) fn writer(&mut self) -> crate::reality::RealityWriter<'_> {
        match self {
            Self::RealityClient(conn) => conn.writer(),
        }
    }

    pub(crate) fn write_tls(&mut self, writer: &mut dyn Write) -> io::Result<usize> {
        match self {
            Self::RealityClient(conn) => conn.write_tls(writer),
        }
    }

    pub(crate) fn wants_write(&self) -> bool {
        match self {
            Self::RealityClient(conn) => conn.wants_write(),
        }
    }
}

pub(crate) fn feed_crypto_connection(
    connection: &mut CryptoConnection,
    data: &[u8],
) -> io::Result<()> {
    match connection {
        CryptoConnection::RealityClient(conn) => feed_reality_client_connection(conn, data),
    }
}
