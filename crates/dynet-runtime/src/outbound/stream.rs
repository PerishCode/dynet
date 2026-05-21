use std::{
    io::{Read, Write},
    time::Duration,
};

use super::ProxiedTcpStream;

impl ProxiedTcpStream {
    #[allow(dead_code)]
    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        match self {
            Self::Direct(stream) => stream.set_read_timeout(timeout),
            Self::Shadowsocks(stream) => stream.set_read_timeout(timeout),
            Self::Trojan(stream) => stream.set_read_timeout(timeout),
            Self::Vmess(stream) => stream.set_read_timeout(timeout),
        }
    }
}

impl Read for ProxiedTcpStream {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Direct(stream) => stream.read(output),
            Self::Shadowsocks(stream) => stream.read(output),
            Self::Trojan(stream) => stream.read(output),
            Self::Vmess(stream) => stream.read(output),
        }
    }
}

impl Write for ProxiedTcpStream {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Direct(stream) => stream.write(input),
            Self::Shadowsocks(stream) => stream.write(input),
            Self::Trojan(stream) => stream.write(input),
            Self::Vmess(stream) => stream.write(input),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Direct(stream) => stream.flush(),
            Self::Shadowsocks(stream) => stream.flush(),
            Self::Trojan(stream) => stream.flush(),
            Self::Vmess(stream) => stream.flush(),
        }
    }
}
