use std::{
    io::{self, Read, Write},
    time::Duration,
};

use crate::outbound;

pub(crate) trait VmessTransport: Read + Write + Send {
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
