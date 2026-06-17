use std::io::{self, BufRead, Write};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::reality::{feed_reality_client_connection, RealityClientConnection};
use crate::sync_adapter::{SyncReadAdapter, SyncWriteAdapter};

const HANDSHAKE_BUFFER_SIZE: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum StreamState {
    Stream,
    ReadShutdown,
    WriteShutdown,
    FullyShutdown,
}

impl StreamState {
    fn readable(self) -> bool {
        !matches!(self, Self::ReadShutdown | Self::FullyShutdown)
    }

    fn writeable(self) -> bool {
        !matches!(self, Self::WriteShutdown | Self::FullyShutdown)
    }

    fn shutdown_read(&mut self) {
        *self = match *self {
            Self::WriteShutdown | Self::FullyShutdown => Self::FullyShutdown,
            _ => Self::ReadShutdown,
        };
    }

    fn shutdown_write(&mut self) {
        *self = match *self {
            Self::ReadShutdown | Self::FullyShutdown => Self::FullyShutdown,
            _ => Self::WriteShutdown,
        };
    }
}

pub(crate) struct RealityStream<IO = tokio::net::TcpStream> {
    io: IO,
    session: RealityClientConnection,
    state: StreamState,
    need_flush: bool,
}

impl<IO> std::fmt::Debug for RealityStream<IO> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RealityStream")
            .field("state", &self.state)
            .field("need_flush", &self.need_flush)
            .finish_non_exhaustive()
    }
}

impl<IO> RealityStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) fn new(io: IO, session: RealityClientConnection) -> Self {
        debug_assert!(!session.is_handshaking());
        Self {
            io,
            session,
            state: StreamState::Stream,
            need_flush: false,
        }
    }

    pub(crate) fn into_inner(self) -> (IO, RealityClientConnection) {
        (self.io, self.session)
    }

    fn write_tls_direct(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut adapter = SyncWriteAdapter {
            io: &mut self.io,
            cx,
        };
        match self.session.write_tls(&mut adapter) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn drain_all_writes(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.session.wants_write() {
            match self.write_tls_direct(cx) {
                Poll::Ready(Ok(0)) => break,
                Poll::Ready(Ok(_)) => self.need_flush = true,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_more_ciphertext(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut adapter = SyncReadAdapter {
            io: &mut self.io,
            cx,
        };
        match self.session.read_tls(&mut adapter) {
            Ok(0) => {
                self.state.shutdown_read();
                Poll::Ready(Ok(()))
            }
            Ok(_) => {
                let _ = self.session.process_new_packets();
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

pub(crate) async fn perform_reality_handshake(
    session: &mut RealityClientConnection,
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
) -> io::Result<()> {
    let mut read_buffer = vec![0_u8; HANDSHAKE_BUFFER_SIZE];
    let mut iteration = 0_u16;
    let mut eof = false;

    loop {
        iteration += 1;
        if iteration > 100 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "REALITY handshake exceeded maximum iterations",
            ));
        }

        let until_handshaked = session.is_handshaking();
        while session.wants_write() {
            let mut write_buffer = Vec::new();
            session.write_tls(&mut write_buffer)?;
            if !write_buffer.is_empty() {
                stream.write_all(&write_buffer).await?;
            }
        }
        stream.flush().await?;

        if !eof && session.is_handshaking() && session.wants_read() {
            let read = stream.read(&mut read_buffer).await?;
            if read == 0 {
                eof = true;
            } else {
                feed_reality_client_connection(session, &read_buffer[..read])?;
                session.process_new_packets()?;
            }
        }

        if until_handshaked && !session.is_handshaking() && session.wants_write() {
            continue;
        }

        match (eof, session.is_handshaking()) {
            (true, true) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF during REALITY handshake",
                ));
            }
            (_, false) => break,
            (_, true) => continue,
        }
    }

    stream.flush().await
}

impl<IO> AsyncRead for RealityStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.state.readable() {
            return Poll::Ready(Ok(()));
        }

        let mut io_pending = false;
        let mut eof = false;

        while this.state.readable() && this.session.wants_read() {
            let mut adapter = SyncReadAdapter {
                io: &mut this.io,
                cx,
            };
            match this.session.read_tls(&mut adapter) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(_) => {
                    if let Err(error) = this.session.process_new_packets() {
                        let _ = this.drain_all_writes(cx);
                        return Poll::Ready(Err(error));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    io_pending = true;
                    break;
                }
                Err(error) => return Poll::Ready(Err(error)),
            }
        }

        let mut reader = this.session.reader();
        match reader.fill_buf() {
            Ok(available) if !available.is_empty() => {
                let len = buf.remaining().min(available.len());
                buf.put_slice(&available[..len]);
                reader.consume(len);
                Poll::Ready(Ok(()))
            }
            Ok(_) => {
                this.state.shutdown_read();
                Poll::Ready(Ok(()))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if eof {
                    this.state.shutdown_read();
                    Poll::Ready(Ok(()))
                } else if io_pending {
                    Poll::Pending
                } else {
                    this.poll_more_ciphertext(cx)
                }
            }
            Err(error) if error.kind() == io::ErrorKind::ConnectionAborted => {
                this.state.shutdown_read();
                Poll::Ready(Err(error))
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl<IO> AsyncWrite for RealityStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.state.writeable() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "write side is shut down",
            )));
        }

        let mut position = 0;
        while position < buf.len() {
            let mut would_block = false;
            match self.session.writer().write(&buf[position..]) {
                Ok(written) => position += written,
                Err(error) => return Poll::Ready(Err(error)),
            }

            while self.session.wants_write() {
                match self.write_tls_direct(cx) {
                    Poll::Ready(Ok(0)) | Poll::Pending => {
                        would_block = true;
                        self.need_flush = true;
                        break;
                    }
                    Poll::Ready(Ok(_)) => self.need_flush = true,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                }
            }

            return match (position, would_block) {
                (0, true) => Poll::Pending,
                (_, true) => Poll::Ready(Ok(position)),
                (_, false) => continue,
            };
        }

        Poll::Ready(Ok(position))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.session.writer().flush()?;

        while self.session.wants_write() {
            match self.write_tls_direct(cx) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(_)) => self.need_flush = true,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if self.need_flush {
            match Pin::new(&mut self.io).poll_flush(cx) {
                Poll::Ready(Ok(())) => {
                    self.need_flush = false;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.session.wants_write() {
            match self.write_tls_direct(cx) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if self.state.writeable() {
            self.session.send_close_notify();
            self.state.shutdown_write();
        }

        while self.session.wants_write() {
            match self.write_tls_direct(cx) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }

        match Pin::new(&mut self.io).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::NotConnected => {
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}
