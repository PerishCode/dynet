use std::{
    fs::File,
    future::Future,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
    time::Duration,
};

use ipstack::{IpStack, IpStackConfig, IpStackStream, IpStackTcpStream, IpStackUdpStream};
use tokio::{
    io::{unix::AsyncFd, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpStream, UdpSocket},
    time,
};

use crate::LinuxTun;

const TCP_RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IpStackPocOptions {
    pub interface: String,
    pub max_tcp: usize,
    pub max_udp: usize,
    pub idle_timeout: Duration,
    pub udp_response_timeout: Duration,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct IpStackPocReport {
    pub tcp_seen: usize,
    pub tcp_succeeded: usize,
    pub udp_seen: usize,
    pub udp_succeeded: usize,
    pub unknown_seen: usize,
}

pub type IpStackCaptureFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;
pub type IpStackTcpCaptureHandler =
    Arc<dyn Fn(IpStackTcpStream) -> IpStackCaptureFuture + Send + Sync>;
pub type IpStackUdpCaptureHandler =
    Arc<dyn Fn(IpStackUdpStream) -> IpStackCaptureFuture + Send + Sync>;

impl Default for IpStackPocOptions {
    fn default() -> Self {
        Self {
            interface: "dynet0".to_string(),
            max_tcp: 1,
            max_udp: 0,
            idle_timeout: Duration::from_secs(15),
            udp_response_timeout: Duration::from_millis(1500),
        }
    }
}

impl IpStackPocOptions {
    pub fn validate(&self) -> Result<(), String> {
        if self.interface.is_empty() {
            return Err("ipstack-poc requires a non-empty interface".to_string());
        }
        if self.max_tcp == 0 && self.max_udp == 0 {
            return Err("ipstack-poc requires at least one of --max-tcp or --max-udp".to_string());
        }
        Ok(())
    }
}

pub async fn run_capture_forever(
    label: &'static str,
    interface: String,
    handle_tcp: IpStackTcpCaptureHandler,
    handle_udp: IpStackUdpCaptureHandler,
) -> Result<(), String> {
    if interface.is_empty() {
        return Err("ipstack capture requires a non-empty interface".to_string());
    }
    let tun = LinuxTun::open(&interface)
        .map_err(|error| format!("failed opening TUN {interface}: {error}"))?;
    tun.set_nonblocking(true)
        .map_err(|error| format!("failed setting TUN nonblocking: {error}"))?;
    let device = AsyncTun::new(tun.into_file())?;
    let mut ipstack_config = IpStackConfig::default();
    ipstack_config.mtu_unchecked(1500);
    ipstack_config.packet_information(false);
    let mut stack = IpStack::new(ipstack_config, device);
    println!("{label}: opened {interface} mode=forever");

    loop {
        let accept = stack
            .accept()
            .await
            .map_err(|error| format!("ipstack accept failed: {error}"))?;
        match accept {
            IpStackStream::Tcp(tcp) => {
                let local = tcp.local_addr();
                let peer = tcp.peer_addr();
                let handle_tcp = Arc::clone(&handle_tcp);
                tokio::spawn(async move {
                    if let Err(error) = handle_tcp(tcp).await {
                        eprintln!("{label}: tcp task failed local={local} peer={peer}: {error}");
                    }
                });
            }
            IpStackStream::Udp(udp) => {
                let local = udp.local_addr();
                let peer = udp.peer_addr();
                let handle_udp = Arc::clone(&handle_udp);
                tokio::spawn(async move {
                    if let Err(error) = handle_udp(udp).await {
                        eprintln!("{label}: udp task failed local={local} peer={peer}: {error}");
                    }
                });
            }
            IpStackStream::UnknownTransport(unknown) => {
                println!(
                    "{label}: ignored unknown transport protocol={:?} src={} dst={}",
                    unknown.ip_protocol(),
                    unknown.src_addr(),
                    unknown.dst_addr()
                );
            }
            IpStackStream::UnknownNetwork(packet) => {
                println!("{label}: ignored unknown network bytes={}", packet.len());
            }
        }
    }
}

pub async fn run_ipstack_poc(options: IpStackPocOptions) -> Result<IpStackPocReport, String> {
    run_capture_once("ipstack-poc", options.clone(), handle_tcp, move |udp| {
        handle_udp(udp, options.udp_response_timeout)
    })
    .await
}

pub async fn run_capture_once<TcpHandler, TcpFuture, UdpHandler, UdpFuture>(
    label: &'static str,
    options: IpStackPocOptions,
    mut handle_tcp: TcpHandler,
    mut handle_udp: UdpHandler,
) -> Result<IpStackPocReport, String>
where
    TcpHandler: FnMut(IpStackTcpStream) -> TcpFuture,
    TcpFuture: Future<Output = Result<bool, String>>,
    UdpHandler: FnMut(IpStackUdpStream) -> UdpFuture,
    UdpFuture: Future<Output = Result<bool, String>>,
{
    options.validate()?;
    let tun = LinuxTun::open(&options.interface)
        .map_err(|error| format!("failed opening TUN {}: {error}", options.interface))?;
    tun.set_nonblocking(true)
        .map_err(|error| format!("failed setting TUN nonblocking: {error}"))?;
    let device = AsyncTun::new(tun.into_file())?;
    let mut ipstack_config = IpStackConfig::default();
    ipstack_config.mtu_unchecked(1500);
    ipstack_config.packet_information(false);
    let mut stack = IpStack::new(ipstack_config, device);
    let mut report = IpStackPocReport::default();
    println!(
        "{label}: opened {} max_tcp={} max_udp={} idle_ms={}",
        options.interface,
        options.max_tcp,
        options.max_udp,
        options.idle_timeout.as_millis()
    );

    while !done(&options, &report) {
        let accept = time::timeout(options.idle_timeout, stack.accept())
            .await
            .map_err(|_| {
                format!(
                    "{label} timed out after {}ms waiting for streams",
                    options.idle_timeout.as_millis()
                )
            })?
            .map_err(|error| format!("ipstack accept failed: {error}"))?;
        match accept {
            IpStackStream::Tcp(tcp) => {
                report.tcp_seen += 1;
                if options.max_tcp == 0 || report.tcp_seen > options.max_tcp {
                    println!(
                        "{label}: ignored tcp local={} peer={}",
                        tcp.local_addr(),
                        tcp.peer_addr()
                    );
                    continue;
                }
                if handle_tcp(tcp).await? {
                    report.tcp_succeeded += 1;
                }
            }
            IpStackStream::Udp(udp) => {
                report.udp_seen += 1;
                if options.max_udp == 0 || report.udp_seen > options.max_udp {
                    println!(
                        "{label}: ignored udp local={} peer={}",
                        udp.local_addr(),
                        udp.peer_addr()
                    );
                    continue;
                }
                if handle_udp(udp).await? {
                    report.udp_succeeded += 1;
                }
            }
            IpStackStream::UnknownTransport(unknown) => {
                report.unknown_seen += 1;
                println!(
                    "{label}: ignored unknown transport protocol={:?} src={} dst={}",
                    unknown.ip_protocol(),
                    unknown.src_addr(),
                    unknown.dst_addr()
                );
            }
            IpStackStream::UnknownNetwork(packet) => {
                report.unknown_seen += 1;
                println!("{label}: ignored unknown network bytes={}", packet.len());
            }
        }
    }

    println!(
        "{label}: done tcp={}/{} udp={}/{} unknown={}",
        report.tcp_succeeded,
        report.tcp_seen,
        report.udp_succeeded,
        report.udp_seen,
        report.unknown_seen
    );
    Ok(report)
}

fn done(options: &IpStackPocOptions, report: &IpStackPocReport) -> bool {
    (options.max_tcp == 0 || report.tcp_seen >= options.max_tcp)
        && (options.max_udp == 0 || report.udp_seen >= options.max_udp)
}

async fn handle_tcp(mut downstream: IpStackTcpStream) -> Result<bool, String> {
    let local = downstream.local_addr();
    let target = downstream.peer_addr();
    if !target.ip().is_ipv4() {
        println!("ipstack-poc: skipped tcp local={local} peer={target} reason=non-ipv4");
        return Ok(false);
    }
    println!("ipstack-poc: accepted tcp local={local} peer={target}");
    let mut upstream = TcpStream::connect(target)
        .await
        .map_err(|error| format!("failed connecting TCP upstream {target}: {error}"))?;
    let upstream_addr = upstream
        .peer_addr()
        .map_err(|error| format!("failed reading TCP upstream address: {error}"))?;
    println!(
        "ipstack-poc: upstream-connected local={local} peer={target} upstream={upstream_addr}"
    );
    let (client_to_upstream, upstream_to_client, closed) =
        relay_tcp_until_idle(&mut downstream, &mut upstream, TCP_RELAY_IDLE_TIMEOUT).await?;
    println!(
        "ipstack-poc: tcp-close local={local} peer={target} upstream={upstream_addr} client_to_upstream={client_to_upstream} upstream_to_client={upstream_to_client} closed={closed}"
    );
    Ok(client_to_upstream > 0 && upstream_to_client > 0)
}

async fn relay_tcp_until_idle(
    downstream: &mut IpStackTcpStream,
    upstream: &mut TcpStream,
    idle_timeout: Duration,
) -> Result<(u64, u64, bool), String> {
    let (mut downstream_reader, mut downstream_writer) = tokio::io::split(downstream);
    let (mut upstream_reader, mut upstream_writer) = tokio::io::split(upstream);
    let mut downstream_buffer = [0_u8; 16 * 1024];
    let mut upstream_buffer = [0_u8; 16 * 1024];
    let mut client_to_upstream = 0_u64;
    let mut upstream_to_client = 0_u64;
    let mut client_closed = false;
    let mut upstream_closed = false;

    loop {
        if client_closed && upstream_closed {
            return Ok((client_to_upstream, upstream_to_client, true));
        }
        if upstream_closed && upstream_to_client > 0 {
            return Ok((client_to_upstream, upstream_to_client, true));
        }

        let idle = time::sleep(idle_timeout);
        tokio::pin!(idle);
        tokio::select! {
            read = downstream_reader.read(&mut downstream_buffer), if !client_closed => {
                let len = read.map_err(|error| format!("failed reading TCP downstream: {error}"))?;
                if len == 0 {
                    client_closed = true;
                    upstream_writer.shutdown().await.map_err(|error| {
                        format!("failed shutting down TCP upstream writer: {error}")
                    })?;
                } else {
                    upstream_writer.write_all(&downstream_buffer[..len]).await.map_err(|error| {
                        format!("failed writing TCP upstream: {error}")
                    })?;
                    client_to_upstream += len as u64;
                }
            }
            read = upstream_reader.read(&mut upstream_buffer), if !upstream_closed => {
                let len = read.map_err(|error| format!("failed reading TCP upstream: {error}"))?;
                if len == 0 {
                    upstream_closed = true;
                } else {
                    downstream_writer.write_all(&upstream_buffer[..len]).await.map_err(|error| {
                        format!("failed writing TCP downstream: {error}")
                    })?;
                    upstream_to_client += len as u64;
                }
            }
            _ = &mut idle => {
                return Ok((client_to_upstream, upstream_to_client, false));
            }
        }
    }
}

async fn handle_udp(
    mut downstream: IpStackUdpStream,
    response_timeout: Duration,
) -> Result<bool, String> {
    let local = downstream.local_addr();
    let target = downstream.peer_addr();
    if !target.ip().is_ipv4() {
        println!("ipstack-poc: skipped udp local={local} peer={target} reason=non-ipv4");
        return Ok(false);
    }
    let mut payload = vec![0_u8; 65_535];
    let len = downstream
        .read(&mut payload)
        .await
        .map_err(|error| format!("failed reading UDP payload for {target}: {error}"))?;
    payload.truncate(len);
    println!(
        "ipstack-poc: accepted udp local={local} peer={target} payload_bytes={}",
        payload.len()
    );
    let bind = match target.ip() {
        IpAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        IpAddr::V6(_) => unreachable!("non-ipv4 target returned earlier"),
    };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|error| format!("failed binding UDP socket: {error}"))?;
    socket
        .connect(target)
        .await
        .map_err(|error| format!("failed connecting UDP upstream {target}: {error}"))?;
    socket
        .send(&payload)
        .await
        .map_err(|error| format!("failed sending UDP upstream {target}: {error}"))?;
    let mut response = vec![0_u8; 65_535];
    match time::timeout(response_timeout, socket.recv(&mut response)).await {
        Ok(Ok(size)) => {
            response.truncate(size);
            downstream
                .write_all(&response)
                .await
                .map_err(|error| format!("failed writing UDP response for {target}: {error}"))?;
            println!("ipstack-poc: udp-response local={local} peer={target} bytes={size}");
            Ok(true)
        }
        Ok(Err(error)) => Err(format!(
            "failed receiving UDP response for {target}: {error}"
        )),
        Err(_) => {
            println!(
                "ipstack-poc: udp-timeout local={local} peer={target} timeout_ms={}",
                response_timeout.as_millis()
            );
            Ok(false)
        }
    }
}

struct AsyncTun {
    inner: AsyncFd<File>,
}

impl AsyncTun {
    fn new(file: File) -> Result<Self, String> {
        AsyncFd::new(file)
            .map(|inner| Self { inner })
            .map_err(|error| format!("failed creating async TUN fd: {error}"))
    }
}

impl AsyncRead for AsyncTun {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.inner.poll_read_ready_mut(cx))?;
            let result = guard.try_io(|inner| {
                let file = inner.get_mut();
                let target = buf.initialize_unfilled();
                match file.read(target) {
                    Ok(size) => {
                        buf.advance(size);
                        Ok(())
                    }
                    Err(error) => Err(error),
                }
            });
            match result {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for AsyncTun {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.inner.poll_write_ready_mut(cx))?;
            let result = guard.try_io(|inner| inner.get_mut().write(input));
            match result {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
