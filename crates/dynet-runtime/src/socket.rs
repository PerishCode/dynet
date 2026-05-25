#[cfg(target_os = "linux")]
use std::{
    io,
    net::{SocketAddr, TcpStream},
    os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd},
    time::Duration,
};

#[cfg(target_os = "linux")]
const MAX_INTERFACE_NAME_LEN: usize = libc::IFNAMSIZ - 1;

#[cfg(target_os = "linux")]
pub(crate) fn set_socket_mark<T: AsRawFd>(socket: &T, mark: u32) -> Result<(), String> {
    if mark == 0 {
        return Ok(());
    }
    let value = mark as libc::c_int;
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "failed to set SO_MARK {mark:#x}: {}",
            std::io::Error::last_os_error()
        ))
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn set_socket_mark<T>(_socket: &T, _mark: u32) -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn connect_bound_tcp(
    address: &SocketAddr,
    mark: u32,
    interface_name: &str,
    timeout: Duration,
) -> Result<TcpStream, String> {
    connect_marked_tcp_inner(address, mark, Some(interface_name), timeout)
}

#[cfg(target_os = "linux")]
pub(crate) fn connect_marked_tcp(
    address: &SocketAddr,
    mark: u32,
    timeout: Duration,
) -> Result<TcpStream, String> {
    connect_marked_tcp_inner(address, mark, None, timeout)
}

#[cfg(target_os = "linux")]
fn connect_marked_tcp_inner(
    address: &SocketAddr,
    mark: u32,
    interface_name: Option<&str>,
    timeout: Duration,
) -> Result<TcpStream, String> {
    let fd = unsafe {
        libc::socket(
            socket_domain(address),
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            libc::IPPROTO_TCP,
        )
    };
    if fd < 0 {
        return Err(format!(
            "failed to create TCP socket: {}",
            io::Error::last_os_error()
        ));
    }
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    set_socket_mark(&socket, mark)?;
    if let Some(interface_name) = interface_name {
        bind_socket_to_device(&socket, interface_name)?;
    }
    set_nonblocking(socket.as_raw_fd(), true)?;
    connect_nonblocking(socket.as_raw_fd(), address, timeout)?;
    set_nonblocking(socket.as_raw_fd(), false)?;
    let stream = unsafe { TcpStream::from_raw_fd(socket.into_raw_fd()) };
    Ok(stream)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn connect_bound_tcp(
    _address: &std::net::SocketAddr,
    _mark: u32,
    interface_name: &str,
    _timeout: std::time::Duration,
) -> Result<std::net::TcpStream, String> {
    let _ = validated_interface_name(interface_name)?;
    Err("outbound interface binding requires Linux SO_BINDTODEVICE".to_string())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn connect_marked_tcp(
    address: &std::net::SocketAddr,
    _mark: u32,
    timeout: std::time::Duration,
) -> Result<std::net::TcpStream, String> {
    std::net::TcpStream::connect_timeout(address, timeout)
        .map_err(|error| format!("failed to connect TCP socket to {address}: {error}"))
}

fn validated_interface_name(interface_name: &str) -> Result<&str, String> {
    let value = interface_name.trim();
    if value.is_empty() {
        return Err("outbound interface name must not be empty".to_string());
    }
    if value.as_bytes().contains(&0) {
        return Err("outbound interface name must not contain NUL bytes".to_string());
    }
    #[cfg(target_os = "linux")]
    if value.len() > MAX_INTERFACE_NAME_LEN {
        return Err(format!(
            "outbound interface name is too long: {} > {} bytes",
            value.len(),
            MAX_INTERFACE_NAME_LEN
        ));
    }
    Ok(value)
}

#[cfg(target_os = "linux")]
fn bind_socket_to_device<T: AsRawFd>(socket: &T, interface_name: &str) -> Result<(), String> {
    let interface_name = validated_interface_name(interface_name)?;
    let mut bytes = Vec::with_capacity(interface_name.len() + 1);
    bytes.extend_from_slice(interface_name.as_bytes());
    bytes.push(0);
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            bytes.as_ptr().cast(),
            bytes.len() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "failed to bind socket to outbound interface length {}: {}",
            interface_name.len(),
            io::Error::last_os_error()
        ))
    }
}

#[cfg(target_os = "linux")]
fn socket_domain(address: &SocketAddr) -> libc::c_int {
    match address {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    }
}

#[cfg(target_os = "linux")]
fn set_nonblocking(fd: libc::c_int, enabled: bool) -> Result<(), String> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(format!(
            "failed to read TCP socket flags: {}",
            io::Error::last_os_error()
        ));
    }
    let next = if enabled {
        flags | libc::O_NONBLOCK
    } else {
        flags & !libc::O_NONBLOCK
    };
    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, next) };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "failed to update TCP socket flags: {}",
            io::Error::last_os_error()
        ))
    }
}

#[cfg(target_os = "linux")]
fn connect_nonblocking(
    fd: libc::c_int,
    address: &SocketAddr,
    timeout: Duration,
) -> Result<(), String> {
    let result = unsafe { connect_socket_address(fd, address) };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if !matches!(
        error.raw_os_error(),
        Some(libc::EINPROGRESS) | Some(libc::EWOULDBLOCK)
    ) {
        return Err(format!("failed to start TCP connect to {address}: {error}"));
    }
    wait_connect(fd, address, timeout)
}

#[cfg(target_os = "linux")]
unsafe fn connect_socket_address(fd: libc::c_int, address: &SocketAddr) -> libc::c_int {
    match address {
        SocketAddr::V4(address) => {
            let mut raw: libc::sockaddr_in = std::mem::zeroed();
            raw.sin_family = libc::AF_INET as libc::sa_family_t;
            raw.sin_port = address.port().to_be();
            raw.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(address.ip().octets()),
            };
            libc::connect(
                fd,
                (&raw as *const libc::sockaddr_in).cast(),
                std::mem::size_of_val(&raw) as libc::socklen_t,
            )
        }
        SocketAddr::V6(address) => {
            let mut raw: libc::sockaddr_in6 = std::mem::zeroed();
            raw.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            raw.sin6_port = address.port().to_be();
            raw.sin6_flowinfo = address.flowinfo();
            raw.sin6_addr = libc::in6_addr {
                s6_addr: address.ip().octets(),
            };
            raw.sin6_scope_id = address.scope_id();
            libc::connect(
                fd,
                (&raw as *const libc::sockaddr_in6).cast(),
                std::mem::size_of_val(&raw) as libc::socklen_t,
            )
        }
    }
}

#[cfg(target_os = "linux")]
fn wait_connect(fd: libc::c_int, address: &SocketAddr, timeout: Duration) -> Result<(), String> {
    let mut poll_fd = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    loop {
        let result = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
        if result > 0 {
            break;
        }
        if result == 0 {
            return Err(format!("timed out connecting TCP socket to {address}"));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(format!("failed to poll TCP connect to {address}: {error}"));
        }
    }
    let mut socket_error: libc::c_int = 0;
    let mut socket_error_len = std::mem::size_of_val(&socket_error) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut socket_error as *mut libc::c_int).cast(),
            &mut socket_error_len,
        )
    };
    if result != 0 {
        return Err(format!(
            "failed to read TCP connect status for {address}: {}",
            io::Error::last_os_error()
        ));
    }
    if socket_error == 0 {
        Ok(())
    } else {
        Err(format!(
            "failed to connect TCP socket to {address}: {}",
            io::Error::from_raw_os_error(socket_error)
        ))
    }
}
