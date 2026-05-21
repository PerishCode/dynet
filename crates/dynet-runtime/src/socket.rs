use std::os::fd::AsRawFd;

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
pub(crate) fn set_socket_mark<T: AsRawFd>(_socket: &T, _mark: u32) -> Result<(), String> {
    Ok(())
}
