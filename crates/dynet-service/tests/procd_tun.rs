use std::os::fd::AsRawFd;

use dynet_service::preopen_tun;
use tempfile::NamedTempFile;

#[test]
fn preopen_survives_exec() {
    let device = NamedTempFile::new().expect("temporary TUN stand-in");
    let inherited = preopen_tun(device.path()).expect("open inheritable descriptor");
    let flags = unsafe {
        // SAFETY: F_GETFD only reads flags from the valid test descriptor.
        libc::fcntl(inherited.as_raw_fd(), libc::F_GETFD)
    };

    assert!(flags >= 0);
    assert_eq!(flags & libc::FD_CLOEXEC, 0);
}
