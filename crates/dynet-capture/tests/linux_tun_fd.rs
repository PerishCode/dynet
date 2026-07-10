use std::{ffi::OsStr, fs::File, io, os::fd::FromRawFd};

use dynet_capture::validate_inherited_fd;

#[test]
fn inherited_fd_validates() {
    let source = tempfile::tempfile().expect("temporary file");
    let fd = std::os::fd::IntoRawFd::into_raw_fd(source);

    let validated = validate_inherited_fd(OsStr::new(&fd.to_string())).expect("valid descriptor");

    assert_eq!(validated, fd);
    let _owned = unsafe {
        // SAFETY: the temporary file transferred this valid descriptor to the test.
        File::from_raw_fd(fd)
    };
}

#[test]
fn invalid_fd_is_rejected() {
    let error =
        validate_inherited_fd(OsStr::new("not-a-fd")).expect_err("invalid descriptor rejected");

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}
