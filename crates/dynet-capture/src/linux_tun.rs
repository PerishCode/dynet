use std::{
    env,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    mem,
    os::fd::{AsRawFd, FromRawFd, RawFd},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

const DEFAULT_TUN_DEVICE: &str = "/dev/net/tun";
const DEFAULT_TUN_INTERFACE: &str = "dynet0";
const INHERITED_TUN_FD_ENV: &str = "DYNET_INHERITED_TUN_FD";

#[derive(Debug)]
pub struct LinuxTun {
    file: File,
    interface: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TunOpenReport {
    pub device: PathBuf,
    pub interface: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TunProbeReport {
    pub open: TunOpenReport,
    pub nonblocking_read: TunProbeRead,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TunProbeRead {
    WouldBlock,
    Packet(usize),
    Eof,
}

#[repr(C)]
struct TunIfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    flags: libc::c_short,
    padding: [u8; 24],
}

impl LinuxTun {
    pub fn open(interface: &str) -> io::Result<Self> {
        let file = match inherited_tun_file(env::var_os(INHERITED_TUN_FD_ENV))? {
            Some(file) => file,
            None => open_device(Path::new(DEFAULT_TUN_DEVICE))?,
        };
        Self::from_file(file, interface)
    }

    pub fn open_default() -> io::Result<Self> {
        Self::open(DEFAULT_TUN_INTERFACE)
    }

    pub fn open_with_device(device: impl AsRef<Path>, interface: &str) -> io::Result<Self> {
        let file = open_device(device.as_ref())?;
        Self::from_file(file, interface)
    }

    fn from_file(file: File, interface: &str) -> io::Result<Self> {
        bind_tun_interface(&file, interface)?;
        Ok(Self {
            file,
            interface: interface.to_string(),
        })
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }

    pub fn read_packet(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }

    pub fn write_packet(&mut self, packet: &[u8]) -> io::Result<usize> {
        self.file.write(packet)
    }

    pub fn into_file(self) -> File {
        self.file
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let flags = fcntl_getfl(&self.file)?;
        let next_flags = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        fcntl_setfl(&self.file, next_flags)
    }
}

fn open_device(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).write(true).open(path)
}

fn inherited_tun_file(value: Option<std::ffi::OsString>) -> io::Result<Option<File>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let fd = validate_inherited_fd(&value)?;
    let file = unsafe {
        // SAFETY: the native procd supervisor transfers ownership of this open
        // descriptor to the runtime process through the private environment ABI.
        File::from_raw_fd(fd)
    };
    Ok(Some(file))
}

#[doc(hidden)]
pub fn validate_inherited_fd(value: &std::ffi::OsStr) -> io::Result<RawFd> {
    let value = value.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{INHERITED_TUN_FD_ENV} must be UTF-8"),
        )
    })?;
    let fd = value.parse::<RawFd>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{INHERITED_TUN_FD_ENV} must be a file descriptor: {error}"),
        )
    })?;
    if fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{INHERITED_TUN_FD_ENV} must be non-negative"),
        ));
    }
    let flags = unsafe {
        // SAFETY: F_GETFD only queries whether the caller-provided descriptor
        // refers to an open file; it does not take ownership.
        libc::fcntl(fd, libc::F_GETFD)
    };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

pub fn probe_default() -> io::Result<TunProbeReport> {
    probe(DEFAULT_TUN_INTERFACE)
}

pub fn probe(interface: &str) -> io::Result<TunProbeReport> {
    probe_wait(interface, Duration::ZERO)
}

pub fn probe_wait(interface: &str, wait: Duration) -> io::Result<TunProbeReport> {
    let mut tun = LinuxTun::open(interface)?;
    tun.set_nonblocking(true)?;
    let mut buffer = [0_u8; 2048];
    let deadline = Instant::now() + wait;
    let nonblocking_read = loop {
        match tun.read_packet(&mut buffer) {
            Ok(0) => break TunProbeRead::Eof,
            Ok(len) => break TunProbeRead::Packet(len),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if wait.is_zero() || Instant::now() >= deadline {
                    break TunProbeRead::WouldBlock;
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(error),
        }
    };
    Ok(TunProbeReport {
        open: TunOpenReport {
            device: PathBuf::from(DEFAULT_TUN_DEVICE),
            interface: tun.interface().to_string(),
        },
        nonblocking_read,
    })
}

fn bind_tun_interface(file: &File, interface: &str) -> io::Result<()> {
    let mut request = TunIfReq::new(interface)?;
    let result = unsafe {
        // SAFETY: file is an open /dev/net/tun descriptor. request is a valid,
        // writable C-compatible ifreq prefix containing ifr_name and ifr_flags,
        // which is what TUNSETIFF reads for IFF_TUN | IFF_NO_PI binding.
        libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &mut request)
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl TunIfReq {
    fn new(interface: &str) -> io::Result<Self> {
        let mut request = Self {
            name: [0; libc::IFNAMSIZ],
            flags: (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short,
            padding: [0; 24],
        };
        let bytes = interface.as_bytes();
        if bytes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN interface name cannot be empty",
            ));
        }
        if bytes.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("TUN interface name is too long: {interface}"),
            ));
        }
        for (target, source) in request.name.iter_mut().zip(bytes) {
            *target = *source as libc::c_char;
        }
        Ok(request)
    }
}

fn fcntl_getfl(file: &File) -> io::Result<libc::c_int> {
    let result = unsafe {
        // SAFETY: F_GETFL does not dereference the third vararg and only reads
        // descriptor status flags for this valid open file descriptor.
        libc::fcntl(file.as_raw_fd(), libc::F_GETFL)
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn fcntl_setfl(file: &File, flags: libc::c_int) -> io::Result<()> {
    let result = unsafe {
        // SAFETY: F_SETFL updates descriptor status flags for this valid open
        // file descriptor; flags are derived from a preceding F_GETFL call.
        libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags)
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

const _: () = {
    assert!(mem::size_of::<TunIfReq>() >= mem::size_of::<libc::c_short>() + libc::IFNAMSIZ);
};
