use std::{
    collections::VecDeque,
    io::{self, Read},
};

pub(crate) enum BufferedRead {
    Ready(Vec<u8>),
    Pending,
    Eof,
}

pub(crate) fn read_exact(
    stream: &mut dyn Read,
    buffered: &mut VecDeque<u8>,
    len: usize,
    label: &str,
) -> io::Result<BufferedRead> {
    while buffered.len() < len {
        let remaining = len - buffered.len();
        let mut buffer = vec![0_u8; remaining];
        match stream.read(&mut buffer) {
            Ok(0) if buffered.is_empty() => return Ok(BufferedRead::Eof),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("failed to read {label}: unexpected EOF"),
                ))
            }
            Ok(size) => buffered.extend(buffer.into_iter().take(size)),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if pending_kind(error.kind()) => return Ok(BufferedRead::Pending),
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("failed to read {label}: {error}"),
                ))
            }
        }
    }
    Ok(BufferedRead::Ready(buffered.drain(..len).collect()))
}

pub(crate) fn pending(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, message)
}

pub(crate) fn invalid_data(error: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn pending_kind(kind: io::ErrorKind) -> bool {
    matches!(kind, io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}
