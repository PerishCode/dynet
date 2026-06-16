use tokio::io::AsyncWriteExt;

#[inline]
#[allow(clippy::uninit_vec)]
pub(crate) fn allocate_vec<T>(len: usize) -> Vec<T> {
    let mut ret = Vec::with_capacity(len);
    unsafe {
        ret.set_len(len);
    }
    ret
}

#[inline]
pub(crate) async fn write_all<T: AsyncWriteExt + Unpin>(
    stream: &mut T,
    buf: &[u8],
) -> std::io::Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        let written = stream.write(&buf[offset..]).await?;
        if written == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        offset += written;
    }
    Ok(())
}
