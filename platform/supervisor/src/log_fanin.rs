use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// Prefix each complete line written to an inner `AsyncWrite` (stdout fan-in).
pub struct LinePrefixWriter<W> {
    inner: W,
    prefix: Vec<u8>,
}

impl<W: AsyncWrite + Unpin> LinePrefixWriter<W> {
    pub fn new(inner: W, prefix: impl AsRef<str>) -> Self {
        let mut p = prefix.as_ref().as_bytes().to_vec();
        p.push(b' ');
        Self { inner, prefix: p }
    }

    /// Copy lines from `reader` into `self`, flushing after each line.
    pub async fn copy_lines<R>(mut self, reader: R) -> std::io::Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        let mut lines = BufReader::new(reader).lines();
        while let Some(line) = lines.next_line().await? {
            self.inner.write_all(&self.prefix).await?;
            self.inner.write_all(line.as_bytes()).await?;
            self.inner.write_all(b"\n").await?;
            self.inner.flush().await?;
        }
        Ok(())
    }
}
