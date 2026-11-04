use anyhow::{Context, Result, bail};
use serde::{Serialize, de::DeserializeOwned};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream as SyncStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub async fn send<T: Serialize>(stream: &mut UnixStream, value: &T, limit: usize) -> Result<()> {
    let body = serde_json::to_vec(value)?;
    if body.len() > limit || body.len() > u32::MAX as usize {
        bail!("protocol frame exceeds limit");
    }
    stream.write_all(&(body.len() as u32).to_be_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn receive<T: DeserializeOwned>(stream: &mut UnixStream, limit: usize) -> Result<T> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 || len > limit {
        bail!("invalid protocol frame length");
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    serde_json::from_slice(&body).context("invalid protocol JSON")
}

pub fn send_sync<T: Serialize>(stream: &mut SyncStream, value: &T, limit: usize) -> Result<()> {
    let body = serde_json::to_vec(value)?;
    if body.len() > limit || body.len() > u32::MAX as usize {
        bail!("protocol frame exceeds limit");
    }
    stream.write_all(&(body.len() as u32).to_be_bytes())?;
    stream.write_all(&body)?;
    stream.flush()?;
    Ok(())
}

pub fn receive_sync<T: DeserializeOwned>(stream: &mut SyncStream, limit: usize) -> Result<T> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 || len > limit {
        bail!("invalid protocol frame length");
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body)?;
    serde_json::from_slice(&body).context("invalid protocol JSON")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn framing_roundtrip() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let producer = tokio::spawn(async move {
            send(&mut a, &"hello", 1024).await.unwrap();
        });
        let actual: String = receive(&mut b, 1024).await.unwrap();
        producer.await.unwrap();
        assert_eq!(actual, "hello");
    }

    #[tokio::test]
    async fn rejects_oversized_frame_before_allocation() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(&(5000u32.to_be_bytes())).await.unwrap();
        assert!(receive::<String>(&mut b, 64).await.is_err());
    }
}
