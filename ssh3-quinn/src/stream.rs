use std::io;

use async_trait::async_trait;
use bytes::Bytes;
use quinn::{Connection, RecvStream, SendDatagramError, VarInt, WriteError};
use ssh3_core::{Ssh3DatagramSender, Ssh3ReceiveStream, Ssh3SendStream};

#[derive(Clone, Debug)]
pub struct Ssh3QuinnDatagramSender {
    connection: Connection,
}

impl Ssh3QuinnDatagramSender {
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

#[async_trait]
impl Ssh3DatagramSender for Ssh3QuinnDatagramSender {
    async fn send_datagram(&self, datagram: Vec<u8>) -> io::Result<()> {
        self.connection
            .send_datagram_wait(Bytes::from(datagram))
            .await
            .map_err(send_datagram_error_to_io)
    }
}

#[derive(Debug)]
pub struct Ssh3QuinnReceiveStream {
    inner: RecvStream,
}

impl Ssh3QuinnReceiveStream {
    pub fn new(inner: RecvStream) -> Self {
        Self { inner }
    }

    pub fn id(&self) -> u64 {
        self.inner.id().into()
    }

    pub fn into_inner(self) -> RecvStream {
        self.inner
    }
}

#[async_trait]
impl Ssh3ReceiveStream for Ssh3QuinnReceiveStream {
    async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.inner
            .read_exact(buf)
            .await
            .map_err(read_exact_error_to_io)
    }

    fn cancel_read(&mut self, error_code: u64) {
        let error_code = VarInt::try_from(error_code).unwrap_or(VarInt::MAX);
        let _ = self.inner.stop(error_code);
    }
}

#[derive(Debug)]
pub struct Ssh3QuinnSendStream {
    inner: quinn::SendStream,
}

impl Ssh3QuinnSendStream {
    pub fn new(inner: quinn::SendStream) -> Self {
        Self { inner }
    }

    pub fn id(&self) -> u64 {
        self.inner.id().into()
    }

    pub fn into_inner(self) -> quinn::SendStream {
        self.inner
    }
}

#[async_trait]
impl Ssh3SendStream for Ssh3QuinnSendStream {
    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.inner.write_all(buf).await.map_err(io::Error::from)
    }

    async fn close(&mut self) -> io::Result<()> {
        self.inner.finish().map_err(close_error_to_io)
    }
}

pub(crate) fn read_exact_error_to_io(error: quinn::ReadExactError) -> io::Error {
    match error {
        quinn::ReadExactError::FinishedEarly(_) => {
            io::Error::new(io::ErrorKind::UnexpectedEof, error)
        }
        quinn::ReadExactError::ReadError(error) => io::Error::from(error),
    }
}

fn close_error_to_io(error: quinn::ClosedStream) -> io::Error {
    let error = WriteError::from(error);
    io::Error::from(error)
}

fn send_datagram_error_to_io(error: SendDatagramError) -> io::Error {
    let kind = match &error {
        SendDatagramError::UnsupportedByPeer | SendDatagramError::Disabled => {
            io::ErrorKind::Unsupported
        }
        SendDatagramError::TooLarge => io::ErrorKind::InvalidData,
        SendDatagramError::ConnectionLost(_) => io::ErrorKind::NotConnected,
    };
    io::Error::new(kind, error)
}
