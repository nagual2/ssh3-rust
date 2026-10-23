//! The byte stream of the SFTP channel of the client.
//!
//! The SFTP protocol is a stream protocol, while an SSH3 channel carries
//! discrete messages: the adapter of this module turns the data messages of a
//! channel into a byte stream and the bytes written into data messages
//! again.
//!
//! The reference implementation of this behavior lives in
//! `nagual2/ssh3-go`, file `cmd/sftp_client.go` (the
//! `ssh3.NewChannelReadWriteCloser` adapter of the client) and
//! `cmd/sftp_subsystem.go` (the server side of the same adapter).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use ssh3_core::{Ssh3Channel, Ssh3ChannelError};
use ssh3_proto::{SSH_EXTENDED_DATA_NONE, Ssh3Message};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Returns `true` when the error of a channel only means that the peer went
/// away.
fn is_end_of_stream(error: &Ssh3ChannelError) -> bool {
    match error {
        Ssh3ChannelError::Io(error) => matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::BrokenPipe
        ),
        _ => false,
    }
}

/// A byte stream over an SSH3 channel.
///
/// The adapter keeps one pending read and one pending write: both are
/// futures that own the data they work on, so the stream stays a plain
/// value that can be moved into another task.
pub(crate) struct ChannelStream {
    /// The channel the stream runs on.
    channel: Arc<Ssh3Channel>,
    /// The bytes of the last data message that were not read yet.
    pending: Vec<u8>,
    /// The pending read of the next message of the channel.
    read_future: Option<ReadFuture>,
    /// The pending write of the next chunk.
    write_future: Option<WriteFuture>,
    /// `true` when the peer closed the channel.
    finished: bool,
}

/// The pending read of the next message of a channel.
type ReadFuture = Pin<Box<dyn Future<Output = Result<Ssh3Message, Ssh3ChannelError>> + Send>>;

/// The pending write of a chunk of data.
type WriteFuture = Pin<Box<dyn Future<Output = Result<(), Ssh3ChannelError>> + Send>>;

impl ChannelStream {
    /// Wraps a channel into a byte stream.
    pub(crate) fn new(channel: Arc<Ssh3Channel>) -> Self {
        Self {
            channel,
            pending: Vec::new(),
            read_future: None,
            write_future: None,
            finished: false,
        }
    }
}

impl AsyncRead for ChannelStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.pending.is_empty() {
                let take = buffer.remaining().min(this.pending.len());
                buffer.put_slice(&this.pending[..take]);
                this.pending.drain(..take);
                return Poll::Ready(Ok(()));
            }
            if this.finished {
                return Poll::Ready(Ok(()));
            }
            let future = match this.read_future.as_mut() {
                Some(future) => future,
                None => {
                    let channel = this.channel.clone();
                    this.read_future = Some(Box::pin(async move { channel.next_message().await }));
                    match this.read_future.as_mut() {
                        Some(future) => future,
                        None => return Poll::Ready(Err(io::Error::other("the sftp read failed"))),
                    }
                }
            };
            match future.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    this.read_future = None;
                    this.finished = true;
                    if is_end_of_stream(&error) {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::other(error.to_string())));
                }
                Poll::Ready(Ok(message)) => {
                    this.read_future = None;
                    match message {
                        Ssh3Message::Data(data) => {
                            if data.data_type != SSH_EXTENDED_DATA_NONE {
                                // the extended data of the channel is not part
                                // of the protocol: it is dropped
                                continue;
                            }
                            if data.data.is_empty() {
                                continue;
                            }
                            this.pending = data.data;
                        }
                        // the requests of the peer (a subsystem request, for
                        // example) are not part of the protocol either
                        _ => continue,
                    }
                }
            }
        }
    }
}

impl AsyncWrite for ChannelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.finished {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the sftp channel is closed",
            )));
        }
        let future = match this.write_future.as_mut() {
            Some(future) => future,
            None => {
                let channel = this.channel.clone();
                let data = buffer.to_vec();
                this.write_future = Some(Box::pin(async move {
                    channel.write_data(&data, SSH_EXTENDED_DATA_NONE).await?;
                    Ok(())
                }));
                match this.write_future.as_mut() {
                    Some(future) => future,
                    None => return Poll::Ready(Err(io::Error::other("the sftp write failed"))),
                }
            }
        };
        match future.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                this.write_future = None;
                this.finished = true;
                Poll::Ready(Err(io::Error::other(error.to_string())))
            }
            Poll::Ready(Ok(())) => {
                this.write_future = None;
                Poll::Ready(Ok(buffer.len()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // every write is sent to the channel as a whole, there is nothing to
        // flush
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
