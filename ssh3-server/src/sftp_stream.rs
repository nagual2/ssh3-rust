//! The byte streams of the SFTP subsystem.
//!
//! The SFTP protocol is a stream protocol, while an SSH3 channel carries
//! discrete messages: the adapters of this module turn the data messages of a
//! channel into a byte stream and the bytes written into data messages
//! again.
//!
//! The reference implementation of this behavior lives in
//! `nagual2/ssh3-go`, file `cmd/sftp_client.go` (the `ssh3.NewChannelReadWriteCloser`
//! adapter) and `cmd/internal_sftp.go` (the standard streams of the child).

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
    /// The signal that tells the end of the stream.
    done: tokio::sync::watch::Sender<bool>,
}

/// The pending read of the next message of a channel.
type ReadFuture = Pin<Box<dyn Future<Output = Result<Ssh3Message, Ssh3ChannelError>> + Send>>;

/// The pending write of a chunk of data.
type WriteFuture = Pin<Box<dyn Future<Output = Result<(), Ssh3ChannelError>> + Send>>;

impl ChannelStream {
    /// Wraps a channel into a byte stream.
    ///
    /// The returned handle tells when the stream is over: either because the
    /// peer closed the channel or because the stream was dropped.
    pub(crate) fn new(channel: Arc<Ssh3Channel>) -> (Self, StreamDone) {
        let (done, receiver) = tokio::sync::watch::channel(false);
        (
            Self {
                channel,
                pending: Vec::new(),
                read_future: None,
                write_future: None,
                finished: false,
                done,
            },
            StreamDone { receiver },
        )
    }

    /// Signals that the stream is over.
    fn signal_done(&self) {
        let _ = self.done.send(true);
    }
}

/// The signal that tells the end of a channel stream.
pub(crate) struct StreamDone {
    /// The state of the signal.
    receiver: tokio::sync::watch::Receiver<bool>,
}
impl StreamDone {
    /// Waits until the stream is over.
    pub(crate) async fn wait(&mut self) {
        if *self.receiver.borrow() {
            return;
        }
        // the sender is dropped with the stream, so a closed channel ends the
        // wait as well
        let _ = self.receiver.changed().await;
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
                    this.signal_done();
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
        _cx: &mut Context<'_>,
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
        match future.as_mut().poll(_cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                this.write_future = None;
                this.finished = true;
                this.signal_done();
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

/// A byte stream over the standard input and the standard output.
///
/// The stream is the transport of the internal SFTP child: the child reads
/// the protocol from its standard input and writes it to its standard
/// output, the parent pumps the bytes of the channel into the child and back.
pub(crate) struct StdioStream {
    /// The standard input of the process.
    input: tokio::io::Stdin,
    /// The standard output of the process.
    output: tokio::io::Stdout,
    /// The signal that tells the end of the stream.
    done: tokio::sync::watch::Sender<bool>,
}

impl StdioStream {
    /// Wraps the standard streams of the process.
    ///
    /// The returned handle tells when the input of the process is over.
    pub(crate) fn new() -> (Self, StreamDone) {
        let (done, receiver) = tokio::sync::watch::channel(false);
        (
            Self {
                input: tokio::io::stdin(),
                output: tokio::io::stdout(),
                done,
            },
            StreamDone { receiver },
        )
    }
}

impl AsyncRead for StdioStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        match Pin::new(&mut this.input).poll_read(cx, buffer) {
            Poll::Ready(Ok(())) => {
                if buffer.filled().len() == before {
                    // the input of the process is over
                    let _ = this.done.send(true);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl AsyncWrite for StdioStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().output).poll_write(cx, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().output).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().output).poll_shutdown(cx)
    }
}
