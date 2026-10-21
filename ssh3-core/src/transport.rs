//! Transport abstraction of the conversation runtime.
//!
//! The runtime does not know how bytes are moved; it only requires a
//! readable stream, a writable stream and a way to send datagrams.

use std::io;

use async_trait::async_trait;

/// The read side of a channel stream.
///
/// The transport is responsible for delivering exactly `buf.len()` bytes or
/// failing; a partial read is retried by the implementation.
#[async_trait]
pub trait Ssh3ReceiveStream: Send {
    /// Fills `buf` completely.
    async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()>;

    /// Aborts a pending read with the given error code.
    fn cancel_read(&mut self, error_code: u64);
}

/// The write side of a channel stream.
#[async_trait]
pub trait Ssh3SendStream: Send {
    /// Writes all bytes of `buf`.
    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()>;

    /// Closes the stream for writing.
    async fn close(&mut self) -> io::Result<()>;
}

/// Transport that can send datagrams for a conversation.
///
/// Datagrams are addressed by the channel they belong to; the conversation
/// prefixes every datagram with the ids of the conversation and the channel.
#[async_trait]
pub trait Ssh3DatagramSender: Send + Sync {
    /// Sends one datagram.
    async fn send_datagram(&self, datagram: Vec<u8>) -> io::Result<()>;
}

/// Test doubles for the transport traits.
#[cfg(test)]
pub mod testutil {
    use std::io::{self, Cursor, Read};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;

    use super::{Ssh3DatagramSender, Ssh3ReceiveStream, Ssh3SendStream};

    /// Handle of a [`BytesReceiveStream`], used to inspect the cancelled reads.
    #[derive(Clone)]
    pub struct BytesReceiveHandle {
        cancelled: Arc<Mutex<Vec<u64>>>,
    }

    impl BytesReceiveHandle {
        /// Returns the error codes of the reads that were cancelled.
        pub fn cancelled_codes(&self) -> Vec<u64> {
            self.cancelled.lock().unwrap().clone()
        }
    }

    /// A receive stream that serves a fixed buffer of bytes.
    pub struct BytesReceiveStream {
        inner: Cursor<Vec<u8>>,
        cancelled: Arc<Mutex<Vec<u64>>>,
    }

    impl BytesReceiveStream {
        /// Creates a stream over `bytes` and the handle that observes it.
        pub fn new(bytes: Vec<u8>) -> (Self, BytesReceiveHandle) {
            let cancelled = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    inner: Cursor::new(bytes),
                    cancelled: cancelled.clone(),
                },
                BytesReceiveHandle { cancelled },
            )
        }
    }

    #[async_trait]
    impl Ssh3ReceiveStream for BytesReceiveStream {
        async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
            self.inner.read_exact(buf)
        }

        fn cancel_read(&mut self, error_code: u64) {
            self.cancelled.lock().unwrap().push(error_code);
        }
    }

    /// Handle of a [`RecordingSendStream`], used to inspect what was written.
    #[derive(Clone)]
    pub struct RecordingSendHandle {
        bytes: Arc<Mutex<Vec<u8>>>,
        closed: Arc<AtomicBool>,
    }

    impl RecordingSendHandle {
        /// Returns everything that was written to the stream.
        pub fn bytes(&self) -> Vec<u8> {
            self.bytes.lock().unwrap().clone()
        }

        /// Returns `true` when the stream was closed.
        pub fn is_closed(&self) -> bool {
            self.closed.load(Ordering::SeqCst)
        }
    }

    /// A send stream that records everything written to it.
    pub struct RecordingSendStream {
        bytes: Arc<Mutex<Vec<u8>>>,
        closed: Arc<AtomicBool>,
    }

    impl RecordingSendStream {
        /// Creates a stream and the handle that observes it.
        pub fn new() -> (Self, RecordingSendHandle) {
            let bytes = Arc::new(Mutex::new(Vec::new()));
            let closed = Arc::new(AtomicBool::new(false));
            (
                Self {
                    bytes: bytes.clone(),
                    closed: closed.clone(),
                },
                RecordingSendHandle { bytes, closed },
            )
        }
    }

    #[async_trait]
    impl Ssh3SendStream for RecordingSendStream {
        async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
            self.bytes.lock().unwrap().extend_from_slice(buf);
            Ok(())
        }

        async fn close(&mut self) -> io::Result<()> {
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    /// A datagram sender that records every datagram it sends.
    #[derive(Clone, Default)]
    pub struct RecordingDatagramSender {
        datagrams: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl RecordingDatagramSender {
        /// Returns the datagrams that were sent so far.
        pub fn datagrams(&self) -> Vec<Vec<u8>> {
            self.datagrams.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl Ssh3DatagramSender for RecordingDatagramSender {
        async fn send_datagram(&self, datagram: Vec<u8>) -> io::Result<()> {
            self.datagrams.lock().unwrap().push(datagram);
            Ok(())
        }
    }
}
