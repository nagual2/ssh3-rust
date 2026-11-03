//! The standard input of the client as an async stream.
//!
//! [`tokio::io::stdin`] runs every read on the blocking pool of the runtime,
//! and the read of an interactive console cannot be cancelled: the thread of
//! the pool stays parked in the read until the user presses a key. The
//! shutdown of the runtime joins the pool, so a client of an interactive
//! session stayed alive after the remote side exited, and the console window
//! never closed. The documentation of tokio names the remedy: read the
//! interactive input on a dedicated thread of the process.
//!
//! The module does exactly that: a plain thread of the process performs the
//! blocking reads and hands the chunks to the async side through a bounded
//! channel, so the backpressure of a blocking reader survives. A thread
//! parked in a console read holds nothing of the runtime: the runtime shuts
//! down, the process exits, and the operating system reclaims the thread.

use std::io::{self, Read};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::AsyncRead;
use tokio::sync::mpsc;

/// The number of chunks the reader thread may hold in flight.
///
/// The bound restores the backpressure of a blocking read: a fast producer
/// (a pipe of bulk input) parks the thread instead of buffering the whole
/// stream inside the process.
const CHANNEL_CAPACITY: usize = 16;
/// The size of one chunk the reader thread reads.
const CHUNK_SIZE: usize = 32 * 1024;

/// The async stream of a blocking reader of the process.
///
/// The stream is [`Unpin`]: the session pump holds it by value and reads it
/// like any other [`AsyncRead`]. Dropping the stream leaves the reader
/// thread behind; the thread dies with the process instead of holding the
/// shutdown of the runtime.
pub struct StdinStream {
    /// The chunks the reader thread produced, `Err` carries a read failure.
    receiver: mpsc::Receiver<io::Result<Vec<u8>>>,
    /// The chunk that is currently being drained into the callers of the
    /// stream: `offset` is the position the caller already consumed.
    chunk: Vec<u8>,
    offset: usize,
}

/// Builds the async stream of the standard input of the process.
pub fn stream() -> StdinStream {
    from_reader(io::stdin())
}

/// Builds the async stream of an arbitrary blocking reader.
///
/// The tests feed synthetic readers; the session pump feeds the standard
/// input of the process.
fn from_reader<R>(reader: R) -> StdinStream
where
    R: Read + Send + 'static,
{
    let (sender, receiver) = mpsc::channel(CHANNEL_CAPACITY);
    let spawned = std::thread::Builder::new()
        .name("ssh3-stdin".to_string())
        .spawn(move || {
            let mut reader = reader;
            let mut buf = vec![0u8; CHUNK_SIZE];
            loop {
                match reader.read(&mut buf) {
                    // The end of the stream: dropping the sender reports the
                    // EOF to the async side.
                    Ok(0) => return,
                    Ok(n) => {
                        if sender.blocking_send(Ok(buf[..n].to_vec())).is_err() {
                            // The session pump is gone: the session ended.
                            return;
                        }
                    }
                    Err(err) => {
                        let _ = sender.blocking_send(Err(err));
                        return;
                    }
                }
            }
        });
    // A failure to spawn the thread is a process-level condition: the
    // session cannot read the console without it. The thread is detached:
    // it lives until its read ends or the process exits, and the EOF
    // travels as the close of the channel.
    spawned.expect("the reader thread of the standard input");
    StdinStream {
        receiver,
        chunk: Vec::new(),
        offset: 0,
    }
}

impl AsyncRead for StdinStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.offset < this.chunk.len() {
                let remaining = &this.chunk[this.offset..];
                let n = remaining.len().min(dst.remaining());
                dst.put_slice(&remaining[..n]);
                this.offset += n;
                return Poll::Ready(Ok(()));
            }
            match this.receiver.poll_recv(cx) {
                // A fresh chunk: drain it on the next pass of the loop.
                Poll::Ready(Some(Ok(chunk))) => {
                    this.chunk = chunk;
                    this.offset = 0;
                }
                // A read failure of the blocking reader.
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Err(err)),
                // The reader thread is gone: the end of the stream.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CHUNK_SIZE, StdinStream, from_reader};
    use std::io::{self, Read};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use tokio::io::AsyncReadExt;

    /// A reader that yields the chunks of a fixed payload, then EOF.
    struct PayloadReader {
        payload: Vec<u8>,
        position: usize,
    }

    impl PayloadReader {
        fn new(payload: Vec<u8>) -> Self {
            Self {
                payload,
                position: 0,
            }
        }
    }

    impl Read for PayloadReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let remaining = self.payload.len() - self.position;
            if remaining == 0 {
                return Ok(0);
            }
            let n = remaining.min(buf.len());
            buf[..n].copy_from_slice(&self.payload[self.position..self.position + n]);
            self.position += n;
            Ok(n)
        }
    }

    /// A reader that fails after the first chunk, like a console that
    /// reports an error mid-session.
    struct FailingReader {
        first: Option<Vec<u8>>,
    }

    impl Read for FailingReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.first.take() {
                Some(chunk) => {
                    let n = chunk.len().min(buf.len());
                    buf[..n].copy_from_slice(&chunk[..n]);
                    Ok(n)
                }
                None => Err(io::Error::other("the reader failed")),
            }
        }
    }

    /// A reader that never returns, like a console read with no key typed.
    ///
    /// The thread of the adapter parks in `recv` until the test drops the
    /// sender side (which never happens inside the test body).
    struct ParkedReader {
        keep_alive: mpsc::Receiver<()>,
    }

    impl Read for ParkedReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            match self.keep_alive.recv() {
                // The test never sends: the read only ends when the test
                // drops the sender, after the shutdown it measures.
                Ok(()) => unreachable!("the test never sends"),
                Err(_) => Ok(0),
            }
        }
    }

    #[tokio::test]
    async fn the_stream_carries_the_data_and_the_eof() {
        let mut stream = from_reader(PayloadReader::new(b"terminal input".to_vec()));
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"terminal input");
    }

    #[tokio::test]
    async fn a_payload_larger_than_one_chunk_arrives_intact() {
        // The pattern spans several reader chunks: the tail of every chunk
        // must survive until the caller consumes it.
        let payload: Vec<u8> = (0..(2 * CHUNK_SIZE + 17))
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let mut stream = from_reader(PayloadReader::new(payload.clone()));
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, payload);
    }

    #[tokio::test]
    async fn a_read_failure_of_the_reader_surfaces() {
        let mut stream = from_reader(FailingReader {
            first: Some(b"partial".to_vec()),
        });
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"partial");
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.to_string(), "the reader failed");
    }

    #[test]
    fn a_parked_reader_does_not_hold_the_runtime_shutdown() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (sender, keep_alive) = mpsc::channel::<()>();
        runtime.block_on(async {
            let mut stream: StdinStream = from_reader(ParkedReader { keep_alive });
            let task = tokio::spawn(async move {
                // The read that never completes, exactly like the console of
                // an interactive session after the remote side exited.
                let mut buf = [0u8; 16];
                let _ = stream.read(&mut buf).await;
            });
            tokio::time::sleep(Duration::from_millis(200)).await;
            task.abort();
        });
        // A read parked on the blocking pool would hold the shutdown until
        // the timeout expires; the dedicated thread holds nothing.
        let started = Instant::now();
        runtime.shutdown_timeout(Duration::from_secs(3));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the shutdown of the runtime waited for the reader"
        );
        // The sender keeps the parked thread alive until the test ends: the
        // thread dies with the process, not with the runtime.
        drop(sender);
    }

    #[test]
    fn the_reader_thread_yields_a_chunk_of_the_expected_size() {
        // The sanity of the plumbing the session relies on: one read of the
        // stream returns exactly one chunk of the reader.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut stream = from_reader(PayloadReader::new(vec![b'x'; CHUNK_SIZE]));
            let mut buf = vec![0u8; CHUNK_SIZE];
            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(n, CHUNK_SIZE);
            assert!(buf.iter().all(|byte| *byte == b'x'));
        });
    }
}
