//! Queues used by the conversation runtime: the accept queue of incoming
//! channels and the bounded queue of the datagrams of a channel.

use std::collections::VecDeque;
use std::sync::Mutex;

use tokio::sync::Notify;

/// An unbounded FIFO queue that can be awaited by a single consumer.
///
/// Used to hand the channels opened by the peer over to the accepting task.
pub struct Ssh3AcceptQueue<T> {
    queue: Mutex<VecDeque<T>>,
    notify: Notify,
}

impl<T> Ssh3AcceptQueue<T> {
    /// Creates an empty queue.
    pub fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
        }
    }

    /// Appends an item and wakes up a waiting consumer.
    pub fn add(&self, item: T) {
        self.queue.lock().unwrap().push_back(item);
        self.notify.notify_one();
    }

    /// Removes the oldest item, if there is one.
    pub fn next(&self) -> Option<T> {
        self.queue.lock().unwrap().pop_front()
    }

    /// Waits for an item and returns it.
    pub async fn wait_next(&self) -> T {
        loop {
            let notified = self.notify.notified();
            if let Some(item) = self.next() {
                return item;
            }
            notified.await;
        }
    }
}

impl<T> Default for Ssh3AcceptQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// A bounded FIFO queue of datagrams.
///
/// The queue applies back pressure: producers that use
/// [`Ssh3DatagramQueue::wait_add`] are suspended while the queue is full.
pub struct Ssh3DatagramQueue {
    queue: Mutex<VecDeque<Vec<u8>>>,
    capacity: usize,
    not_empty: Notify,
    not_full: Notify,
}

impl Ssh3DatagramQueue {
    /// Creates a queue that holds at most `capacity` datagrams.
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
            not_empty: Notify::new(),
            not_full: Notify::new(),
        }
    }

    /// Appends a datagram without waiting.
    ///
    /// Returns `false` when the queue is full and the datagram was dropped.
    pub fn add(&self, datagram: Vec<u8>) -> bool {
        let mut queue = self.queue.lock().unwrap();
        if queue.len() >= self.capacity {
            return false;
        }
        queue.push_back(datagram);
        drop(queue);
        self.not_empty.notify_one();
        true
    }

    /// Appends a datagram, waiting until the queue has room again.
    pub async fn wait_add(&self, datagram: Vec<u8>) {
        let mut datagram = Some(datagram);
        loop {
            let notified = self.not_full.notified();
            {
                let mut queue = self.queue.lock().unwrap();
                if queue.len() < self.capacity {
                    queue.push_back(datagram.take().unwrap());
                    drop(queue);
                    self.not_empty.notify_one();
                    return;
                }
            }
            notified.await;
        }
    }

    /// Removes the oldest datagram, if there is one.
    pub fn next(&self) -> Option<Vec<u8>> {
        let datagram = self.queue.lock().unwrap().pop_front();
        if datagram.is_some() {
            self.not_full.notify_one();
        }
        datagram
    }

    /// Waits for a datagram and returns it.
    pub async fn wait_next(&self) -> Vec<u8> {
        loop {
            let notified = self.not_empty.notified();
            if let Some(datagram) = self.next() {
                return datagram;
            }
            notified.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Ssh3AcceptQueue, Ssh3DatagramQueue};

    #[tokio::test]
    async fn accept_queue_delivers_items_in_order() {
        let queue = Ssh3AcceptQueue::new();
        queue.add(1);
        queue.add(2);

        assert_eq!(queue.next(), Some(1));
        assert_eq!(queue.wait_next().await, 2);
    }

    #[tokio::test]
    async fn datagram_queue_blocks_until_space_and_preserves_order() {
        let queue = Ssh3DatagramQueue::new(1);
        assert!(queue.add(vec![1]));
        assert!(!queue.add(vec![2]));

        let waiting = queue.wait_add(vec![2]);
        tokio::pin!(waiting);
        tokio::task::yield_now().await;
        assert_eq!(queue.wait_next().await, vec![1]);
        waiting.await;
        assert_eq!(queue.wait_next().await, vec![2]);
    }
}
