use crate::tcp::tcb::UnreadPacket;
use bytes::Bytes;
use std::collections::{BTreeMap, LinkedList};

#[derive(Debug, Default)]
pub(crate) struct TcpReceiveQueue {
    total_bytes: usize,
    queue: LinkedList<Bytes>,
}
impl TcpReceiveQueue {
    pub fn push(&mut self, elt: Bytes) {
        self.total_bytes += elt.len();
        self.queue.push_back(elt);
    }
    pub fn pop(&mut self) -> Option<Bytes> {
        if let Some(v) = self.queue.pop_front() {
            self.total_bytes -= v.len();
            Some(v)
        } else {
            None
        }
    }
    pub fn clear(&mut self) {
        self.queue.clear();
        self.total_bytes = 0;
    }
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }
}
#[derive(Debug, Default)]
pub(crate) struct TcpOfoQueue {
    total_bytes: usize,
    queue: OrderQueue<UnreadPacket>,
}
fn handle_duplicate_seq(p1: &UnreadPacket, p2: &UnreadPacket) -> bool {
    p1.len() < p2.len()
}
impl TcpOfoQueue {
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }
    pub fn push(&mut self, elt: UnreadPacket) {
        self.total_bytes += elt.len();
        if let Some(dropped) = self.queue.push(elt, handle_duplicate_seq) {
            // A duplicate seq was rejected or replaced,
            // its bytes must not be counted
            self.total_bytes -= dropped.len();
        }
    }
    pub fn pop(&mut self) -> Option<UnreadPacket> {
        if let Some(v) = self.queue.pop() {
            self.total_bytes -= v.len();
            Some(v)
        } else {
            None
        }
    }
    pub fn peek(&self) -> Option<&UnreadPacket> {
        self.queue.peek()
    }
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

impl<'a> IntoIterator for &'a TcpOfoQueue {
    type Item = &'a UnreadPacket;
    type IntoIter = Iter<'a, UnreadPacket>;

    fn into_iter(self) -> Iter<'a, UnreadPacket> {
        self.queue.iter()
    }
}

#[derive(Debug)]
pub struct OrderQueue<T> {
    entries: BTreeMap<T, ()>,
}
impl<T: Ord> Default for OrderQueue<T> {
    fn default() -> Self {
        OrderQueue::new()
    }
}
impl<T: Ord> OrderQueue<T> {
    /// Insert `elt` keeping the queue ordered.
    /// When an element with an equal key already exists, `compute(curr, new)` decides
    /// whether the new element replaces the current one.
    /// Returns the element that was dropped (the rejected new one or the replaced old one), if any.
    pub fn push<F>(&mut self, elt: T, compute: F) -> Option<T>
    where
        F: Fn(&T, &T) -> bool,
    {
        if let Some((curr, _)) = self.entries.get_key_value(&elt) {
            if compute(curr, &elt) {
                let (old, _) = self.entries.remove_entry(&elt).expect("existing key must be removable");
                self.entries.insert(elt, ());
                return Some(old);
            }
            return Some(elt);
        }
        self.entries.insert(elt, ());
        None
    }
}

impl<T: Ord> OrderQueue<T> {
    pub fn new() -> Self {
        Self { entries: BTreeMap::new() }
    }
    #[inline]
    pub fn peek(&self) -> Option<&T> {
        self.entries.first_key_value().map(|(key, _)| key)
    }
    pub fn pop(&mut self) -> Option<T> {
        self.entries.pop_first().map(|(key, _)| key)
    }
    pub fn clear(&mut self) {
        self.entries.clear();
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn iter(&self) -> Iter<'_, T> {
        self.entries.keys()
    }
}

pub type Iter<'a, T> = std::collections::btree_map::Keys<'a, T, ()>;

pub struct IntoIter<T> {
    keys: std::collections::btree_map::IntoKeys<T, ()>,
}

impl<T> Iterator for IntoIter<T> {
    type Item = T;

    #[inline]
    fn next(&mut self) -> Option<T> {
        self.keys.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.keys.size_hint()
    }
}

impl<'a, T: Ord> IntoIterator for &'a OrderQueue<T> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Iter<'a, T> {
        self.iter()
    }
}

impl<T> IntoIterator for OrderQueue<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    /// Consumes the list into an iterator yielding elements by value.
    #[inline]
    fn into_iter(self) -> IntoIter<T> {
        IntoIter {
            keys: self.entries.into_keys(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn test_push_and_peek() {
        let mut queue = OrderQueue::new();
        queue.push(10, |_, _| false);
        assert_eq!(queue.peek(), Some(&10));
        queue.push(20, |_, _| false);
        assert_eq!(queue.peek(), Some(&10));
        queue.push(5, |_, _| false);
        assert_eq!(queue.peek(), Some(&5));
        queue.push(6, |_, _| false);
        assert_eq!(queue.peek(), Some(&5));
        queue.push(7, |_, _| false);
        assert_eq!(queue.peek(), Some(&5));
        queue.push(1, |_, _| false);
        assert_eq!(queue.peek(), Some(&1));
        assert_eq!(queue.len(), 6);
        let list: Vec<i32> = queue.iter().copied().collect();
        assert_eq!(&list, &[1, 5, 6, 7, 10, 20]);
    }

    #[test]
    fn test_push_with_duplicate_handling() {
        let mut queue = OrderQueue::new();

        assert_eq!(queue.push(10, |_, _| false), None);
        // The new duplicate is rejected and returned
        assert_eq!(queue.push(10, |_, _| false), Some(10));
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.peek(), Some(&10));
        assert_eq!(queue.len(), 1);

        // The old element is replaced and returned
        assert_eq!(queue.push(10, |_, _| true), Some(10));
        assert_eq!(queue.peek(), Some(&10));
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_pop() {
        let mut queue = OrderQueue::new();

        queue.push(10, |_, _| false);
        queue.push(20, |_, _| false);
        queue.push(5, |_, _| false);
        queue.push(6, |_, _| false);
        queue.push(7, |_, _| false);
        queue.push(1, |_, _| false);
        queue.push(0, |_, _| false);
        queue.push(100, |_, _| false);
        queue.push(99, |_, _| false);
        assert_eq!(queue.pop(), Some(0));
        assert_eq!(queue.pop(), Some(1));
        assert_eq!(queue.pop(), Some(5));
        assert_eq!(queue.pop(), Some(6));
        assert_eq!(queue.pop(), Some(7));
        assert_eq!(queue.pop(), Some(10));
        assert_eq!(queue.pop(), Some(20));
        assert_eq!(queue.pop(), Some(99));
        assert_eq!(queue.pop(), Some(100));
        assert_eq!(queue.pop(), None);
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn test_clear() {
        let mut queue = OrderQueue::new();

        queue.push(10, |_, _| false);
        queue.push(20, |_, _| false);
        queue.push(30, |_, _| false);

        queue.clear();
        assert_eq!(queue.len(), 0);
        assert_eq!(queue.peek(), None);
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn test_len() {
        let mut queue = OrderQueue::new();

        assert_eq!(queue.len(), 0);

        queue.push(10, |_, _| false);
        assert_eq!(queue.len(), 1);

        queue.push(20, |_, _| false);
        assert_eq!(queue.len(), 2);

        queue.pop();
        assert_eq!(queue.len(), 1);

        queue.pop();
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn test_ordering() {
        let mut queue = OrderQueue::new();

        queue.push(15, |_, _| false);
        queue.push(10, |_, _| false);
        queue.push(20, |_, _| false);
        queue.push(5, |_, _| false);

        assert_eq!(queue.pop(), Some(5));
        assert_eq!(queue.pop(), Some(10));
        assert_eq!(queue.pop(), Some(15));
        assert_eq!(queue.pop(), Some(20));
    }

    #[test]
    fn test_drop_after_pop() {
        let mut queue = OrderQueue::new();

        // Create elements that track drop count
        let elem1 = Arc::new(10);
        let elem2 = Arc::new(100);
        let elem3 = Arc::new(5);
        let elem4 = Arc::new(6);

        // Push elements into the queue
        queue.push(elem1.clone(), |_, _| false);
        queue.push(elem2.clone(), |_, _| false);
        queue.push(elem3.clone(), |_, _| false);
        queue.push(elem4.clone(), |_, _| false);
        assert_eq!(Arc::strong_count(&elem1), 2);
        assert_eq!(Arc::strong_count(&elem2), 2);
        assert_eq!(Arc::strong_count(&elem3), 2);
        assert_eq!(Arc::strong_count(&elem4), 2);
        queue.clear();
        assert_eq!(Arc::strong_count(&elem1), 1);
        assert_eq!(Arc::strong_count(&elem2), 1);
        assert_eq!(Arc::strong_count(&elem3), 1);
        assert_eq!(Arc::strong_count(&elem4), 1);
    }
}
