use std::cmp::Ordering;
use std::marker::PhantomData;
use std::mem;
use std::ptr::NonNull;

#[derive(Debug)]
pub struct TcpOfoQueue<T> {
    head: Option<NonNull<Node<T>>>,
    tail: Option<NonNull<Node<T>>>,
    len: usize,
}

struct Node<T> {
    next: Option<NonNull<Node<T>>>,
    prev: Option<NonNull<Node<T>>>,
    element: T,
}

impl<T> Node<T> {
    fn new(element: T) -> Self {
        Node {
            next: None,
            prev: None,
            element,
        }
    }
}
impl<T> Default for TcpOfoQueue<T> {
    fn default() -> Self {
        TcpOfoQueue::new()
    }
}
impl<T: Ord> TcpOfoQueue<T> {
    pub fn push<F>(&mut self, elt: T, compute: F)
    where
        F: Fn(&T, &T) -> bool,
    {
        let mut prev = self.tail;
        while let Some(mut v) = prev {
            unsafe {
                let curr_elt = &v.as_ref().element;
                match curr_elt.cmp(&elt) {
                    Ordering::Less => break,
                    Ordering::Equal => {
                        if compute(curr_elt, &elt) {
                            v.as_mut().element = elt;
                        }
                        return;
                    }
                    Ordering::Greater => {
                        prev = v.as_ref().prev;
                    }
                }
            }
        }

        let mut node = Box::new(Node::new(elt));
        node.prev = prev;
        let node_ptr = NonNull::from(Box::leak(node));
        let node = Some(node_ptr);

        unsafe {
            match prev {
                None => {
                    (*node_ptr.as_ptr()).next = self.head;
                    self.head = node
                }
                Some(prev) => {
                    (*node_ptr.as_ptr()).next = (*prev.as_ptr()).next;
                    (*prev.as_ptr()).next = node
                }
            }
            match (*node_ptr.as_ptr()).next {
                None => {
                    self.tail = node;
                }
                Some(next) => {
                    (*next.as_ptr()).prev = node;
                }
            }
        }

        self.len += 1;
    }
    pub fn peek(&self) -> Option<&T> {
        self.head.map(|v| unsafe { &(*v.as_ptr()).element })
    }
}

impl<T> TcpOfoQueue<T> {
    pub fn new() -> Self {
        Self {
            head: None,
            tail: None,
            len: 0,
        }
    }
    pub fn pop(&mut self) -> Option<T> {
        self.head.map(|node| {
            unsafe {
                let node = Box::from_raw(node.as_ptr());
                self.head = node.next;

                match self.head {
                    None => self.tail = None,
                    // Not creating new mutable (unique!) references overlapping `element`.
                    Some(head) => (*head.as_ptr()).prev = None,
                }
                self.len -= 1;
                node.element
            }
        })
    }
    pub fn clear(&mut self) {
        drop(TcpOfoQueue {
            head: self.head.take(),
            tail: self.tail.take(),
            len: mem::take(&mut self.len),
        });
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn iter(&self) -> Iter<'_, T> {
        Iter {
            head: self.head,
            tail: self.tail,
            len: self.len,
            marker: PhantomData,
        }
    }
}

pub struct Iter<'a, T: 'a> {
    head: Option<NonNull<Node<T>>>,
    tail: Option<NonNull<Node<T>>>,
    len: usize,
    marker: PhantomData<&'a Node<T>>,
}

pub struct IntoIter<T> {
    list: TcpOfoQueue<T>,
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a T;

    #[inline]
    fn next(&mut self) -> Option<&'a T> {
        if self.len == 0 {
            None
        } else {
            self.head.map(|node| unsafe {
                // Need an unbound lifetime to get 'a
                let node = &*node.as_ptr();
                self.len -= 1;
                self.head = node.next;
                &node.element
            })
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len, Some(self.len))
    }
}

impl<T> Iterator for IntoIter<T> {
    type Item = T;

    #[inline]
    fn next(&mut self) -> Option<T> {
        self.list.pop()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.list.len, Some(self.list.len))
    }
}

impl<'a, T> IntoIterator for &'a TcpOfoQueue<T> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Iter<'a, T> {
        self.iter()
    }
}

impl<T> IntoIterator for TcpOfoQueue<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    /// Consumes the list into an iterator yielding elements by value.
    #[inline]
    fn into_iter(self) -> IntoIter<T> {
        IntoIter { list: self }
    }
}

impl<T> Drop for TcpOfoQueue<T> {
    fn drop(&mut self) {
        while self.pop().is_some() {}
    }
}
unsafe impl<T: Send> Send for TcpOfoQueue<T> {}

unsafe impl<T: Sync> Sync for TcpOfoQueue<T> {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn test_push_and_peek() {
        let mut queue = TcpOfoQueue::new();
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
        let list: Vec<i32> = queue.iter().map(|v| *v).collect();
        assert_eq!(&list, &[1, 5, 6, 7, 10, 20]);
    }

    #[test]
    fn test_push_with_duplicate_handling() {
        let mut queue = TcpOfoQueue::new();

        queue.push(10, |_, _| false);
        queue.push(10, |_, _| false);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.peek(), Some(&10));
        assert_eq!(queue.len(), 1);

        queue.push(10, |_, _| true);
        assert_eq!(queue.peek(), Some(&10));
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_pop() {
        let mut queue = TcpOfoQueue::new();

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
        let mut queue = TcpOfoQueue::new();

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
        let mut queue = TcpOfoQueue::new();

        assert_eq!(queue.len, 0);

        queue.push(10, |_, _| false);
        assert_eq!(queue.len, 1);

        queue.push(20, |_, _| false);
        assert_eq!(queue.len, 2);

        queue.pop();
        assert_eq!(queue.len, 1);

        queue.pop();
        assert_eq!(queue.len, 0);
    }

    #[test]
    fn test_ordering() {
        let mut queue = TcpOfoQueue::new();

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
        let mut queue = TcpOfoQueue::new();

        // Create elements that track drop count
        let mut elem1 = Arc::new(10);
        let mut elem2 = Arc::new(100);
        let mut elem3 = Arc::new(5);
        let mut elem4 = Arc::new(6);

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
