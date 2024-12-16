use bytes::BytesMut;

#[derive(Debug)]
pub struct FixedBuffer {
    offset: usize,
    buf: BytesMut,
}
impl FixedBuffer {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            offset: 0,
            buf: BytesMut::with_capacity(capacity),
        }
    }
    pub fn available(&self) -> usize {
        self.buf.capacity() - self.buf.len()
    }
    pub fn clear(&mut self) {
        self.offset = 0;
        self.buf.clear();
    }
    pub fn offset(&self) -> usize {
        self.offset
    }
    pub fn advance(&mut self, n: usize) {
        self.offset += n;
        assert!(self.offset <= self.buf.capacity());
        if self.offset > self.buf.len() {
            self.buf.resize(self.offset, 0);
        }
    }
    pub fn back(&mut self, n: usize) {
        assert!(self.offset >= n);
        self.offset -= n;
    }
    pub fn extend_from_slice(&mut self, buf: &[u8]) -> usize {
        let n = buf.len().min(self.available());
        if n == 0 {
            return 0;
        }
        self.buf.extend_from_slice(&buf[..n]);
        n
    }
    pub fn len(&self) -> usize {
        self.buf.len() - self.offset
    }
    pub fn bytes(&self) -> &[u8] {
        &self.buf[self.offset..]
    }
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.offset..]
    }
}

pub struct RingBuffer {
    buffer: Vec<u8>,
    head: usize,
    tail: usize,
    size: usize,
}
impl RingBuffer {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity.is_power_of_two(), "Capacity must be a power of 2");
        Self {
            buffer: vec![0; capacity],
            head: 0,
            tail: 0,
            size: 0,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_full(&self) -> bool {
        self.size == self.buffer.capacity()
    }
    pub fn capacity(&self) -> usize {
        self.buffer.capacity()
    }
    pub fn available(&self) -> usize {
        self.capacity() - self.size
    }
    pub fn push(&mut self, data: &[u8]) -> usize {
        let push_len = self.available().min(data.len());
        if push_len == 0 {
            return 0;
        }
        let first_part = self.capacity() - self.tail;
        if push_len <= first_part {
            self.buffer[self.tail..self.tail + push_len].copy_from_slice(&data[..push_len]);
        } else {
            self.buffer[self.tail..].copy_from_slice(&data[..first_part]);
            self.buffer[..push_len - first_part].copy_from_slice(&data[first_part..push_len]);
        }
        self.tail = (self.tail + push_len) & (self.capacity() - 1);
        self.size += push_len;
        push_len
    }
    pub fn pop(&mut self, buf: &mut [u8]) -> usize {
        let len = buf.len().min(self.len());
        if len == 0 {
            return 0;
        }
        let mask = self.capacity() - 1;
        let first_part = self.capacity() - (self.head & mask);
        if len <= first_part {
            buf[..len].copy_from_slice(&self.buffer[self.head & mask..(self.head & mask) + len]);
        } else {
            buf[..first_part].copy_from_slice(&self.buffer[self.head & mask..]);
            buf[first_part..len].copy_from_slice(&self.buffer[..len - first_part]);
        }

        self.head = (self.head + len) & mask;
        self.size -= len;
        len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_fixed_buffer() {
        let mut buffer = FixedBuffer::with_capacity(10);

        // Test extend_from_slice
        let buf = &[1, 2, 3, 4, 5];
        let extended_len = buffer.extend_from_slice(buf);
        assert_eq!(extended_len, 5); // 5 bytes should be added
        assert_eq!(buffer.len(), 5); // Buffer length should be 5
        assert_eq!(buffer.bytes(), &[1, 2, 3, 4, 5]); // Buffer content should match

        // Test advance
        buffer.advance(3);
        assert_eq!(buffer.len(), 2); // After advancing 3, length should be 2
        assert_eq!(buffer.bytes(), &[4, 5]); // Remaining bytes should be [4, 5]

        // Test back
        buffer.back(1);
        assert_eq!(buffer.len(), 3); // After going back by 1, length should be 3
        assert_eq!(buffer.bytes(), &[3, 4, 5]); // Remaining bytes should be [3, 4, 5]

        // Test available space
        assert_eq!(buffer.available(), 5);
        buffer.extend_from_slice(&[6, 7]);
        assert_eq!(buffer.available(), 3);
        // Test clear
        buffer.clear();
        assert_eq!(buffer.available(), 10);
        assert_eq!(buffer.len(), 0); // After clear, buffer should be empty
        assert_eq!(buffer.bytes(), &[]); // No bytes left after clearing
    }
    #[test]
    fn test_ring_buffer() {
        let mut ring_buffer = RingBuffer::new(8);

        // Test pushing data
        let pushed_len = ring_buffer.push(&[1, 2, 3, 4, 5]);
        assert_eq!(pushed_len, 5); // 5 bytes pushed
        assert_eq!(ring_buffer.len(), 5); // Buffer size should be 5

        // Test popping data
        let mut buf = vec![0; 4];
        let popped_len = ring_buffer.pop(&mut buf);
        assert_eq!(popped_len, 4); // 4 bytes popped
        assert_eq!(buf, [1, 2, 3, 4]); // Popped data should match

        // Test remaining data in buffer
        assert_eq!(ring_buffer.len(), 1); // Only 1 byte should be left

        // Test pushing more data
        let pushed_len = ring_buffer.push(&[6, 7, 8]);
        assert_eq!(pushed_len, 3); // 3 bytes pushed
        assert_eq!(ring_buffer.len(), 4); // Buffer size should now be 4

        // Test popping remaining data
        let mut buf = vec![0; 4];
        let popped_len = ring_buffer.pop(&mut buf);
        assert_eq!(popped_len, 4); // 4 bytes popped
        assert_eq!(buf, [5, 6, 7, 8]); // Popped data should match
        let pushed_len = ring_buffer.push(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(pushed_len, 8);
        let mut buf = vec![0; 10];
        let popped_len = ring_buffer.pop(&mut buf);
        assert_eq!(popped_len, 8);
        assert_eq!(&buf[..popped_len], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
