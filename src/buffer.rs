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
    pub fn advance(&mut self, n: usize) {
        self.offset += n;
        assert!(self.offset <= self.buf.capacity());
        if self.offset > self.buf.len() {
            self.buf.resize(self.offset, 0);
        }
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
}
