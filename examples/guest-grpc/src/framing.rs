//! gRPC's message framing, which is five bytes.
//!
//! One compression flag, then a big-endian `u32` length, then the message.
//! Frames do not align with HTTP/2 DATA frames in either direction — a frame
//! may arrive split across several reads, and several may arrive in one — so
//! this is the only place allowed to assume anything about where they begin.

use bytes::{BufMut, Bytes, BytesMut};

/// Larger than any message this service has a use for.
///
/// The ceiling has to live here. The runtime bounds an ordinary request body
/// because it hashes it, but a stream is never hashed and never buffered, so
/// nothing upstream is counting: the guest is the only thing between a client
/// and an allocation as large as it cares to claim.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Malformed {
    /// We advertise no compression, so a frame claiming it is a client bug.
    Compressed,
    TooLarge(usize),
}

impl std::fmt::Display for Malformed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Malformed::Compressed => write!(f, "compressed frames are not accepted"),
            Malformed::TooLarge(n) => {
                write!(f, "a {n} byte message exceeds the {MAX_MESSAGE_BYTES} byte limit")
            }
        }
    }
}

/// Wrap one encoded message for the wire.
pub fn frame(message: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(5 + message.len());
    out.put_u8(0);
    out.put_u32(message.len() as u32);
    out.put_slice(message);
    out.freeze()
}

/// Reassembles messages from however the bytes happen to arrive.
#[derive(Debug, Default)]
pub struct Deframer {
    buffer: BytesMut,
}

impl Deframer {
    pub fn push(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// The next complete message, if one has fully arrived.
    pub fn next(&mut self) -> Result<Option<Bytes>, Malformed> {
        if self.buffer.len() < 5 {
            return Ok(None);
        }
        if self.buffer[0] != 0 {
            return Err(Malformed::Compressed);
        }
        let len = u32::from_be_bytes(self.buffer[1..5].try_into().expect("five bytes")) as usize;
        if len > MAX_MESSAGE_BYTES {
            return Err(Malformed::TooLarge(len));
        }
        if self.buffer.len() < 5 + len {
            return Ok(None);
        }
        let _prefix = self.buffer.split_to(5);
        Ok(Some(self.buffer.split_to(len).freeze()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_framed_message_deframes_to_itself() {
        let mut d = Deframer::default();
        d.push(&frame(b"hello"));
        assert_eq!(d.next().unwrap().as_deref(), Some(&b"hello"[..]));
        assert_eq!(d.next().unwrap(), None);
    }

    /// The case that makes this a deframer rather than a parser: a message
    /// split across reads, which is the normal state of affairs on the wire.
    #[test]
    fn a_message_split_across_reads_is_reassembled() {
        let whole = frame(b"split me");
        let mut d = Deframer::default();
        d.push(&whole[..3]);
        assert_eq!(d.next().unwrap(), None, "three bytes is not a message");
        d.push(&whole[3..7]);
        assert_eq!(d.next().unwrap(), None, "still short of the payload");
        d.push(&whole[7..]);
        assert_eq!(d.next().unwrap().as_deref(), Some(&b"split me"[..]));
    }

    #[test]
    fn several_messages_in_one_read_all_come_out() {
        let mut d = Deframer::default();
        let mut buf = Vec::new();
        buf.extend_from_slice(&frame(b"one"));
        buf.extend_from_slice(&frame(b"two"));
        d.push(&buf);
        assert_eq!(d.next().unwrap().as_deref(), Some(&b"one"[..]));
        assert_eq!(d.next().unwrap().as_deref(), Some(&b"two"[..]));
        assert_eq!(d.next().unwrap(), None);
    }

    #[test]
    fn an_oversized_length_is_refused_before_it_is_allocated() {
        let mut d = Deframer::default();
        let mut header = vec![0u8];
        header.extend_from_slice(&(MAX_MESSAGE_BYTES as u32 + 1).to_be_bytes());
        d.push(&header);
        assert_eq!(
            d.next(),
            Err(Malformed::TooLarge(MAX_MESSAGE_BYTES + 1)),
            "the length was believed before it was checked"
        );
    }

    #[test]
    fn a_compressed_frame_is_refused() {
        let mut d = Deframer::default();
        d.push(&[1u8, 0, 0, 0, 1, b'x']);
        assert_eq!(d.next(), Err(Malformed::Compressed));
    }
}
