use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use std::io;

/// Upper bound on the number of extension headers walked before the packet
/// is rejected, so a malformed chain cannot loop forever.
const MAX_EXTENSION_HEADERS: usize = 8;

/// Result of walking an IPv6 extension-header chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ipv6PayloadInfo {
    /// The upper-layer protocol after all extension headers.
    pub protocol: IpNextHeaderProtocol,
    /// Offset of the upper-layer payload relative to the start of the
    /// IPv6 payload (i.e. right after the 40-byte fixed header).
    pub payload_offset: usize,
    /// Present if the chain contains a Fragment header (RFC 8200 §4.5).
    pub fragment: Option<Ipv6FragmentInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ipv6FragmentInfo {
    pub identification: u32,
    /// Fragment offset in bytes (the 13-bit field is in 8-byte units).
    pub offset: u16,
    pub more_fragments: bool,
}

impl Ipv6FragmentInfo {
    /// An atomic fragment (offset 0, no more fragments) needs no reassembly.
    pub fn is_segmented(&self) -> bool {
        self.offset > 0 || self.more_fragments
    }
}

/// Walks the extension-header chain of an IPv6 packet.
///
/// `first` is the Next Header field of the fixed header and `payload` is
/// everything after the fixed header. Returns `Ok(None)` for No Next Header
/// (the packet carries nothing to deliver). Hop-by-Hop Options, Routing and
/// Destination Options headers are skipped; a Fragment header is recorded.
/// AH/ESP and extension headers located after a Fragment header (they belong
/// to the fragmentable part) are rejected as unsupported.
pub(crate) fn walk_extension_headers(first: IpNextHeaderProtocol, payload: &[u8]) -> io::Result<Option<Ipv6PayloadInfo>> {
    let mut next_header = first;
    let mut offset = 0usize;
    let mut fragment: Option<Ipv6FragmentInfo> = None;
    for _ in 0..=MAX_EXTENSION_HEADERS {
        match next_header {
            IpNextHeaderProtocols::Hopopt | IpNextHeaderProtocols::Ipv6Route | IpNextHeaderProtocols::Ipv6Opts => {
                if fragment.is_some() {
                    // Extension headers in the fragmentable part can only be
                    // interpreted after reassembly of the original packet.
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "ipv6 extension header after fragment header",
                    ));
                }
                let rest = &payload[offset..];
                if rest.len() < 8 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated ipv6 extension header"));
                }
                // Hdr Ext Len is in 8-byte units, not counting the first 8 bytes.
                let header_len = (rest[1] as usize + 1) * 8;
                if rest.len() < header_len {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated ipv6 extension header"));
                }
                next_header = IpNextHeaderProtocol(rest[0]);
                offset += header_len;
            }
            IpNextHeaderProtocols::Ipv6Frag => {
                if fragment.is_some() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "multiple ipv6 fragment headers"));
                }
                let Some(rest) = payload.get(offset..offset + 8) else {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated ipv6 fragment header"));
                };
                let offset_flags = u16::from_be_bytes([rest[2], rest[3]]);
                fragment = Some(Ipv6FragmentInfo {
                    identification: u32::from_be_bytes([rest[4], rest[5], rest[6], rest[7]]),
                    // The high 13 bits are the offset in 8-byte units, so
                    // masking the flag/reserved bits yields the byte offset.
                    offset: offset_flags & !0b111,
                    more_fragments: offset_flags & 0b1 == 0b1,
                });
                next_header = IpNextHeaderProtocol(rest[0]);
                offset += 8;
            }
            IpNextHeaderProtocols::Ipv6NoNxt => return Ok(None),
            IpNextHeaderProtocols::Ah | IpNextHeaderProtocols::Esp => {
                // AH lengths are in 4-byte units and ESP hides the rest of the
                // chain, so neither can be skipped like a plain extension header.
                return Err(io::Error::new(io::ErrorKind::Unsupported, "ipv6 AH/ESP is unsupported"));
            }
            protocol => {
                return Ok(Some(Ipv6PayloadInfo {
                    protocol,
                    payload_offset: offset,
                    fragment,
                }));
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "too many ipv6 extension headers"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extension(next_header: u8, len_units: u8) -> Vec<u8> {
        let mut header = vec![0u8; (len_units as usize + 1) * 8];
        header[0] = next_header;
        header[1] = len_units;
        header
    }

    fn fragment_header(next_header: u8, offset: u16, more: bool, id: u32) -> Vec<u8> {
        assert_eq!(offset & 0b111, 0);
        let mut header = vec![0u8; 8];
        header[0] = next_header;
        header[2..4].copy_from_slice(&(offset | more as u16).to_be_bytes());
        header[4..8].copy_from_slice(&id.to_be_bytes());
        header
    }

    #[test]
    fn no_extension_headers() {
        let info = walk_extension_headers(IpNextHeaderProtocols::Tcp, &[0u8; 20]).unwrap().unwrap();
        assert_eq!(info.protocol, IpNextHeaderProtocols::Tcp);
        assert_eq!(info.payload_offset, 0);
        assert!(info.fragment.is_none());
    }

    #[test]
    fn skips_hop_by_hop_routing_and_destination_options() {
        let mut payload = extension(IpNextHeaderProtocols::Ipv6Route.0, 0);
        payload.extend(extension(IpNextHeaderProtocols::Ipv6Opts.0, 1));
        payload.extend(extension(IpNextHeaderProtocols::Udp.0, 0));
        payload.extend([0u8; 12]);
        let info = walk_extension_headers(IpNextHeaderProtocols::Hopopt, &payload).unwrap().unwrap();
        assert_eq!(info.protocol, IpNextHeaderProtocols::Udp);
        assert_eq!(info.payload_offset, 8 + 16 + 8);
        assert!(info.fragment.is_none());
    }

    #[test]
    fn parses_fragment_header() {
        let mut payload = fragment_header(IpNextHeaderProtocols::Udp.0, 1480, true, 0xA1B2C3D4);
        payload.extend([0u8; 32]);
        let info = walk_extension_headers(IpNextHeaderProtocols::Ipv6Frag, &payload).unwrap().unwrap();
        assert_eq!(info.protocol, IpNextHeaderProtocols::Udp);
        assert_eq!(info.payload_offset, 8);
        let fragment = info.fragment.unwrap();
        assert_eq!(fragment.identification, 0xA1B2C3D4);
        assert_eq!(fragment.offset, 1480);
        assert!(fragment.more_fragments);
        assert!(fragment.is_segmented());
    }

    #[test]
    fn parses_last_fragment_after_hop_by_hop() {
        let mut payload = extension(IpNextHeaderProtocols::Ipv6Frag.0, 0);
        payload.extend(fragment_header(IpNextHeaderProtocols::Tcp.0, 2960, false, 7));
        payload.extend([0u8; 8]);
        let info = walk_extension_headers(IpNextHeaderProtocols::Hopopt, &payload).unwrap().unwrap();
        assert_eq!(info.protocol, IpNextHeaderProtocols::Tcp);
        assert_eq!(info.payload_offset, 16);
        let fragment = info.fragment.unwrap();
        assert_eq!(fragment.offset, 2960);
        assert!(!fragment.more_fragments);
        assert!(fragment.is_segmented());
    }

    #[test]
    fn atomic_fragment_is_not_segmented() {
        let payload = fragment_header(IpNextHeaderProtocols::Udp.0, 0, false, 1);
        let info = walk_extension_headers(IpNextHeaderProtocols::Ipv6Frag, &payload).unwrap().unwrap();
        assert!(!info.fragment.unwrap().is_segmented());
    }

    #[test]
    fn no_next_header() {
        assert!(walk_extension_headers(IpNextHeaderProtocols::Ipv6NoNxt, &[]).unwrap().is_none());
        let payload = extension(IpNextHeaderProtocols::Ipv6NoNxt.0, 0);
        assert!(walk_extension_headers(IpNextHeaderProtocols::Hopopt, &payload).unwrap().is_none());
    }

    #[test]
    fn rejects_truncated_extension_header() {
        assert!(walk_extension_headers(IpNextHeaderProtocols::Hopopt, &[0u8; 7]).is_err());
        let payload = extension(IpNextHeaderProtocols::Tcp.0, 3);
        assert!(walk_extension_headers(IpNextHeaderProtocols::Hopopt, &payload[..16]).is_err());
        assert!(walk_extension_headers(IpNextHeaderProtocols::Ipv6Frag, &[0u8; 7]).is_err());
    }

    #[test]
    fn rejects_extension_header_after_fragment_header() {
        let mut payload = fragment_header(IpNextHeaderProtocols::Ipv6Opts.0, 0, true, 9);
        payload.extend(extension(IpNextHeaderProtocols::Tcp.0, 0));
        let err = walk_extension_headers(IpNextHeaderProtocols::Ipv6Frag, &payload).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn rejects_ah_and_esp() {
        let err = walk_extension_headers(IpNextHeaderProtocols::Ah, &[0u8; 24]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        let err = walk_extension_headers(IpNextHeaderProtocols::Esp, &[0u8; 24]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn rejects_too_many_extension_headers() {
        let mut payload = Vec::new();
        for _ in 0..MAX_EXTENSION_HEADERS + 1 {
            payload.extend(extension(IpNextHeaderProtocols::Hopopt.0, 0));
        }
        payload.extend(extension(IpNextHeaderProtocols::Tcp.0, 0));
        let err = walk_extension_headers(IpNextHeaderProtocols::Hopopt, &payload).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
