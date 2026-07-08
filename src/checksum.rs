//! Internet checksum (RFC 1071) with a u64 accumulator.
//!
//! Drop-in replacement for the `pnet_packet::util` checksum helpers on the
//! hot paths: identical results, but sums 8 bytes per load instead of 2.

use std::net::{Ipv4Addr, Ipv6Addr};

use pnet_packet::ip::IpNextHeaderProtocol;

/// Plain integer sum of `data` interpreted as native-endian u16 words, the
/// last odd byte padded with zero. Carries between words are recovered when
/// folding, per RFC 1071's byte-order independence.
#[inline]
fn sum_ne_words(data: &[u8]) -> u64 {
    let mut sum: u64 = 0;
    let mut chunks = data.chunks_exact(8);
    for chunk in &mut chunks {
        let v = u64::from_ne_bytes(chunk.try_into().unwrap());
        // Split so each addition stays <= 2^33; u16::MAX-sized input then
        // keeps the accumulator far below overflow.
        sum += (v & 0xffff_ffff) + (v >> 32);
    }
    let mut remainder = chunks.remainder();
    if remainder.len() >= 4 {
        sum += u32::from_ne_bytes(remainder[..4].try_into().unwrap()) as u64;
        remainder = &remainder[4..];
    }
    if remainder.len() >= 2 {
        sum += u16::from_ne_bytes(remainder[..2].try_into().unwrap()) as u64;
        remainder = &remainder[2..];
    }
    if let Some(&last) = remainder.first() {
        // The odd trailing byte is the high byte of a big-endian word.
        if cfg!(target_endian = "little") {
            sum += last as u64;
        } else {
            sum += (last as u64) << 8;
        }
    }
    sum
}

/// Subtracts the word at index `skipword` from the exact (unfolded) sum,
/// mirroring pnet's skip-in-loop behavior: a trailing odd byte counts as the
/// last word and is skippable too. Out-of-range skipwords skip nothing.
#[inline]
fn subtract_skipword(sum: u64, data: &[u8], skipword: usize) -> u64 {
    let skip = skipword * 2;
    if skip + 1 < data.len() {
        sum - u16::from_ne_bytes(data[skip..skip + 2].try_into().unwrap()) as u64
    } else if skip + 1 == data.len() {
        let last = data[data.len() - 1] as u64;
        if cfg!(target_endian = "little") {
            sum - last
        } else {
            sum - (last << 8)
        }
    } else {
        sum
    }
}

/// Folds the accumulator to the big-endian one's-complement checksum.
#[inline]
fn finish(mut sum: u64) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let word = if cfg!(target_endian = "little") {
        (sum as u16).swap_bytes()
    } else {
        sum as u16
    };
    !word
}

/// Equivalent to `pnet_packet::util::checksum(data, skipword)`.
pub fn checksum(data: &[u8], skipword: usize) -> u16 {
    if data.is_empty() {
        return 0;
    }
    let sum = subtract_skipword(sum_ne_words(data), data, skipword);
    finish(sum)
}

#[inline]
fn pseudo_header_sum(octets_src: &[u8], octets_dst: &[u8], len: u64, protocol: IpNextHeaderProtocol) -> u64 {
    // Pseudo-header fields as native-endian u16 words, matching the accumulator.
    let mut sum = (protocol.0 as u16).to_be() as u64;
    sum += (((len >> 16) as u16).to_be() as u64) + ((len as u16).to_be() as u64);
    for chunk in octets_src.chunks_exact(4).chain(octets_dst.chunks_exact(4)) {
        sum += u32::from_ne_bytes(chunk.try_into().unwrap()) as u64;
    }
    sum
}

/// Equivalent to `pnet_packet::util::ipv4_checksum(data, skipword, &[], src, dst, protocol)`.
pub fn ipv4_checksum(data: &[u8], skipword: usize, src: &Ipv4Addr, dst: &Ipv4Addr, protocol: IpNextHeaderProtocol) -> u16 {
    let mut sum = pseudo_header_sum(&src.octets(), &dst.octets(), data.len() as u64, protocol);
    sum += sum_ne_words(data);
    sum = subtract_skipword(sum, data, skipword);
    finish(sum)
}

/// Equivalent to `pnet_packet::util::ipv6_checksum(data, skipword, &[], src, dst, protocol)`.
pub fn ipv6_checksum(data: &[u8], skipword: usize, src: &Ipv6Addr, dst: &Ipv6Addr, protocol: IpNextHeaderProtocol) -> u16 {
    let mut sum = pseudo_header_sum(&src.octets(), &dst.octets(), data.len() as u64, protocol);
    sum += sum_ne_words(data);
    sum = subtract_skipword(sum, data, skipword);
    finish(sum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet_packet::ip::IpNextHeaderProtocols;
    use rand::{Rng, RngExt};

    fn random_buf(rng: &mut impl Rng, len: usize) -> Vec<u8> {
        (0..len).map(|_| rng.random()).collect()
    }

    #[test]
    fn matches_pnet_checksum() {
        let mut rng = rand::rng();
        for _ in 0..2000 {
            let len = rng.random_range(0..=1600usize);
            let buf = random_buf(&mut rng, len);
            let skipword = rng.random_range(0..=len / 2 + 1);
            assert_eq!(
                checksum(&buf, skipword),
                pnet_packet::util::checksum(&buf, skipword),
                "len={len} skipword={skipword}"
            );
        }
    }

    #[test]
    fn matches_pnet_ipv4_checksum() {
        let mut rng = rand::rng();
        for _ in 0..2000 {
            let len = rng.random_range(0..=1600usize);
            let buf = random_buf(&mut rng, len);
            let skipword = rng.random_range(0..=len / 2 + 1);
            let src = Ipv4Addr::from(rng.random::<u32>());
            let dst = Ipv4Addr::from(rng.random::<u32>());
            let proto = if rng.random::<bool>() {
                IpNextHeaderProtocols::Tcp
            } else {
                IpNextHeaderProtocols::Udp
            };
            assert_eq!(
                ipv4_checksum(&buf, skipword, &src, &dst, proto),
                pnet_packet::util::ipv4_checksum(&buf, skipword, &[], &src, &dst, proto),
                "len={len} skipword={skipword}"
            );
        }
    }

    #[test]
    fn matches_pnet_ipv6_checksum() {
        let mut rng = rand::rng();
        for _ in 0..2000 {
            let len = rng.random_range(0..=1600usize);
            let buf = random_buf(&mut rng, len);
            let skipword = rng.random_range(0..=len / 2 + 1);
            let src = Ipv6Addr::from(rng.random::<u128>());
            let dst = Ipv6Addr::from(rng.random::<u128>());
            let proto = if rng.random::<bool>() {
                IpNextHeaderProtocols::Tcp
            } else {
                IpNextHeaderProtocols::Udp
            };
            assert_eq!(
                ipv6_checksum(&buf, skipword, &src, &dst, proto),
                pnet_packet::util::ipv6_checksum(&buf, skipword, &[], &src, &dst, proto),
                "len={len} skipword={skipword}"
            );
        }
    }

    #[test]
    fn edge_cases() {
        for (buf, skipword) in [
            (vec![], 0usize),
            (vec![0xab], 0),
            (vec![0xff; 1600], 0),
            (vec![0xff; 1599], 5),
            (vec![0x00; 8], 1),
            (vec![0x00; 7], 1),
            (vec![0x12, 0x34, 0x56], 1),
        ] {
            assert_eq!(
                checksum(&buf, skipword),
                pnet_packet::util::checksum(&buf, skipword),
                "buf.len()={} skipword={skipword}",
                buf.len()
            );
        }
    }
}
