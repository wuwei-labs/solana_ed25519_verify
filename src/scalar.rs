//! Scalar reduction mod L for Ed25519.
//!
//! L = 2^252 + 27742317777372353535851937790883648493
//!
//! Ported from libsodium's sc25519_reduce (ISC license).

/// Load 3 bytes as little-endian u64
#[inline]
fn load_3(input: &[u8]) -> u64 {
    u64::from(input[0]) | (u64::from(input[1]) << 8) | (u64::from(input[2]) << 16)
}

/// Load 4 bytes as little-endian u64
#[inline]
fn load_4(input: &[u8]) -> u64 {
    u64::from(input[0])
        | (u64::from(input[1]) << 8)
        | (u64::from(input[2]) << 16)
        | (u64::from(input[3]) << 24)
}

/// Reduce a 64-byte value mod L, returning 32 bytes.
///
/// This is used to reduce the SHA-512 hash output in Ed25519 signature verification.
pub fn sc_reduce(s: &[u8; 64]) -> [u8; 32] {
    let mut s0: i64 = 2097151 & load_3(s) as i64;
    let mut s1: i64 = 2097151 & (load_4(&s[2..]) >> 5) as i64;
    let mut s2: i64 = 2097151 & (load_3(&s[5..]) >> 2) as i64;
    let mut s3: i64 = 2097151 & (load_4(&s[7..]) >> 7) as i64;
    let mut s4: i64 = 2097151 & (load_4(&s[10..]) >> 4) as i64;
    let mut s5: i64 = 2097151 & (load_3(&s[13..]) >> 1) as i64;
    let mut s6: i64 = 2097151 & (load_4(&s[15..]) >> 6) as i64;
    let mut s7: i64 = 2097151 & (load_3(&s[18..]) >> 3) as i64;
    let mut s8: i64 = 2097151 & load_3(&s[21..]) as i64;
    let mut s9: i64 = 2097151 & (load_4(&s[23..]) >> 5) as i64;
    let mut s10: i64 = 2097151 & (load_3(&s[26..]) >> 2) as i64;
    let mut s11: i64 = 2097151 & (load_4(&s[28..]) >> 7) as i64;
    let mut s12: i64 = 2097151 & (load_4(&s[31..]) >> 4) as i64;
    let mut s13: i64 = 2097151 & (load_3(&s[34..]) >> 1) as i64;
    let mut s14: i64 = 2097151 & (load_4(&s[36..]) >> 6) as i64;
    let mut s15: i64 = 2097151 & (load_3(&s[39..]) >> 3) as i64;
    let mut s16: i64 = 2097151 & load_3(&s[42..]) as i64;
    let mut s17: i64 = 2097151 & (load_4(&s[44..]) >> 5) as i64;
    let s18: i64 = 2097151 & (load_3(&s[47..]) >> 2) as i64;
    let s19: i64 = 2097151 & (load_4(&s[49..]) >> 7) as i64;
    let s20: i64 = 2097151 & (load_4(&s[52..]) >> 4) as i64;
    let s21: i64 = 2097151 & (load_3(&s[55..]) >> 1) as i64;
    let s22: i64 = 2097151 & (load_4(&s[57..]) >> 6) as i64;
    let s23: i64 = (load_4(&s[60..]) >> 3) as i64;

    // Reduce s23..s18
    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;

    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;

    s9 += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;

    s8 += s20 * 666643;
    s9 += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;

    s7 += s19 * 666643;
    s8 += s19 * 470296;
    s9 += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;

    s6 += s18 * 666643;
    s7 += s18 * 470296;
    s8 += s18 * 654183;
    s9 -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;

    // First carry propagation
    let mut carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    let mut carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    let mut carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;
    let carry12 = (s12 + (1 << 20)) >> 21;
    s13 += carry12;
    s12 -= carry12 << 21;
    let carry14 = (s14 + (1 << 20)) >> 21;
    s15 += carry14;
    s14 -= carry14 << 21;
    let carry16 = (s16 + (1 << 20)) >> 21;
    s17 += carry16;
    s16 -= carry16 << 21;

    let mut carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    let mut carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    let mut carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 << 21;
    let carry13 = (s13 + (1 << 20)) >> 21;
    s14 += carry13;
    s13 -= carry13 << 21;
    let carry15 = (s15 + (1 << 20)) >> 21;
    s16 += carry15;
    s15 -= carry15 << 21;

    // Reduce s17..s12
    s5 += s17 * 666643;
    s6 += s17 * 470296;
    s7 += s17 * 654183;
    s8 -= s17 * 997805;
    s9 += s17 * 136657;
    s10 -= s17 * 683901;

    s4 += s16 * 666643;
    s5 += s16 * 470296;
    s6 += s16 * 654183;
    s7 -= s16 * 997805;
    s8 += s16 * 136657;
    s9 -= s16 * 683901;

    s3 += s15 * 666643;
    s4 += s15 * 470296;
    s5 += s15 * 654183;
    s6 -= s15 * 997805;
    s7 += s15 * 136657;
    s8 -= s15 * 683901;

    s2 += s14 * 666643;
    s3 += s14 * 470296;
    s4 += s14 * 654183;
    s5 -= s14 * 997805;
    s6 += s14 * 136657;
    s7 -= s14 * 683901;

    s1 += s13 * 666643;
    s2 += s13 * 470296;
    s3 += s13 * 654183;
    s4 -= s13 * 997805;
    s5 += s13 * 136657;
    s6 -= s13 * 683901;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    // Second carry propagation
    let mut carry0 = (s0 + (1 << 20)) >> 21;
    s1 += carry0;
    s0 -= carry0 << 21;
    let mut carry2 = (s2 + (1 << 20)) >> 21;
    s3 += carry2;
    s2 -= carry2 << 21;
    let mut carry4 = (s4 + (1 << 20)) >> 21;
    s5 += carry4;
    s4 -= carry4 << 21;
    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;

    let mut carry1 = (s1 + (1 << 20)) >> 21;
    s2 += carry1;
    s1 -= carry1 << 21;
    let mut carry3 = (s3 + (1 << 20)) >> 21;
    s4 += carry3;
    s3 -= carry3 << 21;
    let mut carry5 = (s5 + (1 << 20)) >> 21;
    s6 += carry5;
    s5 -= carry5 << 21;
    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 << 21;

    // Final reduction
    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    // Final carry chain
    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= carry0 << 21;
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= carry1 << 21;
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= carry2 << 21;
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= carry3 << 21;
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= carry4 << 21;
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= carry5 << 21;
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;
    carry11 = s11 >> 21;
    s12 += carry11;
    s11 -= carry11 << 21;

    // One more reduction pass
    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;

    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= carry0 << 21;
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= carry1 << 21;
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= carry2 << 21;
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= carry3 << 21;
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= carry4 << 21;
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= carry5 << 21;
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;

    // Pack result
    let mut out = [0u8; 32];
    out[0] = s0 as u8;
    out[1] = (s0 >> 8) as u8;
    out[2] = ((s0 >> 16) | (s1 << 5)) as u8;
    out[3] = (s1 >> 3) as u8;
    out[4] = (s1 >> 11) as u8;
    out[5] = ((s1 >> 19) | (s2 << 2)) as u8;
    out[6] = (s2 >> 6) as u8;
    out[7] = ((s2 >> 14) | (s3 << 7)) as u8;
    out[8] = (s3 >> 1) as u8;
    out[9] = (s3 >> 9) as u8;
    out[10] = ((s3 >> 17) | (s4 << 4)) as u8;
    out[11] = (s4 >> 4) as u8;
    out[12] = (s4 >> 12) as u8;
    out[13] = ((s4 >> 20) | (s5 << 1)) as u8;
    out[14] = (s5 >> 7) as u8;
    out[15] = ((s5 >> 15) | (s6 << 6)) as u8;
    out[16] = (s6 >> 2) as u8;
    out[17] = (s6 >> 10) as u8;
    out[18] = ((s6 >> 18) | (s7 << 3)) as u8;
    out[19] = (s7 >> 5) as u8;
    out[20] = (s7 >> 13) as u8;
    out[21] = s8 as u8;
    out[22] = (s8 >> 8) as u8;
    out[23] = ((s8 >> 16) | (s9 << 5)) as u8;
    out[24] = (s9 >> 3) as u8;
    out[25] = (s9 >> 11) as u8;
    out[26] = ((s9 >> 19) | (s10 << 2)) as u8;
    out[27] = (s10 >> 6) as u8;
    out[28] = ((s10 >> 14) | (s11 << 7)) as u8;
    out[29] = (s11 >> 1) as u8;
    out[30] = (s11 >> 9) as u8;
    out[31] = (s11 >> 17) as u8;

    out
}

/// Reduce a 32-byte scalar mod L.
///
/// For valid Ed25519 signatures, the s component should already be < L,
/// but this ensures canonical form.
pub fn sc_reduce32(s: &[u8; 32]) -> [u8; 32] {
    // Extend to 64 bytes (pad with zeros) and use sc_reduce
    let mut extended = [0u8; 64];
    extended[..32].copy_from_slice(s);
    sc_reduce(&extended)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sc_reduce_zero() {
        let input = [0u8; 64];
        let output = sc_reduce(&input);
        assert_eq!(output, [0u8; 32]);
    }

    #[test]
    fn test_sc_reduce32_small() {
        // A small value should remain unchanged
        let mut input = [0u8; 32];
        input[0] = 42;
        let output = sc_reduce32(&input);
        assert_eq!(output[0], 42);
        assert_eq!(&output[1..], &[0u8; 31]);
    }
}
