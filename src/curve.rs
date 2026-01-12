//! Edwards curve operations for Ed25519 signature verification.
//!
//! For BPF (target_os = "solana"): Uses Solana syscalls
//! For native: Uses curve25519-dalek (only compiled for non-BPF targets)

/// A 32-byte Edwards point (compressed Y coordinate).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct PodEdwardsPoint(pub [u8; 32]);

/// A 32-byte scalar value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct PodScalar(pub [u8; 32]);

// ============================================================================
// BPF implementation using Solana syscalls
// ============================================================================
#[cfg(target_os = "solana")]
mod target_arch {
    use super::*;

    const CURVE25519_EDWARDS: u64 = 0;
    const SUB: u64 = 1;
    const MUL: u64 = 2;

    extern "C" {
        fn sol_curve_validate_point(curve_id: u64, point: *const u8, result: *mut u8) -> u64;
        fn sol_curve_group_op(
            curve_id: u64,
            op_id: u64,
            left: *const u8,
            right: *const u8,
            result: *mut u8,
        ) -> u64;
    }

    pub fn validate_edwards(point: &PodEdwardsPoint) -> bool {
        let mut validate_result = 0u8;
        let result =
            unsafe { sol_curve_validate_point(CURVE25519_EDWARDS, point.0.as_ptr(), &mut validate_result) };
        result == 0
    }

    pub fn subtract_edwards(
        left_point: &PodEdwardsPoint,
        right_point: &PodEdwardsPoint,
    ) -> Option<PodEdwardsPoint> {
        let mut result_point = PodEdwardsPoint([0u8; 32]);
        let result = unsafe {
            sol_curve_group_op(
                CURVE25519_EDWARDS,
                SUB,
                left_point.0.as_ptr(),
                right_point.0.as_ptr(),
                result_point.0.as_mut_ptr(),
            )
        };

        if result == 0 {
            Some(result_point)
        } else {
            None
        }
    }

    pub fn multiply_edwards(
        scalar: &PodScalar,
        point: &PodEdwardsPoint,
    ) -> Option<PodEdwardsPoint> {
        let mut result_point = PodEdwardsPoint([0u8; 32]);
        let result = unsafe {
            sol_curve_group_op(
                CURVE25519_EDWARDS,
                MUL,
                scalar.0.as_ptr(),
                point.0.as_ptr(),
                result_point.0.as_mut_ptr(),
            )
        };

        if result == 0 {
            Some(result_point)
        } else {
            None
        }
    }
}

// ============================================================================
// Native implementation using curve25519-dalek (for tests)
// ============================================================================
#[cfg(not(target_os = "solana"))]
mod target_arch {
    use super::*;
    use curve25519_dalek::{
        edwards::{CompressedEdwardsY, EdwardsPoint},
        scalar::Scalar,
    };

    pub fn validate_edwards(point: &PodEdwardsPoint) -> bool {
        let Ok(compressed) = CompressedEdwardsY::from_slice(&point.0) else {
            return false;
        };
        compressed.decompress().is_some()
    }

    pub fn subtract_edwards(
        left_point: &PodEdwardsPoint,
        right_point: &PodEdwardsPoint,
    ) -> Option<PodEdwardsPoint> {
        let left = decompress_point(left_point)?;
        let right = decompress_point(right_point)?;
        let result = &left - &right;
        Some(compress_point(&result))
    }

    pub fn multiply_edwards(
        scalar: &PodScalar,
        point: &PodEdwardsPoint,
    ) -> Option<PodEdwardsPoint> {
        let scalar = Scalar::from_canonical_bytes(scalar.0).into_option()?;
        let point = decompress_point(point)?;
        let result = &scalar * &point;
        Some(compress_point(&result))
    }

    fn decompress_point(pod: &PodEdwardsPoint) -> Option<EdwardsPoint> {
        let compressed = CompressedEdwardsY::from_slice(&pod.0).ok()?;
        compressed.decompress()
    }

    fn compress_point(point: &EdwardsPoint) -> PodEdwardsPoint {
        PodEdwardsPoint(point.compress().to_bytes())
    }
}

pub use target_arch::*;

#[cfg(test)]
mod tests {
    use super::*;

    // Ed25519 base point (compressed)
    const BASE_POINT: PodEdwardsPoint = PodEdwardsPoint([
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ]);

    #[test]
    fn test_validate_base_point() {
        assert!(validate_edwards(&BASE_POINT));
    }

    #[test]
    fn test_validate_invalid_point() {
        // Known invalid point from solana-curve25519 tests
        let invalid = PodEdwardsPoint([
            120, 140, 152, 233, 41, 227, 203, 27, 87, 115, 25, 251, 219, 5, 84, 148, 117, 38, 84,
            60, 87, 144, 161, 146, 42, 34, 91, 155, 158, 189, 121, 79,
        ]);
        assert!(!validate_edwards(&invalid));
    }

    #[test]
    fn test_multiply_by_one() {
        let one = PodScalar({
            let mut bytes = [0u8; 32];
            bytes[0] = 1;
            bytes
        });
        let result = multiply_edwards(&one, &BASE_POINT).unwrap();
        assert_eq!(result, BASE_POINT);
    }
}
