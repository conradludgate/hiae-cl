use std::arch::aarch64::*;
use std::ops::{BitAnd, BitXor, BitXorAssign};

use hybrid_array::Array;
use hybrid_array::sizes::U16;

#[derive(Clone, Copy)]
pub struct AesBlock(uint8x16_t);

impl From<AesBlock> for Array<u8, U16> {
    #[inline(always)]
    fn from(val: AesBlock) -> Self {
        Array(val.into())
    }
}

impl From<AesBlock> for [u8; 16] {
    #[inline(always)]
    fn from(val: AesBlock) -> Self {
        let mut out = [0; 16];
        // Safety: we require target_feature = "aes".
        // I think this implies neon.
        unsafe { vst1q_u8(out.as_mut_ptr(), val.0) }
        out
    }
}

impl AesBlock {
    #[inline(always)]
    pub fn aesl(self) -> Self {
        // Safety: we require target_feature = "aes".
        // I think this implies neon.
        let zero = unsafe { vmovq_n_u8(0) };
        // Safety: we require target_feature = "aes".
        let enc = unsafe { vaeseq_u8(self.0, zero) };
        // Safety: we require target_feature = "aes".
        let mixed = unsafe { vaesmcq_u8(enc) };
        Self(mixed)
    }

    #[inline(always)]
    pub fn aes(self, key: Self) -> Self {
        self.aesl() ^ key
    }

    #[inline(always)]
    pub fn from_block(a: &Array<u8, U16>) -> Self {
        // Safety: both types are equivalent, and transmute does not care about alignment.
        AesBlock(unsafe { core::mem::transmute::<[u8; 16], uint8x16_t>(a.0) })
    }
}

impl BitXor for AesBlock {
    type Output = Self;

    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self::Output {
        // Safety: we require target_feature = "aes".
        // I think this implies neon.
        Self(unsafe { veorq_u8(self.0, rhs.0) })
    }
}

impl BitXorAssign for AesBlock {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl BitAnd for AesBlock {
    type Output = Self;

    #[inline(always)]
    fn bitand(self, rhs: Self) -> Self::Output {
        // Safety: we require target_feature = "aes".
        // I think this implies neon.
        Self(unsafe { vandq_u8(self.0, rhs.0) })
    }
}
