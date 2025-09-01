use std::arch::x86_64::*;
use std::ops::{BitAnd, BitXor, BitXorAssign};

use hybrid_array::Array;
use hybrid_array::sizes::U16;

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct AesBlock(pub(super) __m128i);

impl From<AesBlock> for Array<u8, U16> {
    #[inline(always)]
    fn from(val: AesBlock) -> Self {
        Array(val.into())
    }
}

impl From<AesBlock> for [u8; 16] {
    #[inline(always)]
    fn from(val: AesBlock) -> Self {
        // Safety: both types are equivalent, and transmute does not care about alignment.
        unsafe { core::mem::transmute::<__m128i, [u8; 16]>(val.0) }
    }
}

impl AesBlock {
    #[inline(always)]
    pub fn aesl(self) -> Self {
        self.aes(Self::from_block(&Default::default()))
    }

    #[inline(always)]
    pub fn aes(self, key: Self) -> Self {
        // Safety: we require target_feature = "aes".
        Self(unsafe { _mm_aesenc_si128(self.0, key.0) })
    }

    #[inline(always)]
    pub fn from_block(a: &Array<u8, U16>) -> Self {
        // Safety: both types are equivalent, and transmute does not care about alignment.
        AesBlock(unsafe { core::mem::transmute::<[u8; 16], __m128i>(a.0) })
    }
}

impl BitXor for AesBlock {
    type Output = Self;

    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self::Output {
        // Safety: we require target_feature = "aes".
        // I think aes implies sse2???
        Self(unsafe { _mm_xor_si128(self.0, rhs.0) })
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
        // I think aes implies sse2???
        Self(unsafe { _mm_and_si128(self.0, rhs.0) })
    }
}
