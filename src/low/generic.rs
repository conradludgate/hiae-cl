use std::ops::{BitAnd, BitXor, BitXorAssign};

use hybrid_array::Array;
use hybrid_array::sizes::{U1, U16};

#[derive(Clone, Copy)]
pub struct AesBlock(aes::Block);

impl From<Array<AesBlock, U1>> for AesBlock {
    #[inline(always)]
    fn from(value: Array<AesBlock, U1>) -> Self {
        let Array([AesBlock(a)]) = value;
        AesBlock(a)
    }
}

impl From<AesBlock> for Array<u8, U16> {
    #[inline(always)]
    fn from(val: AesBlock) -> Self {
        val.0
    }
}

impl From<AesBlock> for [u8; 16] {
    #[inline(always)]
    fn from(val: AesBlock) -> Self {
        val.0.into()
    }
}

impl AesBlock {
    #[inline(always)]
    pub fn aesl(self) -> Self {
        self.aes(Self::from_block(&Default::default()))
    }

    #[inline(always)]
    pub fn aes(mut self, key: Self) -> Self {
        aes::hazmat::cipher_round(&mut self.0, &key.0);
        self
    }

    #[inline(always)]
    pub fn from_block(a: &Array<u8, U16>) -> Self {
        Self(*a)
    }
}

impl BitXor for AesBlock {
    type Output = Self;

    #[inline(always)]
    fn bitxor(mut self, rhs: Self) -> Self::Output {
        self ^= rhs;
        self
    }
}

impl BitXorAssign for AesBlock {
    #[inline(always)]
    fn bitxor_assign(&mut self, rhs: Self) {
        for i in 0..16 {
            self.0[i] ^= rhs.0[i];
        }
    }
}

impl BitAnd for AesBlock {
    type Output = Self;

    #[inline(always)]
    fn bitand(mut self, rhs: Self) -> Self::Output {
        for i in 0..16 {
            self.0[i] &= rhs.0[i];
        }
        self
    }
}
