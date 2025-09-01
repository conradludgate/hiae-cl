use std::{
    ops::{Index, IndexMut, ShlAssign},
    slice,
};

use crate::low::AesBlock;

use aead::{
    consts::{U16, U32},
    inout::InOut,
};
use cipher::InOutBuf;
use hybrid_array::Array;

/// * C0: an AES block built from the following bytes in hexadecimal format:
///   { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 }.
const C0: hybrid_array::Array<u8, hybrid_array::sizes::U16> = hybrid_array::Array([
    0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
]);

/// * C1: an AES block built from the following bytes in hexadecimal format:
///   { 0x4a, 0x40, 0x93, 0x82, 0x22, 0x99, 0xf3, 0x1d, 0x00, 0x82, 0xef, 0xa9, 0x8e, 0xc4, 0xe6, 0xc8 }.
const C1: hybrid_array::Array<u8, hybrid_array::sizes::U16> = hybrid_array::Array([
    0x4a, 0x40, 0x93, 0x82, 0x22, 0x99, 0xf3, 0x1d, 0x00, 0x82, 0xef, 0xa9, 0x8e, 0xc4, 0xe6, 0xc8,
]);

/// The state used by HiAE.
pub struct HiAeCore {
    offset: usize,
    s: [AesBlock; 16],
}

impl Clone for HiAeCore {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for HiAeCore {}

impl Index<usize> for HiAeCore {
    type Output = AesBlock;

    fn index(&self, index: usize) -> &Self::Output {
        &self.s[(self.offset.wrapping_add(index)) % 16]
    }
}

impl IndexMut<usize> for HiAeCore {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.s[(self.offset.wrapping_add(index)) % 16]
    }
}

impl ShlAssign<usize> for HiAeCore {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn shl_assign(&mut self, rhs: usize) {
        self.offset += rhs;
    }
}

#[rustfmt::skip]
macro_rules! duff16 {
    ($i:ident, $body:expr) => {
        if $i == 16 { $body; $i -= 1; }
        if $i == 15 { $body; $i -= 1; }
        if $i == 14 { $body; $i -= 1; }
        if $i == 13 { $body; $i -= 1; }
        if $i == 12 { $body; $i -= 1; }
        if $i == 11 { $body; $i -= 1; }
        if $i == 10 { $body; $i -= 1; }
        if $i == 9 { $body; $i -= 1; }
        if $i == 8 { $body; $i -= 1; }
        if $i == 7 { $body; $i -= 1; }
        if $i == 6 { $body; $i -= 1; }
        if $i == 5 { $body; $i -= 1; }
        if $i == 4 { $body; $i -= 1; }
        if $i == 3 { $body; $i -= 1; }
        if $i == 2 { $body; $i -= 1; }
        if $i == 1 { $body; $i -= 1; }
        debug_assert_eq!($i, 0);
    };
}

trait Buffer: Sized {
    type Inner<'a>: Sized
    where
        Self: 'a;
    fn len(&self) -> usize;
    fn split_at(self, at: usize) -> (Self, Self);
    fn get(&mut self, index: usize) -> Self::Inner<'_>;
}

impl<T> Buffer for &[T] {
    type Inner<'a>
        = &'a T
    where
        Self: 'a;

    fn len(&self) -> usize {
        <[T]>::len(self)
    }

    fn split_at(self, at: usize) -> (Self, Self) {
        self.split_at(at)
    }

    fn get(&mut self, index: usize) -> &T {
        &self[index]
    }
}

impl<T> Buffer for InOutBuf<'_, '_, T> {
    type Inner<'a>
        = InOut<'a, 'a, T>
    where
        Self: 'a;

    fn len(&self) -> usize {
        self.len()
    }

    fn split_at(self, at: usize) -> (Self, Self) {
        self.split_at(at)
    }

    fn get(&mut self, index: usize) -> InOut<'_, '_, T> {
        self.get(index)
    }
}

macro_rules! chunked {
    ($s:expr, $chunks:expr, |$block:ident| $expr:expr) => {{
        $s.offset %= 16;

        let mut i = 16 - $s.offset;
        while i < Buffer::len(&$chunks) {
            let n = i;
            let (mut batch, rest) = Buffer::split_at($chunks, i);

            duff16!(i, {
                $s.offset = 16 - i;
                let $block = Buffer::get(&mut batch, n - i);
                $expr;
            });
            $s.offset = 16 - i;

            $chunks = rest;
            i = 16;
        }

        let n = Buffer::len(&$chunks);
        let mut batch = $chunks;
        for i in 0..n {
            let $block = Buffer::get(&mut batch, i);
            $expr;
        }
    }};
}

impl HiAeCore {
    #[inline(always)]
    pub fn new(key: &Array<u8, U32>, iv: &Array<u8, U16>) -> Self {
        // k0, k1 = Split(key, 128)

        let (k0, k1) = key.split_ref();
        let k0 = AesBlock::from_block(k0);
        let k1 = AesBlock::from_block(k1);
        let nonce = AesBlock::from_block(iv);
        let c0 = AesBlock::from_block(&C0);
        let c1 = AesBlock::from_block(&C1);
        let zero = AesBlock::from_block(&Default::default());

        // S0 = C0
        // S1 = k1
        // S2 = nonce
        // S3 = C0
        // S4 = ZeroPad({ 0 }, 128)
        // S5 = nonce ^ k0
        // S6 = ZeroPad({ 0 }, 128)
        // S7 = C1
        // S8 = nonce ^ k1
        // S9 = ZeroPad({ 0 }, 128)
        // S10 = k1
        // S11 = C0
        // S12 = C1
        // S13 = k1
        // S14 = ZeroPad({ 0 }, 128)
        // S15 = C0 ^ C1
        let s = [
            c0,
            k1,
            nonce,
            c0,
            zero,
            nonce ^ k0,
            zero,
            c1,
            nonce ^ k1,
            zero,
            k1,
            c0,
            c1,
            k1,
            zero,
            c0 ^ c1,
        ];
        let mut this = Self { s, offset: 0 };

        // Diffuse(C0)
        this.diffuse(c0);

        // S9 =  S9 ^ k0
        // S13 = S13 ^ k1
        this[9] ^= k0;
        this[13] ^= k1;

        this
    }

    #[inline(never)]
    pub fn encrypt_empty_block(&mut self, block: &mut Array<u8, U16>) {
        let t = (self[0] ^ self[1]).aesl();
        let ci = t ^ self[9];
        self[0] = self[13].aes(t);

        *self <<= 1;

        *block = ci.into();
    }

    #[inline(always)]
    fn encrypt_block(&mut self, block: InOut<'_, '_, Array<u8, U16>>) {
        // t = AESL(S0 ^ S1) ^ mi
        // ci = t ^ S9
        // S0 = AESL(S13) ^ t
        // S3 =  S3 ^ mi
        // S13 = S13 ^ mi
        // Rol()

        let xi = AesBlock::from_block(block.get_in());
        let t = (self[0] ^ self[1]).aes(xi);
        self[0] = self[13].aes(t);
        self[3] ^= xi;
        self[13] ^= xi;

        *block.into_out() = (t ^ self[9]).into();

        *self <<= 1;
    }

    #[inline(never)]
    fn encrypt_blocks(&mut self, mut chunks: InOutBuf<'_, '_, Array<u8, U16>>) {
        chunked!(self, chunks, |b| self.encrypt_block(b))
    }

    #[inline(always)]
    pub fn encrypt_buf(&mut self, buf: InOutBuf<'_, '_, u8>) {
        let (chunks, tail) = buf.into_chunks();

        self.encrypt_blocks(chunks);
        if !tail.is_empty() {
            let len = tail.len();
            let mut msg_chunk = Array::default();
            msg_chunk[..len].copy_from_slice(tail.get_in());
            self.encrypt_blocks(InOutBuf::from(slice::from_mut(&mut msg_chunk)));
            tail.into_out().copy_from_slice(&msg_chunk[..len]);
        }
    }

    #[inline(never)]
    pub fn decrypt_buf(&mut self, buf: InOutBuf<'_, '_, u8>) {
        let (chunks, tail) = buf.into_chunks();

        self.decrypt_blocks(chunks);
        if !tail.is_empty() {
            let len = tail.len();
            let mut msg_chunk = Array::default();
            msg_chunk[..len].copy_from_slice(tail.get_in());
            self.decrypt_partial_block(InOut::from(&mut msg_chunk), len);
            tail.into_out().copy_from_slice(&msg_chunk[..len]);
        }
    }

    #[inline(never)]
    pub fn decrypt_blocks(&mut self, mut chunks: InOutBuf<'_, '_, Array<u8, U16>>) {
        chunked!(self, chunks, |b| self.decrypt_block(b))
    }

    #[inline(never)]
    fn decrypt_block(&mut self, block: InOut<'_, '_, Array<u8, U16>>) {
        // t = ci ^ S9
        // mi = AESL(S0 ^ S1) ^ t
        // S0 = AESL(S13) ^ t
        // S3 =  S3 ^ mi
        // S13 = S13 ^ mi
        // Rol()

        let ci = AesBlock::from_block(block.get_in());
        let t = ci ^ self[9];
        let mi = (self[0] ^ self[1]).aes(t);
        self[0] = self[13].aes(t);
        self[3] ^= mi;
        self[13] ^= mi;

        *self <<= 1;

        *block.into_out() = mi.into();
    }

    fn decrypt_partial_block(&mut self, padded_block: InOut<'_, '_, Array<u8, U16>>, len: usize) {
        // # Step 1: Recover the keystream that would encrypt a full zero block
        // ks = AESL(S0 ^ S1) ^ ZeroPad(cn) ^ S9
        let cn = AesBlock::from_block(padded_block.get_in());
        let ks: Array<u8, U16> = (self[0] ^ self[1]).aes(cn ^ self[9]).into();

        // # Step 2: Construct a full 128-bit ciphertext block
        // # by appending the appropriate keystream bits
        // ci = cn || Tail(ks, 128 - |cn|)
        let mut ci: Array<u8, U16> = cn.into();
        ci[len..].copy_from_slice(&ks[len..]);
        let ci = AesBlock::from_block(&ci);

        // # Step 3: Decrypt the full block using standard UpdateDec
        // mi = UpdateDec(ci)

        // # Step 4: Extract only the decrypted bytes corresponding to the partial input
        // mn = Truncate(mi, |cn|)

        let t = ci ^ self[9];
        let mi = (self[0] ^ self[1]).aes(t);
        self[0] = self[13].aes(t);
        self[3] ^= mi;
        self[13] ^= mi;

        *self <<= 1;

        *padded_block.into_out() = mi.into();
    }

    #[inline(never)]
    pub fn finalize(mut self, ad_len_bits: u64, msg_len_bits: u64) -> [u8; 16] {
        // t = (LE64(ad_len_bits) || LE64(msg_len_bits))
        // Diffuse(t)

        // tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6 ^ S7 ^
        //     S8 ^ S9 ^ S10 ^ S11 ^ S12 ^ S13 ^ S14 ^ S15

        let mut t = Array([0; 16]);
        t[..8].copy_from_slice(&ad_len_bits.to_le_bytes());
        t[8..].copy_from_slice(&msg_len_bits.to_le_bytes());
        self.diffuse(AesBlock::from_block(&t));
        self.fold_tag().into()
    }

    #[inline(always)]
    fn absorb_block(&mut self, ad: &Array<u8, U16>) {
        self.update(AesBlock::from_block(ad));
    }

    // #[inline(never)]
    // pub fn absorb_blocks2(&mut self, mut chunks: &[Array<u8, U16>]) {
    //     chunks.iter().for_each(|b| self.absorb_block(b));
    // }

    // #[inline(never)]
    // pub fn absorb_blocks_16(&mut self, mut chunks: &[[Array<u8, U16>; 16]]) {
    //     self.offset = 0;
    //     for chunks in chunks {
    //         self.absorb_block(&chunks[0]);
    //         self.absorb_block(&chunks[1]);
    //         self.absorb_block(&chunks[2]);
    //         self.absorb_block(&chunks[3]);
    //         self.absorb_block(&chunks[4]);
    //         self.absorb_block(&chunks[5]);
    //         self.absorb_block(&chunks[6]);
    //         self.absorb_block(&chunks[7]);
    //         self.absorb_block(&chunks[8]);
    //         self.absorb_block(&chunks[9]);
    //         self.absorb_block(&chunks[10]);
    //         self.absorb_block(&chunks[11]);
    //         self.absorb_block(&chunks[12]);
    //         self.absorb_block(&chunks[13]);
    //         self.absorb_block(&chunks[14]);
    //         self.absorb_block(&chunks[15]);
    //     }
    // }

    #[inline(never)]
    pub fn absorb_blocks(&mut self, mut chunks: &[Array<u8, U16>]) {
        chunked!(self, chunks, |b| self.absorb_block(b))
        // let (prefix, chunks) = chunks.split_at(chunks.len().min((16 - self.offset % 16) % 16));
        // let (chunks, suffix) = chunks.as_chunks::<16>();

        // self.absorb_blocks2(prefix);
        // self.absorb_blocks_16(chunks);
        // self.absorb_blocks2(suffix);
    }

    #[inline(always)]
    pub fn absorb_buf(&mut self, buf: &[u8]) {
        let (chunks, tail) = Array::slice_as_chunks(buf);
        self.absorb_blocks(chunks);

        if !tail.is_empty() {
            let len = tail.len();
            let mut msg_chunk = Array::default();
            msg_chunk[..len].copy_from_slice(tail);
            self.absorb_blocks(slice::from_ref(&msg_chunk));
        }
    }

    #[inline(always)]
    fn diffuse(&mut self, xi: AesBlock) {
        for _ in 0..2 {
            let mut i = 16;
            duff16!(i, self.update(xi));
        }
    }

    #[inline(always)]
    fn update(&mut self, xi: AesBlock) {
        // t = AESL(S0 ^ S1) ^ xi
        // S0 = AESL(S13) ^ t
        // S3 =  S3 ^ xi
        // S13 = S13 ^ xi
        // Rol()

        let t = (self[0] ^ self[1]).aes(xi);
        self[0] = self[13].aes(t);
        self[3] ^= xi;
        self[13] ^= xi;
        *self <<= 1;
    }

    #[inline(always)]
    fn fold_tag(self) -> AesBlock {
        let [
            s0,
            s1,
            s2,
            s3,
            s4,
            s5,
            s6,
            s7,
            s8,
            s9,
            s10,
            s11,
            s12,
            s13,
            s14,
            s15,
        ] = self.s;

        s0 ^ s1 ^ s2 ^ s3 ^ s4 ^ s5 ^ s6 ^ s7 ^ s8 ^ s9 ^ s10 ^ s11 ^ s12 ^ s13 ^ s14 ^ s15
    }
}

// #[cfg(test)]
// mod tests {
//     use hex_literal::hex;
//     use hybrid_array::Array;
//     use hybrid_array::sizes::U16;

//     use crate::low::AesBlock;

//     use super::State;

//     /// <https://www.ietf.org/archive/id/draft-pham-cfrg-hiae-02.html#appendix-B.4>
//     #[test]
//     #[rustfmt::skip]
//     fn init() {
//         let state = State::new(
//             &hex!(
//                 "0123456789abcdef0123456789abcdef
//                 0123456789abcdef0123456789abcdef"
//             ).into(),
//             &hex!("00112233445566778899aabbccddeeff").into(),
//         );

//         let s: [[u8; 16]; 16] = state.s.map(|b| b.into());
//         assert_eq!(s, [
//             hex!("3f8a2b5c9d4e7a1b6c2d9e5f3a8b4c7d"),
//             hex!("e2c8d5f6a3b7914e7d8c2b6a5f9e3d4c"),
//             hex!("7a4b6e9d2c5f8b3a1d4e7c9b6a5f3e2d"),
//             hex!("d5f8c2b6a9e3b7d14c5a8f2e6d9b3c7a"),
//             hex!("1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e"),
//             hex!("a8b7c6d5e4f3029184736251a0b9c8d7"),
//             hex!("5e6d7c8b9a0f1e2d3c4b5a6978879695"),
//             hex!("c2d3e4f506172839a4b5c6d7e8f90102"),
//             hex!("9a8b7c6d5e4f30214132243546576879"),
//             hex!("0123456789abcdef0123456789abcdef"),
//             hex!("7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4"),
//             hex!("e5f607182930a4b5c6d7e8f901234567"),
//             hex!("3c4d5e6f708192a3b4c5d6e7f8091a2b"),
//             hex!("ccddeeff00112233445566778899aabb"),
//             hex!("a7b8c9d0e1f20314253647589a6b7c8d"),
//             hex!("2a3b4c5d6e7f809102143526a7b8c9d0"),
//         ])
//     }

//     /// <https://www.ietf.org/archive/id/draft-pham-cfrg-hiae-02.html#appendix-B.3.1>
//     #[test]
//     #[rustfmt::skip]
//     fn update() {
//         let s = [
//             hex!("7cc0a8cc3b5f3fbce67c59a0c8e64f23"),
//             hex!("0123456789abcdef0123456789abcdef"),
//             hex!("00112233445566778899aabbccddeeff"),
//             hex!("7cc0a8cc3b5f3fbce67c59a0c8e64f23"),
//             hex!("00000000000000000000000000000000"),
//             hex!("01224466ccfeaa88899abcfe01224466"),
//             hex!("00000000000000000000000000000000"),
//             hex!("d3d0e4c0f95c1d6b3e3dc8c7a6f90001"),
//             hex!("00112233ccddeeff00112233ccddeeff"),
//             hex!("00000000000000000000000000000000"),
//             hex!("0123456789abcdef0123456789abcdef"),
//             hex!("7cc0a8cc3b5f3fbce67c59a0c8e64f23"),
//             hex!("d3d0e4c0f95c1d6b3e3dc8c7a6f90001"),
//             hex!("0123456789abcdef0123456789abcdef"),
//             hex!("00000000000000000000000000000000"),
//             hex!("af104c0cc2f3228758410ff26f1f4e22"),
//         ];
//         let mut state = State {
//             i: 0,
//             s: s.map(|s| AesBlock::from_block(&s.into())),
//         };

//         let input = hex!("48656c6c000000000000000000000000");
//         state.update(AesBlock::from_block(&input.into()));

//         assert_eq!(state.i, 1);

//         let s: [[u8; 16]; 16] = state.s.map(|b| b.into());

//         // assert_eq!(s[0], hex!("8a5b7f2c4d9e1a3f6b8c2d5e9f3a7b4c"));

//         assert_eq!(s, [
//             hex!("8a5b7f2c4d9e1a3f6b8c2d5e9f3a7b4c"),
//             hex!("0123456789abcdef0123456789abcdef"),
//             hex!("00112233445566778899aabbccddeeff"),
//             hex!("344582a03b5f3fbce67c59a0c8e64f23"),
//             hex!("00000000000000000000000000000000"),
//             hex!("01224466ccfeaa88899abcfe01224466"),
//             hex!("00000000000000000000000000000000"),
//             hex!("d3d0e4c0f95c1d6b3e3dc8c7a6f90001"),
//             hex!("00112233ccddeeff00112233ccddeeff"),
//             hex!("00000000000000000000000000000000"),
//             hex!("0123456789abcdef0123456789abcdef"),
//             hex!("7cc0a8cc3b5f3fbce67c59a0c8e64f23"),
//             hex!("d3d0e4c0f95c1d6b3e3dc8c7a6f90001"),
//             hex!("494608236b9ae1a30123456789abcdef"),
//             hex!("00000000000000000000000000000000"),
//             hex!("af104c0cc2f3228758410ff26f1f4e22"),
//         ]);
//     }
// }
