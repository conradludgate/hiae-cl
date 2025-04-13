use aead::{
    AeadCore, AeadInOut, Key, KeyInit, KeySizeUser, Nonce,
    inout::{InOut, InOutBuf},
};
use cipher::{BlockSizeUser, ParBlocksSizeUser, typenum::Unsigned};
use digest::{
    FixedOutput, MacMarker, OutputSizeUser, Update,
    block_buffer::{BlockBuffer, Eager},
    crypto_common::{Iv, IvSizeUser, KeyIvInit},
};
use hybrid_array::sizes::{U1, U16, U32};
use hybrid_array::{Array, ArraySize};
use subtle::ConstantTimeEq;

use crate::mid::HiAeCore;

/// The HiAE "high-throughput" authenticated encryption.
pub struct HiAe(Array<u8, U32>);

impl KeySizeUser for HiAe {
    type KeySize = U32;
}

impl KeyInit for HiAe {
    #[inline(always)]
    fn new(key: &Key<Self>) -> Self {
        Self(*key)
    }
}

impl AeadCore for HiAe {
    type NonceSize = U16;
    type TagSize = U16;

    const TAG_POSITION: aead::TagPosition = aead::TagPosition::Postfix;
}

impl AeadInOut for HiAe {
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> aead::Result<aead::Tag<Self>> {
        // P_MAX (maximum length of the plaintext) is 2^61 - 1 bytes (2^64 - 8 bits).
        // A_MAX (maximum length of the associated data) is 2^61 - 1 bytes (2^64 - 8 bits).
        let msg_len_bits = bits(buffer.len())?;
        let ad_len_bits = bits(associated_data.len())?;

        // Init(key, nonce)
        let mut state = HiAeCore::new(&self.0, nonce);

        // msg_blocks = Split(ZeroPad(msg, 128), 128)
        // for ai in ad_blocks:
        //     Absorb(ai)
        process_chunks_padded(associated_data, |ad_chunk| {
            state.absorb(ad_chunk);
        });

        // msg_blocks = Split(ZeroPad(msg, R), R)
        // for xi in msg_blocks:
        //     ct = ct || Enc(xi)
        let (xt_blocks, mut xn) = buffer.into_chunks();
        for xi in xt_blocks {
            state.encrypt_block(xi);
        }
        if !xn.is_empty() {
            let len = xn.len();
            let mut msg_chunk = Array::default();
            msg_chunk[..len].copy_from_slice(xn.get_in());
            state.encrypt_block(InOut::from(&mut msg_chunk));
            xn.get_out().copy_from_slice(&msg_chunk[..len]);
        }

        // tag = Finalize(|ad|, |msg|)
        // ct = Truncate(ct, |msg|)

        // return ct and tag
        Ok(state.finalize(ad_len_bits, msg_len_bits).into())
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        mut buffer: InOutBuf<'_, '_, u8>,
        tag: &aead::Tag<Self>,
    ) -> aead::Result<()> {
        // P_MAX (maximum length of the plaintext) is 2^61 - 1 bytes (2^64 - 8 bits).
        // A_MAX (maximum length of the associated data) is 2^61 - 1 bytes (2^64 - 8 bits).
        let msg_len_bits = bits(buffer.len())?;
        let ad_len_bits = bits(associated_data.len())?;

        // Init(key, nonce)
        let mut state = HiAeCore::new(&self.0, nonce);

        // ad_blocks = Split(ZeroPad(ad, R), R)
        // for ai in ad_blocks:
        //     Absorb(ai)
        process_chunks_padded(associated_data, |ad_chunk| {
            state.absorb(ad_chunk);
        });

        // ct_blocks = Split(ct, R)
        // cn = Tail(ct, |ct| mod R)
        let (ct_blocks, cn) = buffer.reborrow().into_chunks();

        // for ci in ct_blocks:
        //     msg = msg || Dec(ci)
        for ci in ct_blocks {
            state.decrypt_block(ci);
        }

        // if cn is not empty:
        //     msg = msg || DecPartial(cn)
        if !cn.is_empty() {
            decrypt_partial(&mut state, cn);
        }

        // expected_tag = Finalize(|ad|, |msg|)
        let expected_tag = state.finalize(ad_len_bits, msg_len_bits);

        // if CtEq(tag, expected_tag) is False:
        //     erase msg
        //     erase expected_tag
        //     return "verification failed" error
        // else:
        //     return msg

        if expected_tag.ct_ne(tag).into() {
            // re-encrypt the buffer to prevent revealing the plaintext.
            self.encrypt_inout_detached(nonce, associated_data, InOutBuf::from(buffer.get_out()))
                .unwrap();
            Err(aead::Error)
        } else {
            Ok(())
        }
    }
}

fn decrypt_partial(state: &mut HiAeCore, mut tail: InOutBuf<'_, '_, u8>) {
    let len = tail.len();
    let mut msg_chunk = Array::default();
    msg_chunk[..len].copy_from_slice(tail.get_in());
    state.decrypt_partial_block(InOut::from(&mut msg_chunk), len);
    tail.get_out().copy_from_slice(&msg_chunk[..len]);
}

fn process_chunks_padded<T: ArraySize>(data: &[u8], mut f: impl FnMut(&Array<u8, T>)) {
    let (chunks, tail) = Array::slice_as_chunks(data);
    for ad_chunk in chunks {
        f(ad_chunk);
    }
    if !tail.is_empty() {
        let mut chunk = Array::default();
        chunk[..tail.len()].copy_from_slice(tail);
        f(&chunk);
    }
}

#[inline]
fn bits(bytes: usize) -> aead::Result<u64> {
    u64::try_from(bytes)
        .ok()
        .and_then(|b| b.checked_mul(8))
        .ok_or(aead::Error)
}

/// The AEGIS family of message authentication code algorithms.
pub struct HiAeMac {
    state: HiAeCore,
    blocks: BlockBuffer<U16, Eager>,
    data_len_bits: u64,
}

impl Clone for HiAeMac {
    fn clone(&self) -> Self {
        Self {
            state: self.state,
            blocks: self.blocks.clone(),
            data_len_bits: self.data_len_bits,
        }
    }
}

impl KeySizeUser for HiAeMac {
    type KeySize = U32;
}

impl IvSizeUser for HiAeMac {
    type IvSize = U16;
}

impl KeyIvInit for HiAeMac {
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        Self {
            state: HiAeCore::new(key, iv),
            blocks: BlockBuffer::new(&[]),
            data_len_bits: 0,
        }
    }
}

// Update + FixedOutput + MacMarker
impl MacMarker for HiAeMac {}
impl Update for HiAeMac {
    fn update(&mut self, data: &[u8]) {
        self.data_len_bits = bits(data.len())
            .ok()
            .and_then(|b| self.data_len_bits.checked_add(b))
            .expect("data length in bits should not overflow u64");

        self.blocks.digest_blocks(data, |blocks| {
            blocks.iter().for_each(|block| self.state.absorb(block));
        });
    }
}

impl OutputSizeUser for HiAeMac {
    type OutputSize = U16;
}

impl FixedOutput for HiAeMac {
    fn finalize_into(mut self, out: &mut digest::Output<Self>) {
        if self.blocks.get_pos() > 0 {
            self.state.absorb(&self.blocks.pad_with_zeros());
        }
        *out = self.state.finalize(self.data_len_bits, 0).into()
    }
}

pub type HiAeStream = cipher::StreamCipherCoreWrapper<HiAeStreamCore>;
pub struct HiAeStreamCore {
    state: HiAeCore,
    blocks: u64,
}

impl KeySizeUser for HiAeStreamCore {
    type KeySize = U32;
}

impl IvSizeUser for HiAeStreamCore {
    type IvSize = U16;
}

impl KeyIvInit for HiAeStreamCore {
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        Self {
            state: HiAeCore::new(key, iv),
            blocks: (1u64 << 61) / <U16 as Unsigned>::U64,
        }
    }
}

impl BlockSizeUser for HiAeStreamCore {
    type BlockSize = U16;
}
impl ParBlocksSizeUser for HiAeStreamCore {
    type ParBlocksSize = U1;
}

impl cipher::StreamCipherCore for HiAeStreamCore {
    fn remaining_blocks(&self) -> Option<usize> {
        self.blocks.try_into().ok()
    }

    fn process_with_backend(
        &mut self,
        f: impl cipher::StreamCipherClosure<BlockSize = Self::BlockSize>,
    ) {
        f.call(self);
    }
}

impl cipher::StreamCipherBackend for HiAeStreamCore {
    fn gen_ks_block(&mut self, block: &mut cipher::Block<Self>) {
        self.blocks -= 1;
        self.state.encrypt_empty_block(block);
    }
}
#[cfg(test)]
mod tests {
    use aead::{Aead, Key, KeyInit, Nonce, Payload, Tag};
    use digest::{Mac, crypto_common::KeyIvInit};

    use crate::{HiAeMac, high::HiAe};

    fn test_roundtrip(
        key: Key<HiAe>,
        nonce: Nonce<HiAe>,
        aad: &[u8],
        msg: &[u8],
        ct: &[u8],
        tag: Tag<HiAe>,
    ) {
        let encrypted = HiAe::new(&key)
            .encrypt(&nonce, Payload { aad, msg })
            .unwrap();

        let (actual_ct, actual_tag) = encrypted.split_at(msg.len());
        assert_eq!(actual_ct, ct);
        assert_eq!(actual_tag, tag.as_slice());

        let decrypted = HiAe::new(&key)
            .decrypt(
                &nonce,
                Payload {
                    aad,
                    msg: &encrypted,
                },
            )
            .unwrap();

        assert_eq!(decrypted, msg);
    }

    use hex_literal::hex;
    use hybrid_array::Array;

    #[test]
    /// <https://www.ietf.org/archive/id/draft-pham-cfrg-hiae-02.html#appendix-A.1>
    fn test_vector_1() {
        let key = Array(hex!(
            "4b7a9c3ef8d2165a0b3e5f8c9d4a7b1e
            2c5f8a9d3b6e4c7f0a1d2e5b8c9f4a7d"
        ));
        let nonce = Array(hex!("a5b8c2d9e3f4a7b1c8d5e9f2a3b6c7d8"));
        let ad = hex!("");
        let msg = hex!("");
        let ct = hex!("");
        let tag = Array(hex!("e3b7c5993e804d7e1f95905fe8fa1d74"));

        // with no message, this is equivalent to the MAC.
        HiAeMac::new(&key, &nonce)
            .chain_update(ad)
            .verify(&tag)
            .unwrap();

        test_roundtrip(key, nonce, &ad, &msg, &ct, tag);
    }

    #[test]
    /// <https://www.ietf.org/archive/id/draft-pham-cfrg-hiae-02.html#appendix-A.2>
    fn test_vector_2() {
        let key = Array(hex!(
            "2f8e4d7c3b9a5e1f8d2c6b4a9f3e7d5c
            1b8a6f4e3d2c9b5a8f7e6d4c3b2a1f9e"
        ));
        let nonce = Array(hex!("7c3e9f5a1d8b4c6f2e9a5d7b3f8c1e4a"));
        let ad = hex!("");
        let msg = hex!("55f00fcc339669aa55f00fcc339669aa");
        let ct = hex!("66fc201d96ace3ca550326964c2fa950");
        let tag = Array(hex!("2e4d9b3bf320283de63ea5547454878d"));

        test_roundtrip(key, nonce, &ad, &msg, &ct, tag);
    }

    #[test]
    /// <https://www.ietf.org/archive/id/draft-pham-cfrg-hiae-02.html#appendix-A.3>
    fn test_vector_3() {
        let key = Array(hex!(
            "9f3e7d5c4b8a2f1e9d8c7b6a5f4e3d2c
            1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e"
        ));
        let nonce = Array(hex!("3d8c7f2a5b9e4c1f8a6d3b7e5c2f9a4d"));
        let ad = hex!(
            "394a5b6c7d8e9fb0c1d2e3f405162738
            495a6b7c8d9eafc0d1e2f30415263748"
        );
        let msg = hex!();
        let ct = hex!();
        let tag = Array(hex!("531a4d1ed47bda55d01cc510512099e4"));

        // with no message, this is equivalent to the MAC.
        HiAeMac::new(&key, &nonce)
            .chain_update(ad)
            .verify(&tag)
            .unwrap();

        test_roundtrip(key, nonce, &ad, &msg, &ct, tag);
    }

    #[test]
    /// <https://www.ietf.org/archive/id/draft-pham-cfrg-hiae-02.html#appendix-A.4>
    fn test_vector_4() {
        let key = Array(hex!(
            "6c8f2d5a9e3b7f4c1d8a5e9f3c7b2d6a
            4f8e1c9b5d3a7e2f4c8b6d9a1e5f3c7d"
        ));
        let nonce = Array(hex!("9a5c7e3f1b8d4a6c2e9f5b7d3a8c1e6f"));
        let ad = hex!();
        let msg = hex!(
            "ffffffffffffffffffffffffffffffff
            ffffffffffffffffffffffffffffffff
            ffffffffffffffffffffffffffffffff
            ffffffffffffffffffffffffffffffff
            ffffffffffffffffffffffffffffffff
            ffffffffffffffffffffffffffffffff
            ffffffffffffffffffffffffffffffff
            ffffffffffffffffffffffffffffffff
            ffffffffffffffffffffffffffffffff
            ffffffffffffffffffffffffffffffff
            ffffffffffffffffffffffffffffffff
            ffffffffffffffffffffffffffffffff
            ffffffffffffffffffffffffffffffff
            ffffffffffffffffffffffffffffffff
            ffffffffffffffffffffffffffffffff
            ffffffffffffffffffffffffffffffff"
        );
        let ct = hex!(
            "2e28f49c20d1a90a5bce3bc85f6eab2f
            e0d3ee31c293f368ee20e485ec732c90
            45633aa4d53e271b1f583f4f0b208487
            6e4b0d2b2f633433e43c48386155d03d
            00dbf10c07a66159e1bec7859839263a
            c12e77045c6d718ddf5907297818e4ae
            0b4ed7b890f57fa585e4a5940525aa2f
            62e4b6748fa4cd86b75f69eff9dfd4df
            9b0861ae7d52541ff892aa41d41d55a9
            a62f4e4fefb718ee13faca582d73c1d1
            f51592c25c64b0a79d2f24181362dfbb
            352ac20e1b07be892a05b394eb6b2a9d
            473c49e6b63e754311fdbb6c476503f0
            a3570482ece70856ae6e6f8d5aa19cc2
            7b5bce24ee028e197ed9891b0a54bf02
            328cb80ceefc44b11043d784594226ab"
        );
        let tag = Array(hex!("f330ae219d6739aba556fe94776b486b"));

        test_roundtrip(key, nonce, &ad, &msg, &ct, tag);
    }

    #[test]
    /// <https://www.ietf.org/archive/id/draft-pham-cfrg-hiae-02.html#appendix-A.5>
    fn test_vector_5() {
        let key = Array(hex!(
            "3e9d6c5b4a8f7e2d1c9b8a7f6e5d4c3b
            2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d"
        ));
        let nonce = Array(hex!("6f2e8a5c9b3d7f1e4a8c5b9d3f7e2a6c"));
        let ad = hex!("6778899aabbccddeef00112233445566");
        let msg = hex!(
            "cc339669aa55f00fcc339669aa55f00f
            cc339669aa55f00fcc339669aa55f00f
            cc339669aa55f00fcc339669aa55f00f
            cc339669aa55f00fcc339669aa55f00f
            cc339669aa55f00fcc339669aa55f00f
            cc339669aa55f00fcc339669aa55f00f
            cc339669aa55f00fcc339669aa55f00f
            cc339669aa55f00fcc339669aa55f00f
            cc339669aa55f00fcc339669aa55f00f
            cc339669aa55f00fcc339669aa55f00f
            cc339669aa55f00fcc339669aa55f00f
            cc339669aa55f00fcc339669aa55f00f
            cc339669aa55f00fcc339669aa55f00f
            cc339669aa55f00fcc339669aa55f00f
            cc339669aa55f00fcc339669aa55f00f
            cc339669aa55f00fcc339669aa55f00f
            cc"
        );
        let ct = hex!(
            "5d2d2c7f1ff780687c65ed69c08805c2
            69652b55f5d1ef005f25300d1f644b57
            e500d5b0d75f9b025fee04cfdf422c6c
            3c472e6967ac60f69ff730d4d308faed
            beac375ae88da8ab78d26e496a5226b5
            ffd7834a2f76ecc495a444ffa3db60d8
            ec3fb75c0fcaa74966e1caec294c8eb7
            a4895aa2b1e3976eb6bed2f975ff218d
            c98f86f7c95996f03842cee71c6c1bc5
            f7b64374e101b32927ed95432e88f8e3
            8835f1981325dbcec412a4254e964c22
            cf82688ee5e471c23a3537de7e51c288
            92e32c565aa86ab708c70cf01f0d0ee9
            781251759893d55e60e0d70014cb3afb
            45e0821ba6e82e0f490ff2efef2f62c5
            7332c68c11e6ed71ef730b62c3e05edf
            f6"
        );
        let tag = Array(hex!("1122dc5bedc7cad4e196f7227b7102f3"));

        test_roundtrip(key, nonce, &ad, &msg, &ct, tag);
    }

    #[test]
    /// <https://www.ietf.org/archive/id/draft-pham-cfrg-hiae-02.html#appendix-A.6>
    fn test_vector_6() {
        let key = Array(hex!(
            "8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d
            2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f"
        ));
        let nonce = Array(hex!("4d8b2f6a9c3e7f5d1b8a4c6e9f3d5b7a"));
        let ad = hex!();
        let msg = hex!(
            "00000000000000000000000000000000
            00000000000000000000000000000000
            00000000000000000000000000000000
            00000000000000000000000000000000
            00000000000000000000000000000000
            00000000000000000000000000000000
            00000000000000000000000000000000
            00000000000000000000000000000000
            00000000000000000000000000000000
            00000000000000000000000000000000
            00000000000000000000000000000000
            00000000000000000000000000000000
            00000000000000000000000000000000
            00000000000000000000000000000000
            00000000000000000000000000000000
            000000000000000000000000000000"
        );
        let ct = hex!(
            "322970ad70b2af87676d57dd0b27866d
            8c4f0e251b5162b93672de1ab7aaf20c
            d91e7751a31e19762aeea4f3811657a3
            06787ff4ebc06957c1f45b7fd284ef87
            f3a902922999895ff26fddbd5986eac5
            ef856f6ae270136315c698ec7fe5a618
            8aa1847c00a3a870044e8d37e22b1bca
            b3e493d8ae984c7646f2536032a40910
            b6c0f317b916d5789189268c00ef4493
            bcb5fb0135974fa9bec299d473fdbf76
            f44107ec56b5941404fd4b3352576c31
            3169662f1664bd5bccf210a710aa6665
            fb3ec4fa3b4c648411fd09d4cada31b8
            947fdd486de45a4e4a33c151364e23be
            6b3fc14f0855b0518e733d5ea9051165
            25286bb2d6a46ac8ef73144e2046f9"
        );
        let tag = Array(hex!("7eb4461a035fe51eaf4a1829605e6227"));

        test_roundtrip(key, nonce, &ad, &msg, &ct, tag);
    }

    #[test]
    /// <https://www.ietf.org/archive/id/draft-pham-cfrg-hiae-02.html#appendix-A.7>
    fn test_vector_7() {
        let key = Array(hex!(
            "5d9c3b7a8f2e6d4c1b9a8f7e6d5c4b3a
            2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c"
        ));
        let nonce = Array(hex!("8c5a7d3f9b1e6c4a2f8d5b9e3c7a1f6d"));
        let ad = hex!(
            "95a6b7c8d9eafb0c1d2e3f5061728394
            a5b6c7d8e9fa0b1c2d3e4f60718293a4
            b5c6d7e8f90a1b2c3d4e5f708192a3b4
            c5d6e7f8091a2b3c4d5e6f8091a2b3c4"
        );
        let msg = hex!(
            "32e14453e7a776781d4c4e2c3b23bca2
            441ee4213bc3df25021b5106c22c98e8
            a7b310142252c8dcff70a91d55cdc910
            3c1eccd9b5309ef21793a664e0d4b63c
            83530dcd1a6ad0feda6ff19153e9ee62
            0325c1cb979d7b32e54f41da3af1c169
            a24c47c1f6673e115f0cb73e8c507f15
            eedf155261962f2d175c9ba3832f4933
            fb330d28ad6aae787f12788706f45c92
            e72aea146959d2d4fa01869f7d072a7b
            f43b2e75265e1a000dde451b64658919
            e93143d2781955fb4ca2a38076ac9eb4
            9adc2b92b05f0ec7"
        );
        let ct = hex!(
            "ca3b18f0ffb25e4e1a6108abedcfc931
            841804c22a132a701d2f0b5eb845a380
            8028e9e1e0978795776c57a0415971cf
            e87abc72171a24fd11f3c331d1efe306
            e4ca1d8ede6e79cbd531020502d38026
            20d9453ffdd5633fe98ff1d12b057edd
            bd4d99ee6cabf4c8d2c9b4c7ee0d219b
            3b4145e3c63acde6c45f6d65e08dd06e
            f9dd2dde090f1f7579a5657720f348ae
            5761a8df321f20ad711a2c703b1c3f20
            0e4004da409daaa138f3c20f8f77c89c
            b6f46df671f25c75a6a7838a5d792d18
            a59c202fab564f0f"
        );
        let tag = Array(hex!("74ba4c28296f09101db59c37c4759bcf"));

        test_roundtrip(key, nonce, &ad, &msg, &ct, tag);
    }

    #[test]
    /// <https://www.ietf.org/archive/id/draft-pham-cfrg-hiae-02.html#appendix-A.8>
    fn test_vector_8() {
        let key = Array(hex!(
            "7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e
            1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a"
        ));
        let nonce = Array(hex!("2e7c9f5d3b8a4c6f1e9b5d7a3f8c2e4a"));
        let ad = hex!();
        let msg = hex!("ff");
        let ct = hex!("51");
        let tag = Array(hex!("588535eb70c53ba5cce0d215194cb1c9"));

        test_roundtrip(key, nonce, &ad, &msg, &ct, tag);
    }

    #[test]
    /// <https://www.ietf.org/archive/id/draft-pham-cfrg-hiae-02.html#appendix-A.9>
    fn test_vector_9() {
        let key = Array(hex!(
            "4c8b7a9f3e5d2c6b1a8f9e7d6c5b4a3f
            2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b"
        ));
        let nonce = Array(hex!("7e3c9a5f1d8b4e6c2a9f5d7b3e8c1a4f"));
        let ad = hex!(
            "c3d4e5f60718293a4b5c6d7e8fa0b1c2
            d3e4f5061728394a5b6c7d8e9fb0c1d2
            e3f405162738495a6b7c8d9eafc0d1e2"
        );
        let msg = hex!(
            "aa55f00fcc339669aa55f00fcc339669
            aa55f00fcc339669aa55f00fcc339669"
        );
        let ct = hex!(
            "03694107097ff7ea0b1eac408fabb60a
            cd89df4d0288fa9063309e5e323bf78f"
        );
        let tag = Array(hex!("2a3144f369a893c3d756f262067e5e59"));

        test_roundtrip(key, nonce, &ad, &msg, &ct, tag);
    }

    #[test]
    /// <https://www.ietf.org/archive/id/draft-pham-cfrg-hiae-02.html#appendix-A.10>
    fn test_vector_10() {
        let key = Array(hex!(
            "9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b
            3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d"
        ));
        let nonce = Array(hex!("5f9d3b7e2c8a4f6d1b9e5c7a3d8f2b6e"));
        let ad = hex!("daebfc0d1e2f405162738495a6b7c8d9");
        let msg = hex!(
            "00000000000000000000000000000000
            00000000000000000000000000000000
            00000000000000000000000000000000
            00000000000000000000000000000000
            00000000000000000000000000000000
            00000000000000000000000000000000
            00000000000000000000000000000000
            00000000000000000000000000000000"
        );
        let ct = hex!(
            "eef78d00c4de4c557d5c769e499af7b9
            8e5ad36cdaf1ff775a8629d82751e97e
            8f98caa0773fe81ee40266f0d52ddbbe
            f621504863bf39552682b29748f8c244
            5c176cd63865732141edc59073cff90e
            5996a23a763f8dd058a6a91ada1d8f83
            2f5e600b39f799a698228b68d20cd189
            e5e423b253a44c78060435050698ccae"
        );
        let tag = Array(hex!("59970b0b35a7822f3b88b63396c2da98"));

        test_roundtrip(key, nonce, &ad, &msg, &ct, tag);
    }
}
