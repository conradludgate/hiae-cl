use aead::rand_core::{RngCore, SeedableRng};
use divan::Bencher;
use divan::counter::BytesCount;
use rand_xoshiro::Xoshiro512StarStar;

use std::hint::black_box;

fn main() {
    divan::Divan::from_args()
        .sample_size(256)
        .sample_count(512)
        .main();
}

fn rand(rng: &mut impl RngCore) -> Vec<u8> {
    let mut vec = vec![0; 1024 * 1024];
    rng.fill_bytes(&mut vec);
    vec
}

#[divan::bench]
fn hiae_cl(b: Bencher) {
    use aead::{AeadInOut, KeyInit, inout::InOutBuf};
    use hiae_cl::HiAe;

    let key = [0u8; 32];
    let nonce = [0u8; 16];
    let mut rng = Xoshiro512StarStar::seed_from_u64(1);

    b.with_inputs(|| rand(&mut rng))
        .input_counter(|m| BytesCount::of_slice(&m))
        .bench_local_refs(|m| {
            let state = HiAe::new(&black_box(key).into());
            state.encrypt_inout_detached(
                &black_box(nonce).into(),
                &[],
                InOutBuf::from(black_box(&mut **m)),
            )
        });
}
