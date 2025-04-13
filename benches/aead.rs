use divan::Bencher;
use divan::counter::BytesCount;

use std::hint::black_box;

fn main() {
    divan::Divan::from_args()
        .sample_size(1000)
        .sample_count(1000)
        .main();
}

#[divan::bench]
fn hiae_cl(b: Bencher) {
    use aead::{AeadInOut, KeyInit, inout::InOutBuf};
    use hiae_cl::HiAe;

    let mut m = vec![0xd0u8; 16384];
    let key = [0u8; 32];
    let nonce = [0u8; 16];

    b.counter(BytesCount::of_slice(&m)).bench_local(|| {
        let state = HiAe::new(&black_box(key).into());
        state.encrypt_inout_detached(
            &black_box(nonce).into(),
            &[],
            InOutBuf::from(black_box(&mut *m)),
        )
    });
}
