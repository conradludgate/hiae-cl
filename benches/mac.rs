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
    use digest::{Mac, crypto_common::KeyIvInit};
    use hiae_cl::HiAeMac;

    let m = vec![0xd0u8; 65536];
    let key = [0u8; 32];

    b.counter(BytesCount::of_slice(&m)).bench_local(|| {
        let mut state = HiAeMac::new(&black_box(key).into(), &[0u8; 16].into());
        state.update(black_box(&m));
        black_box(state.finalize());
    });
}
