#![feature(test)]
extern crate test;

pub mod traits;
pub mod sip;

use sip::SipHashFunction;
use traits::Hash;

use test::{Bencher,black_box};


// impl Hash for usize {
//     fn hash<H: HashContext>(&self, ctx: &mut H) {
//         let len = std::mem::size_of::<usize>();
//         let ptr = self as *const usize as *const u8;
//         ctx.update(unsafe { std::slice::from_raw_parts(ptr, len) })
//     }
// }

/*
impl<T: Hash> Hash for [T] {
    #[inline(always)]
    fn hash<H: HashContext>(&self, ctx: &mut H) {
        for piece in self {
            piece.hash(ctx)
        }
    }
}
*/

impl<T: std::hash::Hasher> traits::HashContext for T {
    type Result = u64;

    #[inline(always)]
    fn update(&mut self, bytes: &[u8]) {
        std::hash::Hasher::write(self, bytes)
    }

    #[inline(always)]
    fn finish(self) -> u64 {
        std::hash::Hasher::finish(&self)
    }
}

struct OrigSip {
    k0: u64,
    k1: u64,
}

impl traits::HashFunction for OrigSip {
    type Context = std::hash::SipHasher;

    #[inline(always)]
    fn init(&self) -> Self::Context {
        std::hash::SipHasher::new_with_keys(self.k0, self.k1)
    }
}

const ITERS : u64 = 1000;

macro_rules! gen_hash_bench {
    ($name:ident, $v:expr, $b:expr) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            b.iter(|| for _ in 0..ITERS {
                let arg = $v;
                let arg = black_box(arg);
                let mut hasher = std::hash::SipHasher::new_with_keys(7, 39);
                std::hash::Hash::hash(&arg, &mut hasher);
                black_box(std::hash::Hasher::finish(&hasher));
            });
            b.bytes = $b * ITERS;
        }
    }
}

macro_rules! gen_digest_bench {
    ($name:ident, $v:expr, $b:expr, $hash:expr) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            b.iter(|| for _ in 0..ITERS {
                let arg = $v;
                let arg = black_box(arg);
                black_box(arg.digest(&$hash));
            });
            b.bytes = $b * ITERS;
        }
    }
}

gen_hash_bench!{bench_hash_u8,  42u8, 1}
gen_hash_bench!{bench_hash_u8_,  43u8, 1}
gen_hash_bench!{bench_hash_u81, &[42u8; 1], 1}
gen_hash_bench!{bench_hash_u82, &[42u8; 2], 2}
gen_hash_bench!{bench_hash_u87, &[42u8; 7], 7}

gen_digest_bench!{bench_digest_my_u8, 42u8, 1, black_box(SipHashFunction::new_with_keys(7, 39)) }
gen_digest_bench!{bench_digest_my_u8_, 43u8, 1, black_box(SipHashFunction::new_with_keys(7, 39)) }
gen_digest_bench!{bench_digest_my_u81, &[42u8; 1], 1, black_box(SipHashFunction::new_with_keys(7, 39)) }
gen_digest_bench!{bench_digest_my_u82, &[42u8; 2], 2, black_box(SipHashFunction::new_with_keys(7, 39)) }
gen_digest_bench!{bench_digest_my_u87, &[42u8; 7], 7, black_box(SipHashFunction::new_with_keys(7, 39)) }

gen_digest_bench!{bench_digest_orig_u8, 42u8, 1, black_box(OrigSip{k0: 7, k1: 39}) }
gen_digest_bench!{bench_digest_orig_u8_, 43u8, 1, black_box(OrigSip{k0: 7, k1: 39}) }
gen_digest_bench!{bench_digest_orig_u81, &[42u8; 1], 1, black_box(OrigSip{k0: 7, k1: 39}) }
gen_digest_bench!{bench_digest_orig_u82, &[42u8; 2], 2, black_box(OrigSip{k0: 7, k1: 39}) }
gen_digest_bench!{bench_digest_orig_u87, &[42u8; 7], 7, black_box(OrigSip{k0: 7, k1: 39}) }
