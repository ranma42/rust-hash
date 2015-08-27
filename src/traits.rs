pub trait HashContext {
    type Result;

    fn update(&mut self, bytes: &[u8]);

    // This signature prevents from:
    //  - incorrect usage of `update()` after `finish()` :D
    //  - exposing `reset()` :(
    fn finish(self) -> Self::Result;
}

pub trait HashFunction {
    type Context : HashContext;

    // This function exposes a hash context with the usual
    // (crypto-like) operations
    fn init(&self) -> Self::Context;

    // This function exposes one-shot hashing, more convenient for
    // hashtables
    #[inline(always)]
    fn digest(&self, bytes: &[u8]) -> <Self::Context as HashContext>::Result {
        let mut ctx = self.init();
        ctx.update(bytes);
        ctx.finish()
    }
}

pub trait Hash {
    fn hash<H: HashContext>(&self, ctx: &mut H);

    #[inline]
    fn digest<H: HashFunction>(&self, f: &H) -> <<H as HashFunction>::Context as HashContext>::Result {
        let mut ctx = f.init();
        self.hash(&mut ctx);
        ctx.finish()
    }
}

impl Hash for u8 {
    #[inline(always)]
    fn hash<H: HashContext>(&self, ctx: &mut H) {
        ctx.update(&[*self])
    }
}

impl Hash for [u8] {
    #[inline(always)]
    fn hash<H: HashContext>(&self, ctx: &mut H) {
        ctx.update(self)
    }

    fn digest<H: HashFunction>(&self, f: &H) -> <<H as HashFunction>::Context as HashContext>::Result {
        f.digest(self)
    }
}
