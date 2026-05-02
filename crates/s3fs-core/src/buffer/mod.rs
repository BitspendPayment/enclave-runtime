//! Buffer-pool layer: per-part dirty bookkeeping (`RangeSet`), part state
//! machine (`PartBuf`), and the memory-bounded `BufferPool`.

pub mod part;
pub mod pool;
pub mod ranges;

pub use part::{PartBuf, PartState};
pub use pool::{BufferPool, PartKey};
pub use ranges::RangeSet;
