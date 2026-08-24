#[cfg(feature = "bluetooth")]
pub mod bluetooth;
pub mod clipboard;
pub mod embedding;
mod key_store;
pub mod model;
pub mod proximity;
pub mod store;

pub use embedding::{EmbeddingEngine, HashEmbedding};
pub use model::{ClipInput, ClipKind, StoredClip};
pub use store::{HistoryStore, SearchHit};
