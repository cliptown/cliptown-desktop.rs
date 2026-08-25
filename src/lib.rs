pub mod clipboard;
pub mod embedding;
mod key_store;
pub mod model;
pub mod store;

pub use embedding::{EmbeddingEngine, HashEmbedding};
pub use model::{ClipInput, ClipKind, StoredClip};
pub use store::{HistoryStore, SearchHit};
