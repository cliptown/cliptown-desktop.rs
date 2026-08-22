pub mod clipboard;
pub mod embedding;
pub mod model;
pub mod store;

pub use embedding::{EmbeddingEngine, HashEmbedding};
pub use model::{ClipInput, ClipKind, StoredClip};
pub use store::{HistoryStore, SearchHit};
