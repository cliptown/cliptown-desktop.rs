pub const EMBEDDING_DIMENSIONS: usize = 384;

pub trait EmbeddingEngine {
    fn model_id(&self) -> &'static str;
    fn dimensions(&self) -> usize;
    fn embed(&self, text: &str) -> Vec<f32>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct HashEmbedding;

impl EmbeddingEngine for HashEmbedding {
    fn model_id(&self) -> &'static str {
        "cliptown-hash-v1"
    }

    fn dimensions(&self) -> usize {
        EMBEDDING_DIMENSIONS
    }

    fn embed(&self, text: &str) -> Vec<f32> {
        let mut vector = vec![0.0_f32; EMBEDDING_DIMENSIONS];
        for token in text
            .split(|character: char| !character.is_alphanumeric())
            .filter(|token| !token.is_empty())
        {
            let normalized = token.to_lowercase();
            let digest = blake3::hash(normalized.as_bytes());
            let bytes = digest.as_bytes();
            let index =
                usize::from(u16::from_le_bytes([bytes[0], bytes[1]])) % EMBEDDING_DIMENSIONS;
            let sign = if bytes[2] & 1 == 0 { 1.0 } else { -1.0 };
            vector[index] += sign;
        }
        let magnitude = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
        if magnitude > f32::EPSILON {
            for value in &mut vector {
                *value /= magnitude;
            }
        }
        vector
    }
}

pub fn as_le_bytes(vector: &[f32]) -> Vec<u8> {
    vector
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}
