use std::{path::Path, sync::Once};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, Transaction, params, types::Type};
use sha2::{Digest, Sha256};
use sqlite_vec::sqlite3_vec_init;
use uuid::Uuid;

use crate::{ClipInput, ClipKind, EmbeddingEngine, StoredClip, embedding::as_le_bytes};

const DEFAULT_HISTORY_LIMIT: usize = 500;
const MIN_HISTORY_LIMIT: usize = 1;
const MAX_HISTORY_LIMIT: usize = 100_000;
const MAX_TEXT_BYTES: usize = 1024 * 1024;
const MAX_IMAGE_BYTES: usize = 8 * 1024 * 1024;

static REGISTER_SQLITE_VEC: Once = Once::new();

pub struct HistoryStore<E = crate::HashEmbedding> {
    connection: Connection,
    embedding: E,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SearchHit {
    pub clip: StoredClip,
    pub distance: f64,
}

impl HistoryStore<crate::HashEmbedding> {
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_embedding(path, crate::HashEmbedding)
    }

    pub fn open_in_memory() -> Result<Self> {
        register_sqlite_vec();
        Self::open_connection(Connection::open_in_memory()?, crate::HashEmbedding)
    }
}

impl<E: EmbeddingEngine> HistoryStore<E> {
    pub fn open_with_embedding(path: &Path, embedding: E) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("create application data directory {}", parent.display())
            })?;
        }
        register_sqlite_vec();
        Self::open_connection(Connection::open(path)?, embedding)
    }

    fn open_connection(connection: Connection, embedding: E) -> Result<Self> {
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA trusted_schema = OFF;",
        )?;
        let mut store = Self {
            connection,
            embedding,
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&mut self) -> Result<()> {
        let transaction = self.connection.transaction()?;
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS settings (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             ) STRICT;
             CREATE TABLE IF NOT EXISTS clips (
                 id TEXT PRIMARY KEY,
                 kind TEXT NOT NULL CHECK (kind IN ('text', 'image', 'files')),
                 title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 512),
                 text_content TEXT,
                 html_content TEXT,
                 image_png BLOB,
                 file_uris_json TEXT NOT NULL DEFAULT '[]',
                 content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
                 pinned INTEGER NOT NULL DEFAULT 0 CHECK (pinned IN (0, 1)),
                 created_at TEXT NOT NULL,
                 last_used_at TEXT NOT NULL,
                 CHECK (
                    (kind = 'text' AND text_content IS NOT NULL AND image_png IS NULL)
                    OR (kind = 'image' AND image_png IS NOT NULL AND text_content IS NULL)
                    OR (kind = 'files' AND image_png IS NULL AND text_content IS NULL)
                 )
             ) STRICT;
             CREATE INDEX IF NOT EXISTS clips_recency_idx
                 ON clips (pinned DESC, last_used_at DESC, id);
             CREATE TABLE IF NOT EXISTS clip_embeddings (
                 clip_id TEXT PRIMARY KEY REFERENCES clips(id) ON DELETE CASCADE,
                 model_id TEXT NOT NULL,
                 dimensions INTEGER NOT NULL CHECK (dimensions BETWEEN 1 AND 8192),
                 embedding BLOB NOT NULL,
                 created_at TEXT NOT NULL
             ) STRICT;
             CREATE VIRTUAL TABLE IF NOT EXISTS clips_fts USING fts5(
                 clip_id UNINDEXED,
                 title,
                 search_text,
                 tokenize = 'unicode61 remove_diacritics 2'
             );
             PRAGMA user_version = 1;",
        )?;
        transaction.execute(
            "INSERT INTO settings (key, value) VALUES ('history_limit', ?1)
             ON CONFLICT(key) DO NOTHING",
            [DEFAULT_HISTORY_LIMIT.to_string()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn history_limit(&self) -> Result<usize> {
        let raw: String = self.connection.query_row(
            "SELECT value FROM settings WHERE key = 'history_limit'",
            [],
            |row| row.get(0),
        )?;
        parse_history_limit(&raw)
    }

    pub fn set_history_limit(&mut self, limit: usize) -> Result<()> {
        validate_history_limit(limit)?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO settings (key, value) VALUES ('history_limit', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [limit.to_string()],
        )?;
        prune(&transaction, limit)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn insert(&mut self, input: &ClipInput) -> Result<StoredClip> {
        validate_input(input)?;
        let id = Uuid::new_v4();
        let now = Utc::now();
        let title = input.title();
        let search_text = input.search_text();
        let (text, html, image, files) = match input {
            ClipInput::Text { text, html } => {
                (Some(text.as_str()), html.as_deref(), None, "[]".to_owned())
            }
            ClipInput::ImagePng { bytes } => (None, None, Some(bytes.as_slice()), "[]".to_owned()),
            ClipInput::Files { uris } => (None, None, None, serde_json::to_string(uris)?),
        };
        let content_hash = content_hash(input);
        let vector = if search_text.trim().is_empty() {
            None
        } else {
            Some(self.embedding.embed(&search_text))
        };
        let history_limit = self.history_limit()?;
        let transaction = self.connection.transaction()?;

        if let Some(existing_id) = transaction
            .query_row(
                "SELECT id FROM clips WHERE content_sha256 = ?1 ORDER BY last_used_at DESC LIMIT 1",
                [&content_hash],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            transaction.execute(
                "UPDATE clips SET last_used_at = ?1 WHERE id = ?2",
                params![now.to_rfc3339(), existing_id],
            )?;
            let clip = load_one(&transaction, &existing_id)?;
            transaction.commit()?;
            return Ok(clip);
        }

        transaction.execute(
            "INSERT INTO clips (
                 id, kind, title, text_content, html_content, image_png,
                 file_uris_json, content_sha256, created_at, last_used_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)",
            params![
                id.to_string(),
                input.kind().as_str(),
                title,
                text,
                html,
                image,
                files,
                content_hash,
                now.to_rfc3339(),
            ],
        )?;
        transaction.execute(
            "INSERT INTO clips_fts (clip_id, title, search_text) VALUES (?1, ?2, ?3)",
            params![id.to_string(), title, search_text],
        )?;
        if let Some(vector) = vector {
            transaction.execute(
                "INSERT INTO clip_embeddings (
                     clip_id, model_id, dimensions, embedding, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    id.to_string(),
                    self.embedding.model_id(),
                    i64::try_from(self.embedding.dimensions())?,
                    as_le_bytes(&vector),
                    now.to_rfc3339(),
                ],
            )?;
        }
        prune(&transaction, history_limit)?;
        let clip = load_one(&transaction, &id.to_string())?;
        transaction.commit()?;
        Ok(clip)
    }

    pub fn list(&self, limit: usize) -> Result<Vec<StoredClip>> {
        let limit = limit.clamp(1, MAX_HISTORY_LIMIT);
        let mut statement = self.connection.prepare(
            "SELECT id, kind, title, text_content, html_content, image_png,
                    file_uris_json, pinned, created_at, last_used_at
             FROM clips
             ORDER BY pinned DESC, last_used_at DESC, id
             LIMIT ?1",
        )?;
        let rows = statement.query_map([i64::try_from(limit)?], decode_clip)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn text_search(&self, query: &str, limit: usize) -> Result<Vec<StoredClip>> {
        let expression = fts_expression(query);
        if expression.is_empty() {
            return self.list(limit);
        }
        let mut statement = self.connection.prepare(
            "SELECT c.id, c.kind, c.title, c.text_content, c.html_content, c.image_png,
                    c.file_uris_json, c.pinned, c.created_at, c.last_used_at
             FROM clips_fts f
             JOIN clips c ON c.id = f.clip_id
             WHERE clips_fts MATCH ?1
             ORDER BY c.pinned DESC, bm25(clips_fts), c.last_used_at DESC
             LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![expression, i64::try_from(limit.clamp(1, 1000))?],
            decode_clip,
        )?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn vector_search(&self, query: &str, limit: usize) -> Result<Vec<SearchHit>> {
        let vector = self.embedding.embed(query);
        if vector.iter().all(|value| value.abs() <= f32::EPSILON) {
            return Ok(Vec::new());
        }
        let mut statement = self.connection.prepare(
            "SELECT c.id, c.kind, c.title, c.text_content, c.html_content, c.image_png,
                    c.file_uris_json, c.pinned, c.created_at, c.last_used_at,
                    vec_distance_cosine(e.embedding, ?1) AS distance
             FROM clip_embeddings e
             JOIN clips c ON c.id = e.clip_id
             WHERE e.model_id = ?2 AND e.dimensions = ?3
             ORDER BY distance ASC, c.last_used_at DESC
             LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![
                as_le_bytes(&vector),
                self.embedding.model_id(),
                i64::try_from(self.embedding.dimensions())?,
                i64::try_from(limit.clamp(1, 1000))?,
            ],
            |row| {
                Ok(SearchHit {
                    clip: decode_clip(row)?,
                    distance: row.get(10)?,
                })
            },
        )?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn set_pinned(&mut self, id: Uuid, pinned: bool) -> Result<()> {
        let changed = self.connection.execute(
            "UPDATE clips SET pinned = ?1 WHERE id = ?2",
            params![i64::from(pinned), id.to_string()],
        )?;
        if changed != 1 {
            bail!("clip does not exist");
        }
        Ok(())
    }

    pub fn count(&self) -> Result<usize> {
        let value = self
            .connection
            .query_row("SELECT count(*) FROM clips", [], |row| row.get::<_, i64>(0))?;
        usize::try_from(value).context("history count is invalid")
    }

    pub fn embedding_count(&self) -> Result<usize> {
        let value =
            self.connection
                .query_row("SELECT count(*) FROM clip_embeddings", [], |row| {
                    row.get::<_, i64>(0)
                })?;
        usize::try_from(value).context("embedding count is invalid")
    }
}

fn register_sqlite_vec() {
    REGISTER_SQLITE_VEC.call_once(|| {
        // sqlite-vec's supported Rust registration API is an SQLite process-wide
        // C extension callback. This is the only unsafe operation permitted in
        // the crate and runs once before any connection executes application SQL.
        #[allow(unsafe_code, clippy::missing_transmute_annotations)]
        unsafe {
            rusqlite::ffi::sqlite3_auto_extension(Some(std::mem::transmute(
                sqlite3_vec_init as *const (),
            )))
        };
    });
}

fn validate_history_limit(limit: usize) -> Result<()> {
    if !(MIN_HISTORY_LIMIT..=MAX_HISTORY_LIMIT).contains(&limit) {
        bail!("history limit must be between {MIN_HISTORY_LIMIT} and {MAX_HISTORY_LIMIT}");
    }
    Ok(())
}

fn parse_history_limit(raw: &str) -> Result<usize> {
    let value = raw
        .parse::<usize>()
        .context("history limit is not numeric")?;
    validate_history_limit(value)?;
    Ok(value)
}

fn validate_input(input: &ClipInput) -> Result<()> {
    match input {
        ClipInput::Text { text, html } => {
            if text.trim().is_empty() {
                bail!("text clip may not be empty");
            }
            let bytes = text.len() + html.as_deref().map_or(0, str::len);
            if bytes > MAX_TEXT_BYTES {
                bail!("text clip exceeds the byte limit");
            }
        }
        ClipInput::ImagePng { bytes } => {
            if bytes.is_empty() || bytes.len() > MAX_IMAGE_BYTES {
                bail!("image clip is empty or exceeds the byte limit");
            }
            if !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
                bail!("image clip is not a PNG");
            }
        }
        ClipInput::Files { uris } => {
            if uris.is_empty() || uris.len() > 128 {
                bail!("file clip is empty or exceeds the file-count limit");
            }
            if uris
                .iter()
                .any(|uri| uri.len() > 4096 || uri.contains('\0'))
            {
                bail!("file clip contains an invalid URI");
            }
        }
    }
    Ok(())
}

fn content_hash(input: &ClipInput) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.kind().as_str().as_bytes());
    hasher.update([0]);
    match input {
        ClipInput::Text { text, html } => {
            hasher.update(text.as_bytes());
            hasher.update([0]);
            if let Some(html) = html {
                hasher.update(html.as_bytes());
            }
        }
        ClipInput::ImagePng { bytes } => hasher.update(bytes),
        ClipInput::Files { uris } => {
            for uri in uris {
                hasher.update(uri.as_bytes());
                hasher.update([0]);
            }
        }
    }
    hex::encode(hasher.finalize())
}

fn prune(transaction: &Transaction<'_>, limit: usize) -> Result<()> {
    validate_history_limit(limit)?;
    let mut stale = transaction.prepare(
        "SELECT id FROM clips
         WHERE pinned = 0
         ORDER BY last_used_at DESC, id DESC
         LIMIT -1 OFFSET ?1",
    )?;
    let ids = stale
        .query_map([i64::try_from(limit)?], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stale);
    for id in ids {
        transaction.execute("DELETE FROM clips_fts WHERE clip_id = ?1", [&id])?;
        transaction.execute("DELETE FROM clips WHERE id = ?1", [&id])?;
    }
    Ok(())
}

fn load_one(transaction: &Transaction<'_>, id: &str) -> Result<StoredClip> {
    transaction
        .query_row(
            "SELECT id, kind, title, text_content, html_content, image_png,
                    file_uris_json, pinned, created_at, last_used_at
             FROM clips WHERE id = ?1",
            [id],
            decode_clip,
        )
        .map_err(Into::into)
}

fn decode_clip(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredClip> {
    let id_raw = row.get::<_, String>(0)?;
    let kind_raw = row.get::<_, String>(1)?;
    let files_raw = row.get::<_, String>(6)?;
    let created_raw = row.get::<_, String>(8)?;
    let last_used_raw = row.get::<_, String>(9)?;
    Ok(StoredClip {
        id: Uuid::parse_str(&id_raw).map_err(|error| conversion_error(0, Type::Text, error))?,
        kind: ClipKind::parse(&kind_raw).ok_or_else(|| {
            conversion_error(
                1,
                Type::Text,
                std::io::Error::new(std::io::ErrorKind::InvalidData, "unknown clip kind"),
            )
        })?,
        title: row.get(2)?,
        text: row.get(3)?,
        html: row.get(4)?,
        image_png: row.get(5)?,
        file_uris: serde_json::from_str(&files_raw)
            .map_err(|error| conversion_error(6, Type::Text, error))?,
        pinned: row.get::<_, i64>(7)? == 1,
        created_at: DateTime::parse_from_rfc3339(&created_raw)
            .map_err(|error| conversion_error(8, Type::Text, error))?
            .with_timezone(&Utc),
        last_used_at: DateTime::parse_from_rfc3339(&last_used_raw)
            .map_err(|error| conversion_error(9, Type::Text, error))?
            .with_timezone(&Utc),
    })
}

fn conversion_error(
    column: usize,
    kind: Type,
    error: impl std::error::Error + Send + Sync + 'static,
) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(column, kind, Box::new(error))
}

fn fts_expression(query: &str) -> String {
    query
        .split_whitespace()
        .filter(|token| !token.is_empty())
        .map(|token| format!("\"{}\"", token.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" AND ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE_PIXEL_PNG: &[u8] = &[
        137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6,
        0, 0, 0, 31, 21, 196, 137, 0, 0, 0, 13, 73, 68, 65, 84, 8, 215, 99, 248, 207, 192, 240, 31,
        0, 5, 0, 1, 255, 137, 153, 61, 29, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
    ];

    #[test]
    fn stores_and_searches_text_image_and_files() -> Result<()> {
        let mut store = HistoryStore::open_in_memory()?;
        store.insert(&ClipInput::Text {
            text: "alpha skyline deployment".to_owned(),
            html: Some("<p>alpha skyline deployment</p>".to_owned()),
        })?;
        store.insert(&ClipInput::ImagePng {
            bytes: ONE_PIXEL_PNG.to_vec(),
        })?;
        store.insert(&ClipInput::Files {
            uris: vec!["file:///tmp/cliptown-contract.txt".to_owned()],
        })?;

        assert_eq!(store.count()?, 3);
        assert_eq!(store.embedding_count()?, 2);
        assert_eq!(store.text_search("skyline", 10)?.len(), 1);
        assert_eq!(store.text_search("contract", 10)?.len(), 1);
        assert_eq!(store.vector_search("skyline deployment", 10)?.len(), 2);
        Ok(())
    }

    #[test]
    fn configurable_limit_prunes_unpinned_but_preserves_pinned() -> Result<()> {
        let mut store = HistoryStore::open_in_memory()?;
        let pinned = store.insert(&ClipInput::Text {
            text: "keep pinned".to_owned(),
            html: None,
        })?;
        store.set_pinned(pinned.id, true)?;
        for value in ["one", "two", "three"] {
            store.insert(&ClipInput::Text {
                text: value.to_owned(),
                html: None,
            })?;
        }
        store.set_history_limit(2)?;
        assert_eq!(store.count()?, 3);
        assert!(store.list(10)?.iter().any(|clip| clip.id == pinned.id));
        Ok(())
    }

    #[test]
    fn duplicate_capture_updates_recency_without_growing_history() -> Result<()> {
        let mut store = HistoryStore::open_in_memory()?;
        let input = ClipInput::Text {
            text: "same item".to_owned(),
            html: None,
        };
        let first = store.insert(&input)?;
        let second = store.insert(&input)?;
        assert_eq!(first.id, second.id);
        assert_eq!(store.count()?, 1);
        Ok(())
    }

    #[test]
    fn malformed_and_unbounded_inputs_fail_closed() -> Result<()> {
        let mut store = HistoryStore::open_in_memory()?;
        assert!(store.set_history_limit(0).is_err());
        assert!(
            store
                .insert(&ClipInput::ImagePng {
                    bytes: b"not a png".to_vec(),
                })
                .is_err()
        );
        assert!(
            store
                .insert(&ClipInput::Text {
                    text: String::new(),
                    html: None,
                })
                .is_err()
        );
        Ok(())
    }
}
