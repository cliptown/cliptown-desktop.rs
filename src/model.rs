use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipKind {
    Text,
    Image,
    Files,
}

impl ClipKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Image => "image",
            Self::Files => "files",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "text" => Some(Self::Text),
            "image" => Some(Self::Image),
            "files" => Some(Self::Files),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClipInput {
    Text { text: String, html: Option<String> },
    ImagePng { bytes: Vec<u8> },
    Files { uris: Vec<String> },
}

impl ClipInput {
    pub const fn kind(&self) -> ClipKind {
        match self {
            Self::Text { .. } => ClipKind::Text,
            Self::ImagePng { .. } => ClipKind::Image,
            Self::Files { .. } => ClipKind::Files,
        }
    }

    pub fn title(&self) -> String {
        match self {
            Self::Text { text, .. } => {
                let first = text.lines().next().unwrap_or_default().trim();
                truncate_chars(if first.is_empty() { "Text clip" } else { first }, 72)
            }
            Self::ImagePng { .. } => "Clipboard image".to_owned(),
            Self::Files { uris } if uris.len() == 1 => uris[0]
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or("File")
                .to_owned(),
            Self::Files { uris } => format!("{} files", uris.len()),
        }
    }

    pub fn search_text(&self) -> String {
        match self {
            Self::Text { text, .. } => text.clone(),
            Self::ImagePng { .. } => String::new(),
            Self::Files { uris } => uris.join(" "),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StoredClip {
    pub id: Uuid,
    pub kind: ClipKind,
    pub title: String,
    pub text: Option<String>,
    pub html: Option<String>,
    #[serde(skip_serializing)]
    pub image_png: Option<Vec<u8>>,
    pub file_uris: Vec<String>,
    pub pinned: bool,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
}

fn truncate_chars(value: &str, max: usize) -> String {
    let mut chars = value.chars();
    let prefix: String = chars.by_ref().take(max).collect();
    if chars.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}
