use anyhow::{Result, anyhow, bail};
use clipboard_rs::{Clipboard, ClipboardContext, ContentFormat, common::RustImage};

use crate::ClipInput;

pub const MAX_IMAGE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_FILES: usize = 128;

pub fn read_native_clipboard() -> Result<ClipInput> {
    let context =
        ClipboardContext::new().map_err(|error| anyhow!("initialize native clipboard: {error}"))?;

    if context.has(ContentFormat::Files) {
        let files = context
            .get_files()
            .map_err(|error| anyhow!("read clipboard file list: {error}"))?;
        if files.is_empty() {
            bail!("clipboard file list is empty");
        }
        if files.len() > MAX_FILES {
            bail!("clipboard file list exceeds the item limit");
        }
        return Ok(ClipInput::Files { uris: files });
    }

    if context.has(ContentFormat::Image) {
        let image = context
            .get_image()
            .map_err(|error| anyhow!("read clipboard image: {error}"))?;
        let png = image
            .to_png()
            .map_err(|error| anyhow!("encode clipboard image as PNG: {error}"))?;
        if png.get_bytes().len() > MAX_IMAGE_BYTES {
            bail!("clipboard image exceeds the byte limit");
        }
        return Ok(ClipInput::ImagePng {
            bytes: png.get_bytes().to_vec(),
        });
    }

    let text = context
        .get_text()
        .map_err(|error| anyhow!("read clipboard text: {error}"))?;
    if text.trim().is_empty() {
        bail!("clipboard contains no supported non-empty content");
    }
    let html = if context.has(ContentFormat::Html) {
        context.get_html().ok().filter(|value| !value.is_empty())
    } else {
        None
    };
    Ok(ClipInput::Text { text, html })
}
