use std::path::PathBuf;

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
use cliptown_desktop::{HistoryStore, clipboard::read_native_clipboard};
use directories::ProjectDirs;
#[cfg(feature = "desktop-ui")]
use gpui::{
    App, Application, Bounds, Context, IntoElement, Render, SharedString, Window, WindowBounds,
    WindowOptions, div, prelude::*, px, rgb, size,
};
use serde_json::json;

#[derive(Debug, Parser)]
#[command(name = "cliptown-desktop", version, about)]
struct Arguments {
    #[arg(long, env = "CLIPTOWN_DESKTOP_DATABASE")]
    database: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    CaptureOnce,
    Search {
        query: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    SetHistoryLimit {
        count: usize,
    },
    ContractProbe,
}

#[cfg(feature = "desktop-ui")]
struct HistoryView {
    summary: SharedString,
    rows: Vec<SharedString>,
}

#[cfg(feature = "desktop-ui")]
impl Render for HistoryView {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .flex()
            .flex_col()
            .size_full()
            .bg(rgb(0x071224))
            .text_color(rgb(0xe5edf8))
            .p_6()
            .gap_3()
            .child(
                div()
                    .text_2xl()
                    .font_weight(gpui::FontWeight::BOLD)
                    .child("ClipTown native history"),
            )
            .child(div().text_color(rgb(0x93a4ba)).child(self.summary.clone()))
            .children(self.rows.iter().map(|row| {
                div()
                    .bg(rgb(0x122342))
                    .rounded_lg()
                    .p_3()
                    .child(row.clone())
            }))
    }
}

fn main() -> Result<()> {
    let arguments = Arguments::parse();
    let database = arguments.database.unwrap_or(default_database_path()?);
    match arguments.command {
        Some(Command::CaptureOnce) => {
            let input = read_native_clipboard()?;
            let mut store = HistoryStore::open(&database)?;
            let clip = store.insert(&input)?;
            println!(
                "{}",
                json!({"accepted": true, "clip_id": clip.id, "kind": clip.kind})
            );
        }
        Some(Command::Search { query, limit }) => {
            let store = HistoryStore::open(&database)?;
            let results = store.text_search(&query, limit)?;
            println!("{}", serde_json::to_string_pretty(&results)?);
        }
        Some(Command::SetHistoryLimit { count }) => {
            let mut store = HistoryStore::open(&database)?;
            store.set_history_limit(count)?;
            println!("{}", json!({"history_limit": store.history_limit()?}));
        }
        Some(Command::ContractProbe) => contract_probe()?,
        None => run_window(database)?,
    }
    Ok(())
}

#[cfg(feature = "desktop-ui")]
fn run_window(database: PathBuf) -> Result<()> {
    let store = HistoryStore::open(&database)?;
    let clips = store.list(100)?;
    let summary: SharedString = format!(
        "{} saved • unpinned limit {} • local SQLite FTS + vectors",
        clips.len(),
        store.history_limit()?
    )
    .into();
    let rows = clips
        .into_iter()
        .map(|clip| format!("{}  ·  {}", clip.kind.as_str(), clip.title).into())
        .collect::<Vec<_>>();

    Application::new().run(move |cx: &mut App| {
        let bounds = Bounds::centered(None, size(px(900.0), px(680.0)), cx);
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                titlebar: Some(gpui::TitlebarOptions {
                    title: Some("ClipTown".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            |_, cx| {
                cx.new(|_| HistoryView {
                    summary: summary.clone(),
                    rows: rows.clone(),
                })
            },
        )
        .expect("open ClipTown window");
        cx.activate(true);
    });
    Ok(())
}

#[cfg(not(feature = "desktop-ui"))]
fn run_window(_database: PathBuf) -> Result<()> {
    anyhow::bail!("the desktop window requires the desktop-ui Cargo feature")
}

fn contract_probe() -> Result<()> {
    let mut store = HistoryStore::open_in_memory()?;
    store.set_history_limit(2)?;
    let text_clip = store.insert(&cliptown_desktop::ClipInput::Text {
        text: "contract alpha searchable text".to_owned(),
        html: None,
    })?;
    store.set_pinned(text_clip.id, true)?;
    store.insert(&cliptown_desktop::ClipInput::ImagePng {
        bytes: one_pixel_png(),
    })?;
    store.insert(&cliptown_desktop::ClipInput::Files {
        uris: vec!["file:///cliptown/contract.bin".to_owned()],
    })?;
    let result = json!({
        "contract": "cliptown.local-history.v1",
        "history_limit": store.history_limit()?,
        "stored_items": store.count()?,
        "pinned_items": store.list(10)?.iter().filter(|clip| clip.pinned).count(),
        "text_hits": store.text_search("searchable", 10)?.len(),
        "vector_hits": store.vector_search("alpha searchable", 10)?.len(),
        "embedding_rows": store.embedding_count()?,
        "supports": ["text", "image/png", "file-list"],
    });
    println!("{result}");
    Ok(())
}

fn default_database_path() -> Result<PathBuf> {
    let project = ProjectDirs::from("com", "ClipTown", "ClipTown")
        .context("resolve operating-system application data directory")?;
    Ok(project.data_local_dir().join("history-v1.db"))
}

fn one_pixel_png() -> Vec<u8> {
    vec![
        137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6,
        0, 0, 0, 31, 21, 196, 137, 0, 0, 0, 13, 73, 68, 65, 84, 8, 215, 99, 248, 207, 192, 240, 31,
        0, 5, 0, 1, 255, 137, 153, 61, 29, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
    ]
}
