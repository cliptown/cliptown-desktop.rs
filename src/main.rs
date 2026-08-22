use std::path::PathBuf;

use anyhow::{Context as _, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use clap::{Parser, Subcommand};
use cliptown_desktop::{ClipInput, HistoryStore, clipboard::read_native_clipboard};
use directories::ProjectDirs;
#[cfg(feature = "desktop-ui")]
use gpui::{
    App, Application, Bounds, Context, IntoElement, Render, SharedString, Window, WindowBounds,
    WindowOptions, div, prelude::*, px, rgb, size,
};
use serde::Deserialize;
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
    ContractProbe {
        #[arg(long)]
        fixture: Option<PathBuf>,
    },
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
        Some(Command::ContractProbe { fixture }) => contract_probe(fixture.as_deref())?,
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

#[derive(Debug, Deserialize)]
struct ContractFixture {
    contract: String,
    embedding_dimensions: usize,
    history_limit: usize,
    clips: Vec<FixtureClip>,
    lexical_query: String,
    vector_query: String,
    expected: FixtureExpected,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum FixtureClip {
    Text {
        text: String,
        html: Option<String>,
        pinned: bool,
    },
    ImagePng {
        base64: String,
    },
    Files {
        uris: Vec<String>,
    },
}

#[derive(Debug, Deserialize)]
struct FixtureExpected {
    stored_items: usize,
    pinned_items: usize,
    lexical_hits: usize,
    vector_hits: usize,
    embedding_rows: usize,
}

fn contract_probe(fixture_path: Option<&std::path::Path>) -> Result<()> {
    let encoded = if let Some(path) = fixture_path {
        std::fs::read_to_string(path)
            .with_context(|| format!("read tandem contract fixture {}", path.display()))?
    } else {
        include_str!("../tests/fixtures/local_history_v1.json").to_owned()
    };
    let fixture: ContractFixture =
        serde_json::from_str(&encoded).context("parse tandem contract fixture")?;
    if fixture.embedding_dimensions != cliptown_desktop::embedding::EMBEDDING_DIMENSIONS {
        anyhow::bail!("fixture embedding dimensions do not match this client")
    }
    let mut store = HistoryStore::open_in_memory()?;
    store.set_history_limit(fixture.history_limit)?;
    for clip in fixture.clips {
        let (input, pinned) = match clip {
            FixtureClip::Text { text, html, pinned } => (ClipInput::Text { text, html }, pinned),
            FixtureClip::ImagePng { base64 } => (
                ClipInput::ImagePng {
                    bytes: BASE64_STANDARD
                        .decode(base64)
                        .context("decode fixture PNG")?,
                },
                false,
            ),
            FixtureClip::Files { uris } => (ClipInput::Files { uris }, false),
        };
        let stored = store.insert(&input)?;
        if pinned {
            store.set_pinned(stored.id, true)?;
        }
    }
    let stored_items = store.count()?;
    let pinned_items = store
        .list(100_000)?
        .iter()
        .filter(|clip| clip.pinned)
        .count();
    let lexical_hits = store.text_search(&fixture.lexical_query, 10)?.len();
    let vector_hits = store.vector_search(&fixture.vector_query, 10)?.len();
    let embedding_rows = store.embedding_count()?;
    anyhow::ensure!(stored_items == fixture.expected.stored_items);
    anyhow::ensure!(pinned_items == fixture.expected.pinned_items);
    anyhow::ensure!(lexical_hits == fixture.expected.lexical_hits);
    anyhow::ensure!(vector_hits == fixture.expected.vector_hits);
    anyhow::ensure!(embedding_rows == fixture.expected.embedding_rows);
    let result = json!({
        "contract": fixture.contract,
        "embedding_dimensions": fixture.embedding_dimensions,
        "history_limit": store.history_limit()?,
        "stored_items": stored_items,
        "pinned_items": pinned_items,
        "lexical_hits": lexical_hits,
        "vector_hits": vector_hits,
        "embedding_rows": embedding_rows,
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
