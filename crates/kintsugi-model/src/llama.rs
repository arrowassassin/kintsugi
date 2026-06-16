//! Real CPU GGUF inference backend (feature `llama`).
//!
//! Loads a small instruct model with `llama.cpp` and keeps it warm, asking for a
//! forced-short JSON `{summary, risk}`. If generation or parsing fails for a call,
//! it degrades to the [`HeuristicScorer`] for that call — the daemon always gets a
//! usable answer, and the model can only ever *add* caution.
//!
//! This backend is gated off by default because it requires a C/C++ toolchain to
//! build `llama.cpp`. It targets `llama-cpp-2` 0.1.x; pin the model checksum in
//! `manage.rs` before enabling `--features download`.

use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{Context, Result};
use kintsugi_core::{Class, ProposedCommand};

use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::{AddBos, LlamaModel, Special};
use llama_cpp_2::sampling::LlamaSampler;

use crate::heuristic::HeuristicScorer;
use crate::manage;
use crate::{ModelOutput, Scorer};

const MAX_TOKENS: i32 = 256;
const CTX_TOKENS: u32 = 2048;

/// A warm llama.cpp model behind a mutex (one context, reused per call).
pub struct LlamaScorer {
    name: String,
    backend: LlamaBackend,
    model: LlamaModel,
    fallback: HeuristicScorer,
    // Serialize access: a single context is not concurrently usable.
    guard: Mutex<()>,
}

impl LlamaScorer {
    /// Resolve weights, then load the model.
    ///
    /// Future-proof override: if `KINTSUGI_MODEL_FILE` points at a readable `.gguf`,
    /// load it directly — any newer/local model, no recompile and no pinned spec.
    /// This is the same bring-your-own-weights trust model as the picker script;
    /// it deliberately bypasses the checksum pin (the user chose the file). The
    /// daemon's `download` path stays pinned-only.
    pub fn autoload() -> Result<Self> {
        if let Some(p) = std::env::var_os("KINTSUGI_MODEL_FILE") {
            let path = std::path::PathBuf::from(p);
            if path.is_file() {
                let id = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("custom");
                return Self::load(&path, id);
            }
            anyhow::bail!(
                "KINTSUGI_MODEL_FILE is set but not a readable file: {}",
                path.display()
            );
        }
        let dir = weights_dir();
        let spec = manage::select_spec(manage::detect_ram_mb());
        let path = manage::ensure_weights(spec, &dir)
            .with_context(|| format!("ensure weights for {}", spec.id))?;
        Self::load(&path, spec.id)
    }

    /// Load a model from an explicit GGUF path.
    pub fn load(path: &std::path::Path, id: &str) -> Result<Self> {
        let backend = LlamaBackend::init().context("init llama backend")?;
        let params = LlamaModelParams::default(); // CPU-only
        let model = LlamaModel::load_from_file(&backend, path, &params)
            .with_context(|| format!("load model {}", path.display()))?;
        Ok(Self {
            name: format!("llama:{id}"),
            backend,
            model,
            fallback: HeuristicScorer::new(),
            guard: Mutex::new(()),
        })
    }

    /// Run inference and parse the JSON answer; returns None on any failure.
    // `token_to_str` + `Special::Tokenize` are deprecated in newer llama-cpp-2 but
    // remain the stable API at the pinned 0.1.x; allowed here until the pin moves.
    #[allow(deprecated)]
    fn infer(&self, cmd: &ProposedCommand, class: Class) -> Option<ModelOutput> {
        let _lock = self.guard.lock().ok()?;
        let prompt = build_prompt(&cmd.raw, class);

        let mut ctx = self
            .model
            .new_context(
                &self.backend,
                LlamaContextParams::default().with_n_ctx(std::num::NonZeroU32::new(CTX_TOKENS)),
            )
            .ok()?;

        let tokens = self.model.str_to_token(&prompt, AddBos::Always).ok()?;
        let mut batch = LlamaBatch::new(tokens.len().max(1) + MAX_TOKENS as usize, 1);
        let last = tokens.len() as i32 - 1;
        for (i, tok) in tokens.iter().enumerate() {
            batch.add(*tok, i as i32, &[0], i as i32 == last).ok()?;
        }
        ctx.decode(&mut batch).ok()?;

        let mut sampler = LlamaSampler::greedy();
        let mut out = String::new();
        let start = batch.n_tokens();
        let mut n_cur = start;
        // Greedy-decode up to MAX_TOKENS, stopping at EOG or the closing brace of
        // the forced-short JSON object.
        while n_cur < start + MAX_TOKENS {
            let token = sampler.sample(&ctx, batch.n_tokens() - 1);
            sampler.accept(token);
            if self.model.is_eog_token(token) {
                break;
            }
            if let Ok(piece) = self.model.token_to_str(token, Special::Tokenize) {
                out.push_str(&piece);
                if out.contains('}') {
                    break;
                }
            }
            batch.clear();
            batch.add(token, n_cur, &[0], true).ok()?;
            n_cur += 1;
            ctx.decode(&mut batch).ok()?;
        }
        parse_output(&out)
    }
}

impl Scorer for LlamaScorer {
    fn name(&self) -> &str {
        &self.name
    }

    fn score(&self, cmd: &ProposedCommand, class: Class, rule: &str) -> ModelOutput {
        // Safe commands never reach the model in the daemon, but be defensive.
        match self.infer(cmd, class) {
            Some(out) => ModelOutput {
                summary: out.summary,
                risk: out.risk.min(100),
            },
            None => self.fallback.score(cmd, class, rule),
        }
    }
}

fn weights_dir() -> PathBuf {
    if let Ok(d) = std::env::var("KINTSUGI_MODEL_DIR") {
        return PathBuf::from(d);
    }
    if let Some(dirs) = directories_next() {
        return dirs;
    }
    std::env::temp_dir().join("kintsugi-models")
}

fn directories_next() -> Option<PathBuf> {
    // Avoid a hard dep here; mirror the data dir layout used elsewhere.
    std::env::var("KINTSUGI_DATA_DIR")
        .ok()
        .map(|d| PathBuf::from(d).join("models"))
}

fn build_prompt(raw: &str, class: Class) -> String {
    // Ask for a beginner-friendly explanation: a plain first sentence, then up to
    // three short "• " pointers spelling out what the command actually does and
    // why it matters — for someone who can't read the shell. The pointers live
    // inside the single `summary` string (newline-separated) so the storage
    // schema and the risk score are unchanged.
    format!(
        "You are a security assistant explaining a shell command to someone who is \
         NOT comfortable reading shell. The command was classified as {class}. \
         Write a plain-English explanation, then 2-3 short bullet pointers (each \
         starting with \"• \") naming what it does, what it touches, and the risk. \
         Avoid jargon; if you must use a flag or path, say what it means. \
         Reply with ONLY a compact JSON object of the form \
         {{\"summary\": \"<sentence>\\n• <point>\\n• <point>\", \"risk\": <0-100>}}. \
         Command: {raw}\nJSON: "
    )
}

/// Parse the model's JSON, tolerating leading/trailing prose.
fn parse_output(text: &str) -> Option<ModelOutput> {
    let start = text.find('{')?;
    let end = text[start..].find('}')? + start + 1;
    let json = &text[start..end];
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let summary = v
        .get("summary")
        .and_then(|s| s.as_str())?
        .trim()
        .to_string();
    let risk = v
        .get("risk")
        .and_then(|r| r.as_u64())
        .map(|r| r.min(100) as u8)?;
    if summary.is_empty() {
        return None;
    }
    Some(ModelOutput { summary, risk })
}
