//! Model weight management: pinned specs, RAM-based selection, checksum
//! verification, and (feature `download`) the single permitted network fetch.
//!
//! Security spine: weights are **pinned by SHA-256**. A spec with an empty hash is
//! treated as not-yet-pinned and refused, so Kintsugi never loads an unverified blob.
//! The download is the only network egress Kintsugi ever performs.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

/// A pinned model: where to fetch it, its checksum, and the RAM it needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelSpec {
    /// Stable id, e.g. `"qwen3-4b-instruct-q4_k_m"`.
    pub id: &'static str,
    /// File name on disk.
    pub file: &'static str,
    /// Pinned download URL (empty until pinned for a release).
    pub url: &'static str,
    /// Pinned SHA-256 of the file (empty until pinned — refused if empty).
    pub sha256: &'static str,
    /// Approximate download size in bytes (for UX).
    pub size_bytes: u64,
    /// Minimum total system RAM (MB) to prefer this model.
    pub min_ram_mb: u64,
}

impl ModelSpec {
    /// Whether this spec has a real checksum pinned.
    pub fn is_pinned(&self) -> bool {
        self.sha256.len() == 64
    }
}

// Default model choice — researched to be future-proof (2026-06).
//
// Our Tier-2 task is deliberately tiny: emit forced-short JSON with a one-line
// summary and a 0..=100 risk score. That favours a *small, permissive,
// instruction-tuned* model with reliable structured output over raw size. We
// surveyed the current small-model field (Qwen3.x, Llama 3.2, Gemma, Phi-4-mini)
// and pin the Qwen3 instruct family as the default:
//   - Apache-2.0 — no usage restrictions for a tool we ship to others.
//   - Official first-party GGUF builds (Q4_K_M) at the sizes we want.
//   - Best small-model instruction-following / forced-JSON in its class.
//   - A 4B-dense primary and a 1.7B fallback so RAM-based selection has a
//     same-family low-end that behaves identically.
//
// Models move fast, so the durable answer is *not* this constant: set
// `KINTSUGI_MODEL_FILE=/path/to/any.gguf` to run a newer/local GGUF without
// recompiling (see `llama::LlamaScorer::autoload`). This spec is only the
// pinned, checksum-verified default for the `download` path; url/sha must be
// filled before enabling that feature.

/// Primary model: Qwen3-4B-Instruct, Q4_K_M (~2.5 GB), used when RAM ≥ ~6 GB.
pub const MODEL_PRIMARY: ModelSpec = ModelSpec {
    id: "qwen3-4b-instruct-q4_k_m",
    file: "qwen3-4b-instruct-q4_k_m.gguf",
    url: "",
    sha256: "",
    size_bytes: 2_500_000_000,
    min_ram_mb: 6_000,
};

/// Low-RAM fallback: Qwen3-1.7B-Instruct, Q4_K_M (~1.1 GB), auto-selected on
/// machines with less RAM. URL/sha must be pinned before enabling `download`.
pub const MODEL_FALLBACK: ModelSpec = ModelSpec {
    id: "qwen3-1.7b-instruct-q4_k_m",
    file: "qwen3-1.7b-instruct-q4_k_m.gguf",
    url: "",
    sha256: "",
    size_bytes: 1_100_000_000,
    min_ram_mb: 0,
};

/// Choose the largest model that comfortably fits in the available RAM.
pub fn select_spec(ram_mb: u64) -> &'static ModelSpec {
    if ram_mb >= MODEL_PRIMARY.min_ram_mb {
        &MODEL_PRIMARY
    } else {
        &MODEL_FALLBACK
    }
}

/// Best-effort total system RAM in MB. Falls back to a conservative 4096.
pub fn detect_ram_mb() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(text) = std::fs::read_to_string("/proc/meminfo") {
            for line in text.lines() {
                if let Some(rest) = line.strip_prefix("MemTotal:") {
                    if let Some(kb) = rest.split_whitespace().next() {
                        if let Ok(kb) = kb.parse::<u64>() {
                            return kb / 1024;
                        }
                    }
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output()
        {
            if let Ok(s) = String::from_utf8(out.stdout) {
                if let Ok(bytes) = s.trim().parse::<u64>() {
                    return bytes / (1024 * 1024);
                }
            }
        }
    }
    4096
}

/// Compute the SHA-256 of a file as a lowercase hex string.
pub fn sha256_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

/// Verify a file matches the spec's pinned checksum.
pub fn verify(spec: &ModelSpec, path: &Path) -> Result<bool> {
    if !spec.is_pinned() {
        bail!(
            "model {} has no pinned checksum; refusing to use it",
            spec.id
        );
    }
    Ok(sha256_file(path)?.eq_ignore_ascii_case(spec.sha256))
}

/// Ensure the weights for `spec` exist and verify under `dir`, returning the path.
///
/// If the file is missing and the `download` feature is enabled, fetch it from the
/// pinned URL and verify the checksum before returning. Without the feature, a
/// missing file is an error (the caller should fall back to the heuristic scorer).
pub fn ensure_weights(spec: &ModelSpec, dir: &Path) -> Result<PathBuf> {
    if !spec.is_pinned() {
        bail!(
            "model {} is not pinned (set its url + sha256 before download)",
            spec.id
        );
    }
    let path = dir.join(spec.file);
    if path.is_file() {
        if verify(spec, &path)? {
            return Ok(path);
        }
        bail!("checksum mismatch for {}", path.display());
    }

    #[cfg(feature = "download")]
    {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        download(spec, &path)?;
        if !verify(spec, &path)? {
            let _ = std::fs::remove_file(&path);
            bail!("downloaded weights failed checksum for {}", spec.id);
        }
        Ok(path)
    }
    #[cfg(not(feature = "download"))]
    {
        bail!(
            "weights for {} not present at {} (build with --features download to fetch)",
            spec.id,
            path.display()
        )
    }
}

/// Download the weights from the pinned URL (the only permitted network egress).
#[cfg(feature = "download")]
fn download(spec: &ModelSpec, dest: &Path) -> Result<()> {
    if spec.url.is_empty() {
        bail!("model {} has no pinned URL", spec.id);
    }
    let resp = reqwest::blocking::get(spec.url)
        .with_context(|| format!("GET {}", spec.url))?
        .error_for_status()?;
    let bytes = resp.bytes()?;
    std::fs::write(dest, &bytes).with_context(|| format!("write {}", dest.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_primary_with_enough_ram_else_fallback() {
        assert_eq!(select_spec(16_000).id, MODEL_PRIMARY.id);
        assert_eq!(select_spec(6_000).id, MODEL_PRIMARY.id);
        assert_eq!(select_spec(4_000).id, MODEL_FALLBACK.id);
        assert_eq!(select_spec(0).id, MODEL_FALLBACK.id);
    }

    #[test]
    fn detect_ram_is_positive() {
        assert!(detect_ram_mb() > 0);
    }

    #[test]
    fn unpinned_specs_are_refused() {
        // Default specs ship unpinned; using them must error, not load a blob.
        assert!(!MODEL_PRIMARY.is_pinned());
        let tmp = tempfile::tempdir().unwrap();
        assert!(ensure_weights(&MODEL_PRIMARY, tmp.path()).is_err());
        assert!(verify(&MODEL_PRIMARY, tmp.path()).is_err());
    }

    #[test]
    fn checksum_roundtrip_and_match() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("blob.bin");
        std::fs::write(&f, b"hello kintsugi").unwrap();
        let digest = sha256_file(&f).unwrap();
        assert_eq!(digest.len(), 64);

        // A spec pinned to the real digest verifies; a wrong pin does not.
        let good = ModelSpec {
            sha256: Box::leak(digest.clone().into_boxed_str()),
            ..MODEL_FALLBACK
        };
        assert!(verify(&good, &f).unwrap());
        let bad = ModelSpec {
            sha256: "0000000000000000000000000000000000000000000000000000000000000000",
            ..MODEL_FALLBACK
        };
        assert!(!verify(&bad, &f).unwrap());
    }
}
