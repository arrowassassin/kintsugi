//! Local IPC transport between interception and the daemon.
//!
//! Wire format: one newline-delimited JSON value per message. The interception
//! side connects and sends a [`Request`]; the daemon replies with a [`Response`].
//! A `Propose` carries a [`ProposedCommand`] and is answered with a [`Verdict`];
//! a `Resolve` records a human's decision on a held command and is answered with
//! `Ack`. Transport is a Unix domain socket (filesystem) or a Windows named pipe
//! (namespaced), abstracted by the `interprocess` crate.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use interprocess::local_socket::prelude::*;
#[cfg(unix)]
use interprocess::local_socket::GenericFilePath;
#[cfg(not(unix))]
use interprocess::local_socket::GenericNamespaced;
use interprocess::local_socket::{ListenerOptions, Name, Stream};
use kintsugi_core::{Decision, ProposedCommand, Verdict};
use serde::{Deserialize, Serialize};

/// A request from interception to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Request {
    /// "Here is a command I'm about to run — what's the verdict?"
    Propose(ProposedCommand),
    /// "A human resolved a held command; record it (and maybe remember it)."
    Resolve(Resolution),
    /// "I observed a filesystem change that bypassed interception — just record
    /// it." The backstop sends these so the daemon's single writer keeps the hash
    /// chain intact.
    Observe(Observation),
    /// "A human (no AI agent) already ran this shell command — record it for the
    /// audit trail." Passive session recording: the daemon classifies it (so a
    /// destructive command is flagged in the timeline) but never blocks or
    /// snapshots, because by the time we hear about it the command has run.
    Record(ProposedCommand),
    /// "List the commands currently held for approval."
    ListPending,
    /// "What is the status of this queued command?" (`pending`/`approved`/`denied`).
    // Struct variants (not newtype-of-String): serde's internally-tagged enums
    // cannot represent a tagged newtype wrapping a primitive.
    PendingStatus { id: String },
    /// "A human approved this queued command id."
    Approve { id: String },
    /// "A human denied this queued command id."
    Deny { id: String },
    /// "What is the daemon's runtime status?" — currently the active scorer, so
    /// callers can tell whether the local model loaded or it's on the heuristic
    /// fallback.
    Status,
}

/// A filesystem change observed by the backstop watcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    /// `created` | `modified` | `removed`. Serialized as `change` so it never
    /// collides with the enum's internal `kind` tag.
    #[serde(rename = "change")]
    pub kind: String,
    /// The path that changed.
    pub path: String,
}

/// A human's resolution of a held command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resolution {
    /// The original command being resolved.
    pub command: ProposedCommand,
    /// The human's decision — `Allow` or `Deny` (never `Hold`).
    pub decision: Decision,
    /// Whether to remember this decision for this exact command in this repo.
    pub remember: bool,
}

/// The daemon's reply.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Response {
    /// Verdict for a `Propose`.
    Verdict(Verdict),
    /// Acknowledgement of a `Resolve`/`Approve`/`Deny`/`Observe`.
    Ack,
    /// The approval queue (reply to `ListPending`). A struct variant because
    /// serde's internally-tagged enums cannot wrap a bare sequence.
    PendingList {
        items: Vec<kintsugi_core::PendingItem>,
    },
    /// The status of a queued command (reply to `PendingStatus`): `pending` |
    /// `approved` | `denied` | `gone` (not in the queue).
    Pending { status: String },
    /// The daemon's runtime status (reply to `Status`). `scorer` is the active
    /// backend id, e.g. `heuristic` or `llama:Qwen3-4B-Instruct-2507-Q4_K_M`.
    Status { scorer: String },
    /// Something went wrong handling the request.
    Error { message: String },
}

/// Resolve the socket path. Override with `KINTSUGI_SOCKET` (handy in tests).
///
/// On Unix this is a filesystem path under `$XDG_RUNTIME_DIR` (falling back to
/// the temp dir). On Windows a namespaced pipe name is used instead.
pub fn socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("KINTSUGI_SOCKET") {
        return PathBuf::from(p);
    }
    #[cfg(unix)]
    {
        // $XDG_RUNTIME_DIR is already a per-user 0700 dir — the right home.
        if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
            if !rt.is_empty() {
                return PathBuf::from(rt).join("kintsugi.sock");
            }
        }
        // Otherwise use the per-user data dir (created 0700 at bind), never the
        // world-writable temp dir, so another local user can't pre-create or
        // connect to the socket.
        if let Some(dirs) = directories::ProjectDirs::from("", "", "kintsugi") {
            return dirs.data_dir().join("kintsugi.sock");
        }
        std::env::temp_dir().join("kintsugi.sock")
    }
    #[cfg(not(unix))]
    {
        PathBuf::from(r"\\.\pipe\kintsugi")
    }
}

/// Best-effort chmod on Unix (no-op elsewhere). Used to keep the socket and its
/// parent dir private to the owning user.
#[cfg(unix)]
pub(crate) fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

/// Build the `interprocess` name for the current platform.
fn make_name() -> Result<Name<'static>> {
    let path = socket_path();
    #[cfg(unix)]
    {
        path.clone()
            .to_fs_name::<GenericFilePath>()
            .with_context(|| format!("invalid socket path {}", path.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = &path;
        "kintsugi"
            .to_ns_name::<GenericNamespaced>()
            .context("invalid namespaced pipe name")
    }
}

/// Write one JSON message followed by a newline.
fn write_message<W: Write, T: Serialize>(w: &mut W, value: &T) -> Result<()> {
    let mut line = serde_json::to_string(value).context("serialize IPC message")?;
    line.push('\n');
    w.write_all(line.as_bytes()).context("write IPC message")?;
    w.flush().context("flush IPC message")?;
    Ok(())
}

/// Maximum size of a single IPC message. Bounds memory so a misbehaving or
/// hostile local peer can't OOM/stall the single-threaded daemon with a giant or
/// newline-free stream.
pub const MAX_FRAME: u64 = 16 * 1024 * 1024;

/// Read one newline-delimited JSON message from a length-bounded reader.
fn read_message<R: BufRead, T: serde::de::DeserializeOwned>(r: &mut R) -> Result<T> {
    let mut line = String::new();
    let n = r.read_line(&mut line).context("read IPC message")?;
    if n == 0 {
        anyhow::bail!("connection closed before a message was received");
    }
    if !line.ends_with('\n') && n as u64 >= MAX_FRAME {
        anyhow::bail!("IPC message exceeds {MAX_FRAME} bytes");
    }
    serde_json::from_str(line.trim_end()).context("deserialize IPC message")
}

/// Wrap a stream in a length-bounded buffered reader (see [`MAX_FRAME`]).
fn bounded(stream: &mut Stream) -> BufReader<std::io::Take<&mut Stream>> {
    BufReader::new(stream.take(MAX_FRAME))
}

/// Expect an `Ack`, mapping anything else to an error.
fn expect_ack(resp: Response) -> Result<()> {
    match resp {
        Response::Ack => Ok(()),
        Response::Error { message } => anyhow::bail!("daemon error: {message}"),
        _ => anyhow::bail!("unexpected response (wanted Ack)"),
    }
}

/// Send a request and read the response on a fresh connection.
fn round_trip(req: &Request) -> Result<Response> {
    let name = make_name()?;
    let mut stream =
        Stream::connect(name).context("connect to kintsugi daemon (is it running?)")?;
    write_message(&mut stream, req)?;
    let mut reader = bounded(&mut stream);
    read_message(&mut reader)
}

/// Client side: connect, send a request, and block for the response.
pub struct Client;

impl Client {
    /// Propose a command and await its verdict.
    pub fn send(cmd: &ProposedCommand) -> Result<Verdict> {
        match round_trip(&Request::Propose(cmd.clone()))? {
            Response::Verdict(v) => Ok(v),
            Response::Error { message } => anyhow::bail!("daemon error: {message}"),
            _ => anyhow::bail!("unexpected response to Propose"),
        }
    }

    /// Record a human's resolution of a held command.
    pub fn resolve(resolution: &Resolution) -> Result<()> {
        expect_ack(round_trip(&Request::Resolve(resolution.clone()))?)
    }

    /// Record an observed filesystem change (backstop).
    pub fn observe(observation: &Observation) -> Result<()> {
        expect_ack(round_trip(&Request::Observe(observation.clone()))?)
    }

    /// Record a shell command a human already ran (passive session recording).
    pub fn record(cmd: &ProposedCommand) -> Result<()> {
        expect_ack(round_trip(&Request::Record(cmd.clone()))?)
    }

    /// List the commands currently held for approval.
    pub fn list_pending() -> Result<Vec<kintsugi_core::PendingItem>> {
        match round_trip(&Request::ListPending)? {
            Response::PendingList { items } => Ok(items),
            Response::Error { message } => anyhow::bail!("daemon error: {message}"),
            _ => anyhow::bail!("unexpected response to ListPending"),
        }
    }

    /// The status of a queued command: `pending` | `approved` | `denied` | `gone`.
    pub fn pending_status(id: &str) -> Result<String> {
        match round_trip(&Request::PendingStatus { id: id.to_string() })? {
            Response::Pending { status } => Ok(status),
            Response::Error { message } => anyhow::bail!("daemon error: {message}"),
            _ => anyhow::bail!("unexpected response to PendingStatus"),
        }
    }

    /// Approve a queued command (records the human decision; may snapshot).
    pub fn approve(id: &str) -> Result<()> {
        expect_ack(round_trip(&Request::Approve { id: id.to_string() })?)
    }

    /// Deny a queued command.
    pub fn deny(id: &str) -> Result<()> {
        expect_ack(round_trip(&Request::Deny { id: id.to_string() })?)
    }

    /// The daemon's active scorer backend id (e.g. `heuristic` or
    /// `llama:<model>`). Lets callers report whether the local model is loaded.
    pub fn status_scorer() -> Result<String> {
        match round_trip(&Request::Status)? {
            Response::Status { scorer } => Ok(scorer),
            Response::Error { message } => anyhow::bail!("daemon error: {message}"),
            _ => anyhow::bail!("unexpected response to Status"),
        }
    }

    /// Whether a daemon appears to be listening.
    pub fn is_daemon_running() -> bool {
        match make_name() {
            Ok(name) => Stream::connect(name).is_ok(),
            Err(_) => false,
        }
    }
}

/// Server side: a bound listener that dispatches each request to a handler.
pub struct Server {
    listener: interprocess::local_socket::Listener,
}

impl Server {
    /// Bind the listener, clearing any stale Unix socket file first.
    pub fn bind() -> Result<Self> {
        #[cfg(unix)]
        {
            let path = socket_path();
            // Ensure a private parent dir (0700) so peers can't pre-create the
            // socket, then clear any stale socket file.
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
                set_mode(parent, 0o700);
            }
            if path.exists() {
                let _ = std::fs::remove_file(&path);
            }
        }
        let name = make_name()?;
        let listener = ListenerOptions::new()
            .name(name)
            .create_sync()
            .context("bind kintsugi daemon socket")?;
        // Restrict the socket to the owning user (no group/other access), so on a
        // shared host another user can't connect and Approve/Deny/Resolve.
        #[cfg(unix)]
        set_mode(&socket_path(), 0o600);
        Ok(Self { listener })
    }

    /// The path/name the server is listening on.
    pub fn endpoint() -> PathBuf {
        socket_path()
    }

    /// Serve connections sequentially, calling `handler` for each request.
    pub fn serve<F>(self, mut handler: F) -> Result<()>
    where
        F: FnMut(Request) -> Response,
    {
        for incoming in self.listener.incoming() {
            let stream = match incoming {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("kintsugi-daemon: accept error: {e}");
                    continue;
                }
            };
            if let Err(e) = Self::handle_one(stream, &mut handler) {
                eprintln!("kintsugi-daemon: connection error: {e}");
            }
        }
        Ok(())
    }

    /// Serve exactly `count` connections then stop. Used by tests.
    pub fn serve_n<F>(self, count: usize, mut handler: F) -> Result<()>
    where
        F: FnMut(Request) -> Response,
    {
        if count == 0 {
            return Ok(());
        }
        let mut served = 0;
        for incoming in self.listener.incoming() {
            let stream = incoming.context("accept connection")?;
            Self::handle_one(stream, &mut handler)?;
            served += 1;
            if served >= count {
                break;
            }
        }
        Ok(())
    }

    fn handle_one<F>(mut stream: Stream, handler: &mut F) -> Result<()>
    where
        F: FnMut(Request) -> Response,
    {
        let req: Request = {
            let mut reader = bounded(&mut stream);
            read_message(&mut reader)?
        };
        let resp = handler(req);
        write_message(&mut stream, &resp)?;
        Ok(())
    }
}
