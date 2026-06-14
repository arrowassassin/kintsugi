//! Local IPC transport between interception and the daemon.
//!
//! Wire format: one newline-delimited JSON value per message. The interception
//! side connects, writes a [`ProposedCommand`], and blocks reading a [`Verdict`].
//! Transport is a Unix domain socket (filesystem) or a Windows named pipe
//! (namespaced), abstracted by the `interprocess` crate.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use aegis_core::{ProposedCommand, Verdict};
use anyhow::{Context, Result};
use interprocess::local_socket::prelude::*;
#[cfg(unix)]
use interprocess::local_socket::GenericFilePath;
#[cfg(not(unix))]
use interprocess::local_socket::GenericNamespaced;
use interprocess::local_socket::{ListenerOptions, Name, Stream};

/// Resolve the socket path. Override with `AEGIS_SOCKET` (handy in tests).
///
/// On Unix this is a filesystem path under `$XDG_RUNTIME_DIR` (falling back to
/// the temp dir). On Windows a namespaced pipe name is used instead.
pub fn socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("AEGIS_SOCKET") {
        return PathBuf::from(p);
    }
    #[cfg(unix)]
    {
        if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
            if !rt.is_empty() {
                return PathBuf::from(rt).join("aegis.sock");
            }
        }
        std::env::temp_dir().join("aegis.sock")
    }
    #[cfg(not(unix))]
    {
        PathBuf::from(r"\\.\pipe\aegis")
    }
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
        // Windows: use a namespaced pipe name (ignore the filesystem path form).
        let _ = &path;
        "aegis"
            .to_ns_name::<GenericNamespaced>()
            .context("invalid namespaced pipe name")
    }
}

/// Write one JSON message followed by a newline.
fn write_message<W: Write, T: serde::Serialize>(w: &mut W, value: &T) -> Result<()> {
    let mut line = serde_json::to_string(value).context("serialize IPC message")?;
    line.push('\n');
    w.write_all(line.as_bytes()).context("write IPC message")?;
    w.flush().context("flush IPC message")?;
    Ok(())
}

/// Read one newline-delimited JSON message.
fn read_message<R: BufRead, T: serde::de::DeserializeOwned>(r: &mut R) -> Result<T> {
    let mut line = String::new();
    let n = r.read_line(&mut line).context("read IPC message")?;
    if n == 0 {
        anyhow::bail!("connection closed before a message was received");
    }
    serde_json::from_str(line.trim_end()).context("deserialize IPC message")
}

/// Client side: connect, send a proposal, and block for the verdict.
pub struct Client;

impl Client {
    /// Send a proposed command to the daemon and await its verdict.
    pub fn send(cmd: &ProposedCommand) -> Result<Verdict> {
        let name = make_name()?;
        let mut stream =
            Stream::connect(name).context("connect to aegis daemon (is it running?)")?;
        write_message(&mut stream, cmd)?;
        let mut reader = BufReader::new(&mut stream);
        read_message(&mut reader)
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
            if path.exists() {
                // A stale socket file from a previous run blocks rebinding.
                let _ = std::fs::remove_file(&path);
            }
        }
        let name = make_name()?;
        let listener = ListenerOptions::new()
            .name(name)
            .create_sync()
            .context("bind aegis daemon socket")?;
        Ok(Self { listener })
    }

    /// The path/name the server is listening on.
    pub fn endpoint() -> PathBuf {
        socket_path()
    }

    /// Serve connections sequentially, calling `handler` for each request.
    ///
    /// Sequential by design: the event log holds a single SQLite connection that
    /// is not shared across threads, and each request is sub-millisecond. The
    /// interception side blocks on the response, so ordering is preserved.
    pub fn serve<F>(self, mut handler: F) -> Result<()>
    where
        F: FnMut(ProposedCommand) -> Verdict,
    {
        for incoming in self.listener.incoming() {
            let stream = match incoming {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("aegis-daemon: accept error: {e}");
                    continue;
                }
            };
            if let Err(e) = Self::handle_one(stream, &mut handler) {
                eprintln!("aegis-daemon: connection error: {e}");
            }
        }
        Ok(())
    }

    /// Serve exactly `count` connections then stop. Used by tests.
    pub fn serve_n<F>(self, count: usize, mut handler: F) -> Result<()>
    where
        F: FnMut(ProposedCommand) -> Verdict,
    {
        if count == 0 {
            return Ok(());
        }
        let mut served = 0;
        for incoming in self.listener.incoming() {
            let stream = incoming.context("accept connection")?;
            Self::handle_one(stream, &mut handler)?;
            served += 1;
            // Break immediately after the last request so we never block waiting
            // for an accept that will not come.
            if served >= count {
                break;
            }
        }
        Ok(())
    }

    fn handle_one<F>(mut stream: Stream, handler: &mut F) -> Result<()>
    where
        F: FnMut(ProposedCommand) -> Verdict,
    {
        let cmd: ProposedCommand = {
            let mut reader = BufReader::new(&mut stream);
            read_message(&mut reader)?
        };
        let verdict = handler(cmd);
        write_message(&mut stream, &verdict)?;
        Ok(())
    }
}
