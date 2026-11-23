//! Command-line secret redaction.
//!
//! Audit recorders that capture commands verbatim will faithfully store the
//! credentials that appear on a command line — DB connection strings, `mysql
//! -pSECRET`, `PGPASSWORD=…`, bearer tokens. `auditd` does exactly this; `tlog`
//! disables input logging *because* of it. Kintsugi must not: the event log is
//! append-only and hash-chained (you can't scrub it later), and the security
//! spine forbids secret *values* in the log (rule #6) while still preserving the
//! raw command (rule #3).
//!
//! This module redacts only the **value span** of a detected credential, leaving
//! the rest of the command verbatim and replacing the secret with a fixed marker.
//! It is intentionally **conservative** — when in doubt it over-redacts — because a
//! leaked secret in an immutable log is far worse than an over-redacted one. It
//! does **no I/O** and is allocation-light so it can run on the capture hot path.
//!
//! Tokenization is **quote-aware**: a quoted value (`--password "pa ss word"`) is
//! a single token, so a multi-word secret is redacted whole — a per-whitespace
//! approach leaks the tail of every quoted credential.
//!
//! It is best-effort pattern matching, not a guarantee: a novel flag can slip
//! through, and secrets typed at a sub-prompt (`psql`→`\password`) remain out
//! of scope. Here-doc bodies ARE covered, best-effort: they are segmented
//! out and run through the same passes, one body line at a time.

/// The placeholder a redacted value is replaced with. ASCII and unambiguous (not
/// `<…>`, which reads like a shell redirect). Frozen — it enters the canonical
/// hash, so changing it would change every event hash.
pub const MARKER: &str = "[redacted]";

/// The result of redacting a command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redaction {
    /// The command with every detected secret value replaced by [`MARKER`].
    pub text: String,
    /// How many secret values were redacted (0 = nothing matched).
    pub count: usize,
}

impl Redaction {
    /// Whether any secret was redacted.
    pub fn any(&self) -> bool {
        self.count > 0
    }
}

/// Redact credentials that appear inline in a command line. Preserves the
/// command's structure and whitespace; only secret *values* are replaced.
///
/// Here-doc backstop: `raw` is first segmented into here-doc pieces
/// (`<<DELIM`, `<<-DELIM`, `<<'DELIM'`, `<<"DELIM"`, here-strings `<<<word`);
/// bodies get the same token passes the rest of the line gets, redacted one
/// body line at a time (a script line is a command line), while the operator +
/// delimiter stay verbatim so the stored text keeps the heredoc's shape. A
/// secret pasted through `bash <<EOF … AWS_SECRET_ACCESS_KEY=… EOF` therefore
/// lands in the log as `[redacted]`, not as the raw value. Input with no
/// here-doc structure takes the pre-heredoc path byte-for-byte.
pub fn redact_command(raw: &str) -> Redaction {
    // Fast path — also the regression lock: no here-operator anywhere, so
    // the heredoc pre-pass is skipped entirely and behavior is byte-identical
    // to the pre-heredoc redactor.
    if !raw.contains("<<") {
        return redact_region(raw);
    }
    let pieces = segment_heredocs(raw);
    if !pieces
        .iter()
        .any(|p| matches!(p, Piece::Body(_) | Piece::Word(_)))
    {
        // `<<` text that never forms a here-doc (a quoted `<<`, `<< ` with no
        // delimiter word, `$((1<<4))` at end of line): fall back to the
        // single-region pass so these inputs stay byte-identical too.
        return redact_region(raw);
    }

    let mut count = 0usize;
    let mut text = String::with_capacity(raw.len() + MARKER.len());
    for piece in &pieces {
        match piece {
            Piece::Glue(s) => text.push_str(s),
            Piece::Outside(s) => {
                let r = redact_region(s);
                count += r.count;
                text.push_str(&r.text);
            }
            Piece::Body(s) => {
                // A here-doc body fed to a shell is a script: each line is
                // redacted as its own command line — the program-gated passes
                // fire with the line's own program (`mysql -p…` inside a body
                // redacts like a bare `mysql -p…` line), and a stray quote can
                // only swallow its own line, never the rest of the body. The
                // separated-flag linkage carries across the body's newlines,
                // matching the old whole-line pass (never weaker).
                let mut carry = false;
                let mut pos = 0usize;
                while pos < s.len() {
                    let (line, term) = line_at(s, pos);
                    let end = pos + line.len() + term;
                    let (r, c) = redact_line(&s[pos..end], carry);
                    carry = c;
                    count += r.count;
                    text.push_str(&r.text);
                    pos = end;
                }
            }
            Piece::Word(s) => {
                let r = redact_here_string_word(s);
                count += r.count;
                text.push_str(&r.text);
            }
        }
    }
    Redaction { text, count }
}

/// The complete pre-heredoc pass over one unsegmented span (the old
/// whole-line behavior). [`redact_command`] delegates here for every piece of
/// input that carries no here-doc body.
fn redact_region(raw: &str) -> Redaction {
    redact_line(raw, false).0
}

/// Redact one line-shaped span. `carry_in` seeds the separated-flag linkage
/// from the previous body line (`--password` at the end of one line marks the
/// first token of the next); the returned bool is this line's trailing
/// linkage. With `carry_in == false` this is exactly the historical
/// single-line redactor.
fn redact_line(raw: &str, carry_in: bool) -> (Redaction, bool) {
    let mut count = 0usize;
    let segments = split_keep_ws(raw);
    let token_count = segments.iter().filter(|s| !s.is_ws).count();
    if token_count == 0 {
        // Whitespace-only span: pass the linkage through unchanged.
        return (
            Redaction {
                text: raw.to_string(),
                count,
            },
            carry_in,
        );
    }

    // Effective program for flag-gating. A credential client is honored *anywhere*
    // on the line so command wrappers (`sudo mysql -p…`, `env mysql -p…`,
    // `sudo -u postgres mysql -p…`, `timeout 5 mysql -p…`) can't smuggle a secret
    // past the program-gated redaction. Otherwise it's the first non-wrapper,
    // non-assignment, non-flag token. Over-redaction here is the safe direction.
    let progs = || {
        segments
            .iter()
            .filter(|s| !s.is_ws)
            .map(|s| s.text.as_str())
            .filter(|t| env_assignment(t).is_none())
            .map(program_name)
    };
    let program = progs()
        .find(|p| is_credential_client(p))
        .or_else(|| progs().find(|p| !is_wrapper(p) && !p.starts_with('-')))
        .unwrap_or_default();
    let ctx = Ctx {
        program: &program,
        // `docker login -p` is a password; `docker run -p` is a port. Detect the
        // `login` subcommand as a bare token (no full-line lowercase allocation).
        docker_login: program == "docker" && segments.iter().any(|s| !s.is_ws && s.text == "login"),
    };

    // `redact_next[k]` = the next token's whole value is the secret of a separated
    // flag (`--password SECRET`).
    let mut redact_next = vec![false; token_count];
    if carry_in {
        redact_next[0] = true;
    }
    let mut carry_out = false;

    let mut out = String::with_capacity(raw.len() + MARKER.len());
    let mut tok_i = 0usize;
    for seg in &segments {
        if seg.is_ws {
            out.push_str(&seg.text);
            continue;
        }
        let this = tok_i;
        tok_i += 1;

        if redact_next[this] {
            out.push_str(MARKER);
            count += 1;
            continue;
        }

        let (redacted, n, takes_next) = redact_token(&seg.text, &ctx);
        count += n;
        if takes_next {
            if this + 1 < redact_next.len() {
                redact_next[this + 1] = true;
            } else {
                // The value sits on the next line: pass the linkage on.
                carry_out = true;
            }
        }
        out.push_str(&redacted);
    }

    (Redaction { text: out, count }, carry_out)
}

/// Sanitize a **taint source identifier** (a url / path / tool name) so a secret
/// embedded in it can never reach the append-only log or an agent-facing reason
/// string. A `source_id` is meant to be an *identifier only*, but a url is an
/// identifier that can carry a credential — `https://u:tok@h/p`, a colonless
/// PAT-as-username, `?api_key=…` — and the log is append-only, so a leak there is
/// unscrubbable.
///
/// A `source_id` is a single field, but it is shaped like one command token, so we
/// reuse [`redact_command`]'s conservative, quote-aware machinery: the URI-userinfo,
/// query-string, header, and env passes all fire on a lone token and are
/// program-independent, which is exactly the secret shapes a url can hide. A plain
/// path or tool name matches nothing and is returned verbatim (over-redacting an
/// identifier would corrupt the provenance trail). Idempotent — safe to re-apply
/// on log replay.
pub fn redact_source_id(source_id: &str) -> String {
    redact_command(source_id).text
}

// ======================= Here-doc backstop (T4.1) ==========================
//
// A secret pasted through `bash <<EOF … EOF` used to land verbatim in the
// append-only log (documented gap, redact.rs's module doc / DECISIONS.md).
// The pre-pass below carves here-doc bodies out of the raw command BEFORE
// the tokenizer runs, so the existing token passes apply inside bodies too.
// It is a line-oriented structural scan, not a shell parser: total (every
// input terminates), allocation-light, and deliberately conservative — an
// unrecognized or malformed here-operator simply stays command text.

/// One span carved out of the raw command. Every byte of the input lands in
/// exactly one piece, in order, so the pieces always rejoin byte-exactly.
enum Piece<'a> {
    /// Command text outside here-doc bodies — redacted with the token passes.
    Outside(&'a str),
    /// A here-operator plus its delimiter word exactly as written (`<<EOF`,
    /// `<<-'EOF'`, the `<<<` run). Kept verbatim so no pass can eat the
    /// operator as a separated flag's value (`mysql -p <<EOF`) and the stored
    /// text keeps the heredoc's shape.
    Glue(&'a str),
    /// A here-doc body, including its terminating delimiter line — redacted
    /// one line at a time.
    Body(&'a str),
    /// A here-string word, quotes as written — redacted through the passes
    /// (matching surrounding quotes are re-attached around the inner text).
    Word(&'a str),
}

/// A here-operator found by the line scan.
enum HereOp {
    /// `<<DELIM` / `<<-DELIM`: the delimiter for matching (quotes stripped)
    /// and whether `<<-` tab-stripping applies. The span covers operator +
    /// delimiter as written.
    Doc { delim: String, strip_tabs: bool },
    /// `<<<` (or a longer malformed `<` run): the span covers the run only;
    /// the here-string word ends at `word_end`.
    Str { word_end: usize },
}

/// The content and terminator length of the line starting at byte offset
/// `pos`. The terminator is the single `\n` when present; a trailing `\r`
/// stays inside the content (CRLF inputs keep their bytes through rejoin).
fn line_at(raw: &str, pos: usize) -> (&str, usize) {
    match raw[pos..].find('\n') {
        Some(nl) => (&raw[pos..pos + nl], 1),
        None => (&raw[pos..], 0),
    }
}

/// Parse the shell word at byte offset `start` in `line`: a matching-quoted
/// span (quotes included in the span, an unterminated quote runs to line end)
/// or a bare word up to whitespace or `<`. Returns `None` for an empty word —
/// `<< ` and a bare `<<<` form no heredoc. Byte offsets stay on char
/// boundaries (all stops are ASCII).
fn scan_word(line: &str, start: usize) -> Option<(usize, usize)> {
    let b = line.as_bytes();
    if start >= b.len() {
        return None;
    }
    if b[start] == b'\'' || b[start] == b'"' {
        let q = b[start];
        let mut j = start + 1;
        while j < b.len() && b[j] != q {
            j += 1;
        }
        if j < b.len() {
            j += 1; // include the closing quote
        }
        return Some((start, j));
    }
    let mut j = start;
    while j < b.len() && !b[j].is_ascii_whitespace() && b[j] != b'<' {
        j += 1;
    }
    (j > start).then_some((start, j))
}

/// The delimiter for *matching* a here-doc's terminator line: a quoted
/// delimiter's surrounding quotes are stripped (POSIX quote removal).
fn delim_of(line: &str, span: (usize, usize)) -> String {
    let word = &line[span.0..span.1];
    let b = word.as_bytes();
    if b.len() >= 2 && (b[0] == b'\'' || b[0] == b'"') && b[b.len() - 1] == b[0] {
        word[1..word.len() - 1].to_string()
    } else if b.first() == Some(&b'\'') || b.first() == Some(&b'"') {
        word[1..].to_string() // unterminated quoted delimiter
    } else {
        word.to_string()
    }
}

/// Skip ASCII whitespace forward from byte offset `i`.
fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// Scan one line's content for here-operators, quote-aware: a `<<` inside
/// quotes or after a backslash is text, not an operator. Returns
/// `(start, span_end, op)` byte spans relative to `line`: for a here-doc the
/// span covers operator + intervening whitespace + delimiter as written; for
/// a here-string it covers the `<`-run + whitespace (the word ends at
/// `word_end`).
fn scan_line_ops(line: &str) -> Vec<(usize, usize, HereOp)> {
    let mut ops = Vec::new();
    let b = line.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        if in_single {
            if c == b'\'' {
                in_single = false;
            }
            i += 1;
        } else if in_double {
            if c == b'\\' && i + 1 < b.len() {
                i += 2;
            } else {
                if c == b'"' {
                    in_double = false;
                }
                i += 1;
            }
        } else {
            match c {
                b'\\' => i = if i + 1 < b.len() { i + 2 } else { i + 1 },
                b'\'' => {
                    in_single = true;
                    i += 1;
                }
                b'"' => {
                    in_double = true;
                    i += 1;
                }
                b'<' if i + 1 < b.len() && b[i + 1] == b'<' => {
                    // A run of `<`s: exactly two is a here-doc operator
                    // (optionally `<<-`); three or more is a here-string
                    // (`<<<`; longer runs are malformed but treated the same
                    // so they can never re-trigger the scan). The delimiter /
                    // word follows, separated by optional whitespace — the
                    // shell allows `cat << EOF` and `bash <<< 'x'`.
                    let mut run_end = i + 2;
                    while run_end < b.len() && b[run_end] == b'<' {
                        run_end += 1;
                    }
                    if run_end == i + 2 {
                        let strip_tabs = run_end < b.len() && b[run_end] == b'-';
                        let after_op = if strip_tabs { run_end + 1 } else { run_end };
                        let word_start = skip_ws(b, after_op);
                        match scan_word(line, word_start) {
                            Some((_, we)) => {
                                let delim = delim_of(line, (word_start, we));
                                if delim.is_empty() {
                                    // `<<` with no word (or `<<''`): not an
                                    // operator — stay plain command text.
                                    i = word_start;
                                } else {
                                    ops.push((i, we, HereOp::Doc { delim, strip_tabs }));
                                    i = we;
                                }
                            }
                            None => i = word_start,
                        }
                    } else {
                        let word_start = skip_ws(b, run_end);
                        match scan_word(line, word_start) {
                            Some((_, we)) => {
                                ops.push((i, word_start, HereOp::Str { word_end: we }));
                                i = we;
                            }
                            None => i = word_start, // bare `<<<`: not an operator
                        }
                    }
                }
                _ => i += 1,
            }
        }
    }
    ops
}

/// Segment `raw` into here-doc pieces: one forward pass over the lines, each
/// scanned (quote-aware) for here-operators. Heredoc operators on a line
/// queue their bodies in order; a body starts on the next line and ends at
/// the first line whose content — after `<<-` tab stripping and CRLF
/// tolerance — equals the delimiter. An unterminated body takes the rest of
/// the input and the walk finishes (any later queued body lies inside that
/// span). The scan is structurally terminating: the cursor only moves
/// forward, so no input can loop, and every iteration consumes at least one
/// byte.
fn segment_heredocs(raw: &str) -> Vec<Piece<'_>> {
    let mut pieces: Vec<Piece> = Vec::new();
    let mut pending: Vec<(String, bool)> = Vec::new();
    let mut outside_start = 0usize;
    let mut pos = 0usize;
    let len = raw.len();

    while pos < len {
        let (line, term) = line_at(raw, pos);
        let line_start = pos;
        let next_line = line_start + line.len() + term;

        for (op_start, span_end, op) in scan_line_ops(line) {
            let op_start = line_start + op_start;
            let span_end = line_start + span_end;
            if op_start > outside_start {
                pieces.push(Piece::Outside(&raw[outside_start..op_start]));
            }
            match op {
                HereOp::Doc { delim, strip_tabs } => {
                    pieces.push(Piece::Glue(&raw[op_start..span_end]));
                    pending.push((delim, strip_tabs));
                    outside_start = span_end;
                }
                HereOp::Str { word_end } => {
                    let word_end = line_start + word_end;
                    pieces.push(Piece::Glue(&raw[op_start..span_end]));
                    pieces.push(Piece::Word(&raw[span_end..word_end]));
                    outside_start = word_end;
                }
            }
        }
        pos = next_line;

        // Here-docs on one line collect their bodies after that line, queued
        // in operator order (POSIX).
        if !pending.is_empty() {
            let queued = std::mem::take(&mut pending);
            for (delim, strip_tabs) in queued {
                if pos > outside_start {
                    pieces.push(Piece::Outside(&raw[outside_start..pos]));
                }
                let body_start = pos;
                let mut closed = false;
                while pos < len {
                    let (bline, bterm) = line_at(raw, pos);
                    let mut content = bline;
                    if strip_tabs {
                        content = content.trim_start_matches('\t');
                    }
                    let content = content.trim_end_matches('\r');
                    let line_content_end = pos + bline.len();
                    if content == delim {
                        let body_end = line_content_end + bterm;
                        pieces.push(Piece::Body(&raw[body_start..body_end]));
                        pos = body_end;
                        closed = true;
                        break;
                    }
                    pos = line_content_end + bterm;
                }
                if closed {
                    outside_start = pos;
                } else {
                    // Unterminated: the remainder is the body — redact it and
                    // finish. Later queued bodies lie inside this span.
                    pieces.push(Piece::Body(&raw[body_start..len]));
                    outside_start = len;
                    pos = len;
                    break;
                }
            }
        }
    }
    if len > outside_start {
        pieces.push(Piece::Outside(&raw[outside_start..len]));
    }
    pieces
}

/// Redact a here-string word through the existing passes. The word is tried
/// **as written** first, exactly like the same text on a command line (a
/// quoted multi-word header stays one token, so the header pass fires). If
/// nothing matched and the word carries matching surrounding quotes, the
/// passes run on the inner text — the shell strips those quotes before
/// feeding the string, so a quoted `PGPASSWORD=…` still redacts — and the
/// quotes are re-attached.
fn redact_here_string_word(word: &str) -> Redaction {
    let as_is = redact_region(word);
    if as_is.any() {
        return as_is;
    }
    let b = word.as_bytes();
    if b.len() >= 2 && (b[0] == b'\'' || b[0] == b'"') && b[b.len() - 1] == b[0] {
        let inner = redact_region(&word[1..word.len() - 1]);
        if inner.any() {
            return Redaction {
                text: format!("{}{}{}", &word[..1], inner.text, &word[word.len() - 1..]),
                count: inner.count,
            };
        }
    }
    as_is
}

struct Ctx<'a> {
    program: &'a str,
    docker_login: bool,
}

/// Redact secrets *within* a single (quote-aware) token. Returns (redacted, count,
/// `takes_next`) where `takes_next` means the following token is the secret value
/// of a separated flag.
fn redact_token(tok: &str, ctx: &Ctx) -> (String, usize, bool) {
    // 1. `KEY=value` env assignment with a sensitive key (PGPASSWORD=…).
    if let Some((key, _)) = env_assignment(tok) {
        if sensitive_env_key(key) {
            return (format!("{key}={MARKER}"), 1, false);
        }
    }

    // 2. A sensitive HTTP header carried as one (often quoted) token:
    //    `X-Api-Key: v`, `Authorization: Bearer v`, `Authorization:Token v`.
    if let Some(red) = redact_header(tok) {
        return (red, 1, false);
    }

    // 3. A URI: redact the userinfo password (or a colonless PAT), AND any
    //    sensitive query-string parameter in the SAME token — a connection string
    //    can carry a secret in both (`scheme://u:p@host/db?password=…`), so we must
    //    not stop after the userinfo: compose both passes on the one token.
    let uri_red = if tok.contains("://") {
        redact_uri(tok)
    } else {
        None
    };
    let base = uri_red.as_deref().unwrap_or(tok);
    if base.contains('?') || base.contains('&') || base.contains(":_") {
        if let Some(red) = redact_query_params(base) {
            return (red, 1, false);
        }
    }
    if let Some(red) = uri_red {
        return (red, 1, false);
    }

    // 4. Long credential flags: --password=…, --token=…, openssl -passin=… (and
    //    the separated `--password SECRET` form via `takes_next`).
    if let Some(eq) = tok.find('=') {
        let flag = &tok[..eq];
        if credential_flag(flag) {
            return (format!("{flag}={MARKER}"), 1, false);
        }
    }
    if credential_flag(tok) {
        return (tok.to_string(), 0, true);
    }

    // 5. OpenSSL inline `pass:SECRET`.
    if let Some(rest) = tok.strip_prefix("pass:") {
        if !rest.is_empty() {
            return (format!("pass:{MARKER}"), 1, false);
        }
    }

    // 6. Oracle `user/pass`, `user/pass@tns`, `userid=user/pass@…` (program-gated).
    if oracle_tool(ctx.program) {
        if let Some(red) = redact_oracle_login(tok) {
            return (red, 1, false);
        }
    }

    // 7. Program-gated short password flags (avoid `mkdir -p`, `docker run -p`).
    if let Some(res) = redact_short_flag(tok, ctx) {
        return res;
    }

    (tok.to_string(), 0, false)
}

/// `Header-Name: value` (possibly quoted, with an optional auth scheme word).
/// Per-token detection — no line-global gate — so an incidental "authorization"
/// in a commit message can't arm a spurious redaction.
fn redact_header(tok: &str) -> Option<String> {
    let lead = tok.len() - tok.trim_start_matches(['"', '\'']).len();
    let inner = &tok[lead..];
    let colon = inner.find(':')?;
    let name = inner[..colon].to_ascii_lowercase();
    let sensitive = matches!(
        name.as_str(),
        "authorization"
            | "proxy-authorization"
            | "x-api-key"
            | "api-key"
            | "apikey"
            | "x-auth-token"
            | "x-auth"
            | "auth-token"
            | "private-token"
            | "x-amz-security-token"
            | "x-csrf-token"
            | "cookie"
            | "set-cookie"
    );
    if !sensitive {
        return None;
    }
    let after = &inner[colon + 1..];
    let trimmed = after.trim_start();
    let lead_ws = after.len() - trimmed.len();
    // Keep an auth scheme word (Bearer/Basic/Token/…) but redact the credential.
    if let Some((w, _)) = trimmed.split_once(char::is_whitespace) {
        if is_auth_scheme(w) {
            let kept = &after[..lead_ws + w.len() + 1];
            return Some(format!(
                "{}{}:{kept}{MARKER}",
                &tok[..lead],
                &inner[..colon]
            ));
        }
    }
    let keep_ws = if lead_ws > 0 { " " } else { "" };
    Some(format!(
        "{}{}:{keep_ws}{MARKER}",
        &tok[..lead],
        &inner[..colon]
    ))
}

fn is_auth_scheme(w: &str) -> bool {
    matches!(
        w.to_ascii_lowercase().as_str(),
        "bearer" | "basic" | "token" | "apikey" | "digest" | "negotiate" | "ntlm"
    )
}

/// Redact a URI userinfo password (or colonless token-as-user), preserving the
/// surrounding token (scheme, quotes, host, path).
fn redact_uri(tok: &str) -> Option<String> {
    let scheme_end = tok.find("://")? + 3;
    let rest = &tok[scheme_end..];
    // The userinfo lives before the query/fragment. `?` and `#` reliably END the
    // authority (they're not valid unencoded in userinfo), and a secret in the
    // query is redacted separately by the compose pass — so confine the search to
    // the pre-query region. Within it, the userinfo `@` is the RIGHTMOST `@`: a
    // password may contain `@` and `/`, and the host may be empty
    // (`scheme://user:pass@/db`). The colon/path heuristic below then decides
    // whether this is real userinfo or just an `@` inside a path.
    let authority = &rest[..rest.find(['?', '#']).unwrap_or(rest.len())];
    let at = authority.rfind('@')?;
    let userinfo = &rest[..at];
    let tail = &rest[at..];
    match userinfo.find(':') {
        // `user:password` — redact the password (which may contain `/` or `@`).
        Some(c) => Some(format!(
            "{}{}:{MARKER}{tail}",
            &tok[..scheme_end],
            &userinfo[..c]
        )),
        // Colonless userinfo is a PAT-as-username (redact) ONLY when it has no path
        // chars; otherwise the `@` is just inside the path — leave the URL alone.
        None if !userinfo.contains(['/', '?', '#']) => {
            Some(format!("{}{MARKER}{tail}", &tok[..scheme_end]))
        }
        None => None,
    }
}

/// Redact sensitive `key=value` query/connection-string parameters in a token
/// (`?access_token=…`, `&password=…`, `;password=…`, `:_authToken=…`).
fn redact_query_params(tok: &str) -> Option<String> {
    let bytes = tok.as_bytes();
    let mut out = String::with_capacity(tok.len());
    let mut redacted = false;
    let mut start = 0usize;
    let mut i = 0usize;
    while i <= bytes.len() {
        let sep = i == bytes.len() || matches!(bytes[i], b'&' | b';' | b'?');
        if sep {
            let chunk = &tok[start..i];
            if let Some(eq) = chunk.find('=') {
                let key = chunk[..eq]
                    .rsplit([':', '/'])
                    .next()
                    .unwrap_or(&chunk[..eq]);
                if sensitive_param_key(key) && eq + 1 < chunk.len() {
                    out.push_str(&chunk[..eq + 1]);
                    out.push_str(MARKER);
                    redacted = true;
                } else {
                    out.push_str(chunk);
                }
            } else {
                out.push_str(chunk);
            }
            if i < bytes.len() {
                out.push(bytes[i] as char);
            }
            start = i + 1;
        }
        i += 1;
    }
    redacted.then_some(out)
}

/// Oracle `user/password`, `user/password@connect`, `userid=user/password@…`.
fn redact_oracle_login(tok: &str) -> Option<String> {
    let (prefix, body) = match tok.split_once('=') {
        Some((k, v)) if matches!(k.to_ascii_lowercase().as_str(), "userid" | "connect") => {
            (&tok[..k.len() + 1], v)
        }
        _ => ("", tok),
    };
    let slash = body.find('/')?;
    let user = &body[..slash];
    if user.is_empty() || user.contains(' ') {
        return None;
    }
    let after = &body[slash + 1..];
    let pw_end = after.find('@').unwrap_or(after.len());
    let pw = &after[..pw_end];
    // Non-empty, and not a filesystem path (`a/b/c`).
    if pw.is_empty() || pw.contains('/') {
        return None;
    }
    Some(format!("{prefix}{user}/{MARKER}{}", &after[pw_end..]))
}

/// Program-gated short password flags. Returns (redacted, count, takes_next).
fn redact_short_flag(tok: &str, ctx: &Ctx) -> Option<(String, usize, bool)> {
    let p_flag_program = matches!(
        ctx.program,
        "mysql"
            | "mysqldump"
            | "mysqladmin"
            | "mariadb"
            | "mariadb-dump"
            | "cqlsh"
            | "mongosh"
            | "mongo"
            | "mongodump"
            | "mongorestore"
    ) || (ctx.program == "docker" && ctx.docker_login);
    let big_p_program = ctx.program == "sqlcmd"; // sqlcmd uses uppercase -P

    let flag = if big_p_program { "-P" } else { "-p" };
    if (p_flag_program || big_p_program) && tok == flag {
        return Some((tok.to_string(), 0, true)); // separated value
    }
    if (p_flag_program || big_p_program) && tok.starts_with(flag) && tok.len() > flag.len() {
        return Some((format!("{flag}{MARKER}"), 1, false)); // attached value
    }

    match ctx.program {
        "redis-cli" => {
            if tok == "-a" || tok == "--pass" || tok == "--user" {
                return Some((tok.to_string(), 0, true));
            }
            if let Some(rest) = tok.strip_prefix("-a") {
                if !rest.is_empty() {
                    return Some((format!("-a{MARKER}"), 1, false));
                }
            }
        }
        "curl" | "wget" => {
            if tok == "-u" || tok == "--user" {
                return Some((tok.to_string(), 0, true));
            }
            if let Some(rest) = tok.strip_prefix("-u") {
                if !rest.is_empty() {
                    if let Some(c) = rest.find(':') {
                        return Some((format!("-u{}:{MARKER}", &rest[..c]), 1, false));
                    }
                    return Some((format!("-u{MARKER}"), 1, false));
                }
            }
        }
        "sshpass" => {
            if tok == "-p" {
                return Some((tok.to_string(), 0, true));
            }
            if let Some(rest) = tok.strip_prefix("-p") {
                if !rest.is_empty() {
                    return Some((format!("-p{MARKER}"), 1, false));
                }
            }
        }
        _ => {}
    }
    None
}

/// Split `KEY=value` (only when KEY looks like a shell variable name).
fn env_assignment(tok: &str) -> Option<(&str, &str)> {
    let eq = tok.find('=')?;
    if eq == 0 {
        return None;
    }
    let key = &tok[..eq];
    let ok = key
        .chars()
        .enumerate()
        .all(|(i, c)| c == '_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()));
    ok.then_some((key, &tok[eq + 1..]))
}

fn sensitive_env_key(key: &str) -> bool {
    let k = key.to_ascii_uppercase();
    k.contains("PASSWORD")
        || k.contains("PASSWD")
        || k.contains("SECRET")
        || k.contains("TOKEN")
        || k.contains("APIKEY")
        || k.contains("API_KEY")
        || k == "MYSQL_PWD"
        || k == "PGPASSWORD"
        || k == "REDISCLI_AUTH"
}

fn sensitive_param_key(key: &str) -> bool {
    let k = key.trim_start_matches('_').to_ascii_lowercase();
    matches!(
        k.as_str(),
        "password"
            | "passwd"
            | "pwd"
            | "pass"
            | "token"
            | "authtoken"
            | "access_token"
            | "accesstoken"
            | "api_key"
            | "apikey"
            | "secret"
            | "client_secret"
            | "sig"
            | "signature"
            | "auth"
            | "key"
    )
}

fn credential_flag(flag: &str) -> bool {
    // Must be an actual flag — a bare word like `auth`/`token`/`secret` is a
    // subcommand (`gcloud auth …`, `vault token …`), not a credential flag.
    if !flag.starts_with('-') {
        return false;
    }
    let f = flag.trim_start_matches('-').to_ascii_lowercase();
    matches!(
        f.as_str(),
        "password"
            | "passwd"
            | "token"
            | "secret"
            | "api-key"
            | "apikey"
            | "access-key"
            | "secret-key"
            | "secret-access-key"
            | "auth"
            | "auth-token"
            | "access-token"
            | "client-secret"
            | "passin"
            | "passout"
            | "pass"
    )
}

fn oracle_tool(program: &str) -> bool {
    matches!(
        program,
        "sqlplus" | "sqlldr" | "rman" | "exp" | "imp" | "expdp" | "impdp" | "sqlcl" | "sql"
    )
}

struct Segment {
    text: String,
    is_ws: bool,
}

/// Split `s` into alternating whitespace / token segments, **honoring quotes** so
/// whitespace inside `'…'` / `"…"` does not break a token (a quoted multi-word
/// secret stays one token). Preserves every byte so the pieces rejoin to `s`.
fn split_keep_ws(s: &str) -> Vec<Segment> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut cur_ws: Option<bool> = None;
    let mut in_single = false;
    let mut in_double = false;
    for c in s.chars() {
        if c == '\'' && !in_double {
            in_single = !in_single;
        } else if c == '"' && !in_single {
            in_double = !in_double;
        }
        let ws = c.is_whitespace() && !in_single && !in_double;
        match cur_ws {
            Some(prev) if prev == ws => cur.push(c),
            Some(prev) => {
                out.push(Segment {
                    text: std::mem::take(&mut cur),
                    is_ws: prev,
                });
                cur.push(c);
                cur_ws = Some(ws);
            }
            None => {
                cur.push(c);
                cur_ws = Some(ws);
            }
        }
    }
    if let Some(ws) = cur_ws {
        out.push(Segment {
            text: cur,
            is_ws: ws,
        });
    }
    out
}

/// Command wrappers that prefix the real program (so the program-gated redaction
/// must look past them, not treat the wrapper as the program).
fn is_wrapper(p: &str) -> bool {
    matches!(
        p,
        "sudo"
            | "doas"
            | "env"
            | "nice"
            | "ionice"
            | "nohup"
            | "time"
            | "timeout"
            | "stdbuf"
            | "setsid"
            | "xargs"
            | "command"
            | "builtin"
            | "exec"
    )
}

/// Programs whose short flags carry a credential (so `-p…`/`-a…`/`-u…` redaction
/// must fire even when the program appears after a wrapper). Mirrors the set
/// `redact_short_flag` switches on.
fn is_credential_client(p: &str) -> bool {
    matches!(
        p,
        "mysql"
            | "mysqldump"
            | "mysqladmin"
            | "mariadb"
            | "mariadb-dump"
            | "cqlsh"
            | "mongosh"
            | "mongo"
            | "mongodump"
            | "mongorestore"
            | "docker"
            | "sqlcmd"
            | "redis-cli"
            | "curl"
            | "wget"
            | "sshpass"
    )
}

fn program_name(arg0: &str) -> String {
    let base = arg0
        .trim_matches(['"', '\''])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(arg0);
    base.strip_suffix(".exe").unwrap_or(base).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn red(s: &str) -> String {
        redact_command(s).text
    }
    fn leaks(s: &str, secret: &str) -> bool {
        red(s).contains(secret)
    }

    #[test]
    fn wrappers_do_not_smuggle_a_secret_past_redaction() {
        // sudo/env/nice/time/timeout prefixes must not defeat the -p redaction.
        assert!(!leaks("sudo mysql -ps3cr3t", "s3cr3t"));
        assert!(!leaks("env mysql -ps3cr3t -u root", "s3cr3t"));
        assert!(!leaks("nice -n10 mysql -ps3cr3t", "s3cr3t"));
        assert!(!leaks("time mysql -ps3cr3t", "s3cr3t"));
        assert!(!leaks("timeout 5 mysql -ps3cr3t", "s3cr3t"));
        // sudo WITH its own options before the real client.
        assert!(!leaks("sudo -u postgres mysql -ps3cr3t", "s3cr3t"));
        // redis-cli and curl behind a wrapper, too.
        assert!(!leaks("sudo redis-cli -ap@ss", "p@ss"));
        assert!(!leaks("sudo curl -u alice:hunter2 https://x", "hunter2"));
        // a non-client token named like a client must NOT trigger a port redaction.
        assert_eq!(red("cat mysql.log"), "cat mysql.log");
    }

    #[test]
    fn db_connection_strings() {
        assert_eq!(
            red("psql \"postgresql://dba:s3cr3t@prod-db/orders\""),
            "psql \"postgresql://dba:[redacted]@prod-db/orders\""
        );
        // password containing '@' — split at the LAST '@' before the path.
        assert_eq!(
            red("psql 'postgresql://u:p@ss@host/db'"),
            "psql 'postgresql://u:[redacted]@host/db'"
        );
        // colonless PAT-as-username.
        assert_eq!(
            red("git remote add o https://ghp_abc123@github.com/o/r.git"),
            "git remote add o https://[redacted]@github.com/o/r.git"
        );
        assert!(!leaks(
            "svc --url=jdbc:postgresql://h/db?user=u&password=p4ss",
            "p4ss"
        ));
        // Password containing '/' (e.g. a base64 secret) — must not slip through
        // because the matcher mistook the '/' for the path boundary (regression).
        assert!(!leaks("psql postgres://app:aB/cD/ef@host/db", "aB/cD/ef"));
        // Secret in the query string ALONGSIDE userinfo: BOTH must be redacted —
        // the userinfo pass must not short-circuit the query pass (regression).
        let both = red("psql \"postgres://u:userpw@db/prod?password=QUERYSECRET\"");
        assert!(!both.contains("userpw"), "userinfo leaked: {both}");
        assert!(!both.contains("QUERYSECRET"), "query secret leaked: {both}");
        // Empty-host DSN (default host / unix socket): the real '@' precedes '/',
        // so an '@' inside the password must not be mistaken for the delimiter.
        assert!(!leaks("psql postgresql://user:pa@ss@/dbname", "pa@ss"));
        // An '@' that is purely in the path (no userinfo) must be left untouched.
        assert_eq!(red("curl http://host/p@q"), "curl http://host/p@q");
    }

    #[test]
    fn mysql_and_db_short_flags() {
        assert_eq!(
            red("mysql -ptopsecret -u root"),
            "mysql -p[redacted] -u root"
        );
        assert_eq!(
            red("mysql --password=topsecret"),
            "mysql --password=[redacted]"
        );
        assert_eq!(
            red("mysql --password topsecret"),
            "mysql --password [redacted]"
        );
        assert!(!leaks("sqlcmd -S srv -U sa -P MyPa55", "MyPa55"));
        assert_eq!(
            red("cqlsh host 9042 -u cassandra -p cassandra"),
            "cqlsh host 9042 -u cassandra -p [redacted]"
        );
        assert!(!leaks(
            "docker login -u user -p Sup3rPass reg.io",
            "Sup3rPass"
        ));
        // `docker run -p` is a PORT, must NOT be redacted.
        assert_eq!(
            red("docker run -p 8080:80 img"),
            "docker run -p 8080:80 img"
        );
        assert_eq!(red("mkdir -p /tmp/a/b"), "mkdir -p /tmp/a/b");
        assert_eq!(red("ps -p 1234"), "ps -p 1234");
    }

    #[test]
    fn quoted_multiword_secrets_are_fully_redacted() {
        // The headline leak: the whole quoted value must go, not just the first word.
        assert!(!leaks("tool --password \"pa ss word\"", "ss word"));
        assert!(!leaks("redis-cli -a 'my pass word'", "pass word"));
        assert!(!leaks("curl -u 'alice:my pass' https://x", "my pass"));
        assert!(!leaks("mysql -p'top secret'", "secret"));
    }

    #[test]
    fn env_assignments() {
        assert_eq!(
            red("PGPASSWORD=hunter2 pg_dump db"),
            "PGPASSWORD=[redacted] pg_dump db"
        );
        assert_eq!(red("MYSQL_PWD=abc mysql"), "MYSQL_PWD=[redacted] mysql");
        assert_eq!(
            red("AWS_SECRET_ACCESS_KEY=zzz aws s3 ls"),
            "AWS_SECRET_ACCESS_KEY=[redacted] aws s3 ls"
        );
        assert_eq!(red("PWD=/tmp ls"), "PWD=/tmp ls");
        assert_eq!(
            red("RUST_LOG=debug cargo test"),
            "RUST_LOG=debug cargo test"
        );
    }

    #[test]
    fn headers_any_scheme_and_name() {
        assert!(!leaks(
            "curl -H \"X-Api-Key: sk-live-abc123\" https://api",
            "sk-live-abc123"
        ));
        assert!(!leaks(
            "curl --header \"X-Auth-Token: abc123\" https://api",
            "abc123"
        ));
        assert!(!leaks(
            "curl -H \"Authorization: Bearer tok123\" https://api",
            "tok123"
        ));
        assert!(!leaks(
            "curl -H \"Authorization: Token abc123def\" https://api",
            "abc123def"
        ));
        assert!(!leaks(
            "curl -H \"Authorization:Bearer tok123\" https://api",
            "tok123"
        ));
        // the scheme word is preserved and the URL is NOT eaten.
        assert!(red("curl -H \"Authorization: Bearer tok123\" https://api").contains("https://api"));
    }

    #[test]
    fn does_not_redact_on_incidental_authorization_word() {
        // "authorization" in prose must NOT arm a later bare `basic`/`bearer`.
        assert_eq!(
            red("echo 'see the authorization docs' && curl basic https://x"),
            "echo 'see the authorization docs' && curl basic https://x"
        );
        assert_eq!(
            red("git commit -m 'add authorization check' ; deploy basic stuff"),
            "git commit -m 'add authorization check' ; deploy basic stuff"
        );
        assert_eq!(
            red("mytool --mode basic value"),
            "mytool --mode basic value"
        );
    }

    #[test]
    fn query_string_and_post_secrets() {
        assert!(!leaks(
            "curl 'https://api/v1?access_token=secret123&q=1'",
            "secret123"
        ));
        assert!(!leaks(
            "curl 'https://api/v1?api_key=secret123'",
            "secret123"
        ));
        assert!(!leaks("wget https://api/data?token=abc123", "abc123"));
        assert!(!leaks(
            "npm config set //registry.npmjs.org/:_authToken=npm_xxx",
            "npm_xxx"
        ));
    }

    #[test]
    fn oracle_easy_connect() {
        assert_eq!(
            red("sqlplus system/oracle@orcl"),
            "sqlplus system/[redacted]@orcl"
        );
        assert_eq!(red("sqlplus scott/tiger"), "sqlplus scott/[redacted]");
        assert!(!leaks("sqlplus scott/tiger@//host:1521/svc", "tiger"));
        assert!(!leaks("sqlldr userid=scott/tiger@orcl", "tiger"));
        // a non-oracle program with a path-like a/b arg is untouched.
        assert_eq!(red("cat dir/file"), "cat dir/file");
    }

    #[test]
    fn sshpass_openssl_redis() {
        assert!(!leaks("sshpass -p 'MyP4ss' ssh user@host", "MyP4ss"));
        assert!(!leaks("sshpass -pMyP4ss ssh user@host", "MyP4ss"));
        assert!(!leaks(
            "openssl rsa -in k.pem -passin pass:s3cr3t",
            "s3cr3t"
        ));
        assert!(!leaks("redis-cli -aSECRET ping", "SECRET"));
    }

    #[test]
    fn verbatim_when_no_secret() {
        for s in [
            "ls -la /tmp",
            "git push --force",
            "psql -h localhost -U readonly -d analytics",
            "rm -rf build",
            "echo \"hello   world\"",
            "echo $TOKEN",
            "docker login --password-stdin",
            "gcloud auth activate-service-account --key-file=/tmp/key.json",
            "ssh-add ~/.ssh/id_rsa",
            "cp -p a b",
            "tar -p -xf x.tar",
        ] {
            assert_eq!(red(s), s, "must be verbatim: {s}");
        }
        // Colonless `scheme://word@host` is conservatively redacted (could be a
        // PAT-as-username), accepting over-redaction of a plain username.
        assert_eq!(
            red("curl http://user@host/p"),
            "curl http://[redacted]@host/p"
        );
    }

    #[test]
    fn multibyte_boundaries_never_panic() {
        assert_eq!(
            red("psql postgres://café:naïve@h/d"),
            "psql postgres://café:[redacted]@h/d"
        );
        assert_eq!(red("curl -ucafé:secret x"), "curl -ucafé:[redacted] x");
        assert_eq!(red("mysql -pcafé"), "mysql -p[redacted]");
        assert_eq!(
            red("psql postgres://u🔥x:p🔥y@h/d"),
            "psql postgres://u🔥x:[redacted]@h/d"
        );
        let _ = redact_command("psql postgres://u:p\u{0}w@h/d"); // NUL, no panic
    }

    #[test]
    fn source_id_redaction_strips_secrets_but_keeps_plain_identifiers() {
        // A taint source identifier is a single field, but a url can smuggle a
        // secret in its userinfo or query string — those must never reach a log
        // row or an agent-facing reason. (Segment G.)
        assert!(!redact_source_id("https://u:ghp_tok123@github.com/o/r").contains("ghp_tok123"));
        assert!(
            !redact_source_id("https://api.example/v1?api_key=sk-live-abc").contains("sk-live-abc")
        );
        assert!(!redact_source_id("https://ghp_pat456@github.com/o/r.git").contains("ghp_pat456"));
        // A plain path or tool name carries no secret and must be left verbatim —
        // over-redacting an identifier would corrupt the provenance trail's meaning.
        for id in [
            "file:///home/user/project/notes.md",
            "/home/user/.aws/config",
            "issue#42",
            "tool:web_fetch",
            "https://docs.example.com/guide/intro",
        ] {
            assert_eq!(redact_source_id(id), id, "must be verbatim: {id}");
        }
        // Idempotent: redacting an already-redacted id is a fixpoint (matters for
        // replay, where a logged-and-redacted id is re-applied on cold start).
        let once = redact_source_id("https://u:tok@h/x?token=secret");
        assert_eq!(redact_source_id(&once), once);
    }

    // ============ Here-doc backstop (T4.1) ============

    #[test]
    fn heredoc_body_env_secret_is_redacted_in_the_stored_text() {
        // The headline smuggle: a secret pasted through `bash <<EOF … EOF`
        // used to land verbatim in the append-only (unscrubbable) log.
        let raw = "bash <<EOF\nexport AWS_SECRET_ACCESS_KEY=sk-live-abc123\nEOF\n";
        let r = redact_command(raw);
        assert!(!r.text.contains("sk-live-abc123"), "leaked: {}", r.text);
        assert!(
            r.text.contains("AWS_SECRET_ACCESS_KEY=[redacted]"),
            "{}",
            r.text
        );
        // Operator, delimiter, and structure stay verbatim around the body.
        assert!(r.text.starts_with("bash <<EOF\n"));
        assert!(r.text.ends_with("\nEOF\n"));
        assert!(r.any());
    }

    #[test]
    fn quoted_delimiters_disable_expansion_not_redaction() {
        // `<<'EOF'` / `<<"EOF"` bodies are literal to the shell — the threat
        // is still the secret VALUE sitting in the body text.
        for op in ["<<'EOF'", "<<\"EOF\""] {
            let raw = format!("bash {op}\nGITHUB_TOKEN=ghp_abc123\nEOF\n");
            let r = redact_command(&raw);
            assert!(
                !r.text.contains("ghp_abc123"),
                "leaked via {op}: {}",
                r.text
            );
            assert!(r.text.contains("GITHUB_TOKEN=[redacted]"), "{}", r.text);
            assert!(r.text.starts_with(&format!("bash {op}\n")));
            assert!(r.text.ends_with("\nEOF\n"));
        }
    }

    #[test]
    fn dash_heredoc_matches_a_tab_indented_delimiter() {
        // `<<-` strips leading tabs from body lines and from the delimiter
        // line when matching; the tabs themselves stay in the stored text.
        let raw = "bash <<-EOF\n\tAWS_SECRET_ACCESS_KEY=sk-dash-99\n\tEOF\n";
        let r = redact_command(raw);
        assert!(!r.text.contains("sk-dash-99"), "leaked: {}", r.text);
        assert!(
            r.text.contains("\tAWS_SECRET_ACCESS_KEY=[redacted]\n"),
            "{}",
            r.text
        );
        assert!(r.text.ends_with("\n\tEOF\n"));
    }

    #[test]
    fn multiple_heredocs_on_one_line_queue_their_bodies_in_order() {
        let raw = "cmd <<A <<B\nTOKEN=aaa111\nA\nTOKEN=bbb222\nB\n";
        let r = redact_command(raw);
        assert!(!r.text.contains("aaa111"), "leaked: {}", r.text);
        assert!(!r.text.contains("bbb222"), "leaked: {}", r.text);
        assert!(r
            .text
            .contains("TOKEN=[redacted]\nA\nTOKEN=[redacted]\nB\n"));
        assert!(r.text.starts_with("cmd <<A <<B\n"));
    }

    #[test]
    fn nested_looking_delimiter_text_inside_a_body_stays_body() {
        // Delimiter-ish lines and here-operators INSIDE a body are data, not
        // terminators or new operators; only the exact delimiter line closes.
        let raw = "cat <<OUT\nnoise <<IN x\nIN\nPGPASSWORD=inner1\nOUT\n";
        let r = redact_command(raw);
        assert!(!r.text.contains("inner1"), "leaked: {}", r.text);
        assert!(r.text.contains("PGPASSWORD=[redacted]"), "{}", r.text);
        assert!(r.text.ends_with("PGPASSWORD=[redacted]\nOUT\n"));
        assert!(r.text.starts_with("cat <<OUT\nnoise <<IN x\nIN\n"));
    }

    #[test]
    fn unclosed_heredoc_takes_the_rest_of_the_input_as_body() {
        // Never hangs: an unterminated body consumes the remainder, gets
        // redacted, and the pass finishes.
        let raw = "bash <<EOF\nAWS_SECRET_ACCESS_KEY=sk-unclosed\n";
        let r = redact_command(raw);
        assert!(!r.text.contains("sk-unclosed"), "leaked: {}", r.text);
        assert!(
            r.text.contains("AWS_SECRET_ACCESS_KEY=[redacted]"),
            "{}",
            r.text
        );
        assert!(r.text.starts_with("bash <<EOF\n"));
        // Two queued bodies where the first never closes: the rest is one
        // body (the second heredoc's lines lie inside it) and we finish.
        let raw2 = "cmd <<A <<B\nTOKEN=never-closed\n";
        let r2 = redact_command(raw2);
        assert!(!r2.text.contains("never-closed"), "leaked: {}", r2.text);
        assert!(r2.text.contains("TOKEN=[redacted]"));
    }

    #[test]
    fn here_string_words_are_redacted_quoted_or_not() {
        let r = redact_command("env <<< PGPASSWORD=hunter2");
        assert!(!r.text.contains("hunter2"), "leaked: {}", r.text);
        assert_eq!(r.text, "env <<< PGPASSWORD=[redacted]");
        // Matching surrounding quotes are re-attached around the redacted
        // inner text (the shell strips them before feeding the string).
        let q = redact_command("bash <<< 'GITHUB_TOKEN=ghp_tok456'");
        assert!(!q.text.contains("ghp_tok456"), "leaked: {}", q.text);
        assert_eq!(q.text, "bash <<< 'GITHUB_TOKEN=[redacted]'");
        let d = redact_command("bash <<< \"Authorization: Bearer tok123\"");
        assert!(!d.text.contains("tok123"), "leaked: {}", d.text);
        // The marker span consumes the trailing quote — the same convention
        // the existing header pass applies to every quoted header on a
        // command line (see `curl -H "X-Api-Key: …"`).
        assert_eq!(d.text, "bash <<< \"Authorization: Bearer [redacted]");
    }

    #[test]
    fn empty_and_delimiter_only_bodies_round_trip_untouched() {
        for raw in [
            "cat <<EOF\nEOF\n",
            "cat <<EOF\nEOF\necho done\n",
            "cat <<EOF",
        ] {
            let r = redact_command(raw);
            assert_eq!(r.text, raw, "must be byte-identical: {:?}", r.text);
            assert_eq!(r.count, 0);
        }
    }

    #[test]
    fn crlf_here_docs_terminate_and_redact() {
        // CRLF line endings (Windows-authored payloads): the delimiter line
        // matches despite the trailing `\r`, and the `\r` bytes survive.
        let raw = "bash <<EOF\r\nAWS_SECRET_ACCESS_KEY=sk-crlf-77\r\nEOF\r\n";
        let r = redact_command(raw);
        assert!(!r.text.contains("sk-crlf-77"), "leaked: {}", r.text);
        assert!(
            r.text.contains("AWS_SECRET_ACCESS_KEY=[redacted]\r\n"),
            "{}",
            r.text
        );
        assert!(r.text.starts_with("bash <<EOF\r\n"));
        assert!(r.text.ends_with("\r\nEOF\r\n"));
    }

    #[test]
    fn delimiter_words_with_special_characters_match_exactly() {
        // "Regex-ish" delimiter characters are plain text: matching is
        // string equality, never a pattern.
        let raw = "bash <<E*OF.[x+\nSECRET=special-delim\nE*OF.[x+\n";
        let r = redact_command(raw);
        assert!(!r.text.contains("special-delim"), "leaked: {}", r.text);
        assert!(
            r.text.contains("SECRET=[redacted]\nE*OF.[x+\n"),
            "{}",
            r.text
        );
    }

    #[test]
    fn here_operator_text_is_preserved_verbatim() {
        // A separated flag on the here-line must not eat the operator as its
        // value — the operator + delimiter are structural and stay verbatim,
        // while the body still redacts.
        let raw = "mysql -p <<EOF\nPGPASSWORD=body-secret\nEOF\n";
        let r = redact_command(raw);
        assert!(
            r.text.starts_with("mysql -p <<EOF\n"),
            "operator mangled: {}",
            r.text
        );
        assert!(!r.text.contains("body-secret"), "leaked: {}", r.text);
        assert!(r.text.contains("PGPASSWORD=[redacted]"));
    }

    #[test]
    fn body_lines_get_their_own_program_context() {
        // A here-doc fed to a shell IS a script: each body line is redacted
        // as its own command line, so the program-gated short-flag pass fires
        // with the body line's program (`mysql`), not the outer `bash`.
        let raw = "bash <<EOF\nmysql -ptopsecret -u root\nEOF\n";
        let r = redact_command(raw);
        assert!(!r.text.contains("topsecret"), "leaked: {}", r.text);
        assert!(r.text.contains("mysql -p[redacted] -u root"), "{}", r.text);
    }

    #[test]
    fn heredoc_line_tail_after_the_delimiter_word_is_still_command_text() {
        let raw = "cat <<EOF | grep x\nAWS_SECRET_ACCESS_KEY=sk-tail-1\nEOF\n";
        let r = redact_command(raw);
        assert!(!r.text.contains("sk-tail-1"), "leaked: {}", r.text);
        assert!(r.text.starts_with("cat <<EOF | grep x\n"), "{}", r.text);
        assert!(r.text.contains("AWS_SECRET_ACCESS_KEY=[redacted]\n"));
    }

    #[test]
    fn non_secret_bodies_are_byte_identical() {
        let raw = "cat <<EOF\njust text, $vars and 'quotes'\nEOF\necho done\n";
        let r = redact_command(raw);
        assert_eq!(r.text, raw, "must be verbatim: {:?}", r.text);
        assert_eq!(r.count, 0);
    }

    #[test]
    fn stray_quote_in_a_body_cannot_poison_later_body_lines() {
        // The old whole-line tokenizer let one unmatched quote swallow every
        // later line into a single token, hiding this assignment from the env
        // pass. Line-scoped body redaction confines quote confusion to the
        // line it starts on.
        let raw = "bash <<EOF\nit's ready\nAWS_SECRET_ACCESS_KEY=sk-quote-1\nEOF\n";
        let r = redact_command(raw);
        assert!(!r.text.contains("sk-quote-1"), "leaked: {}", r.text);
        assert!(
            r.text.contains("AWS_SECRET_ACCESS_KEY=[redacted]"),
            "{}",
            r.text
        );
    }

    #[test]
    fn separated_credential_flags_link_across_body_lines_like_before() {
        // Regression guard: the old whole-line pass treated the newline as
        // whitespace, so `--password <value>` linked across body lines. The
        // body pass must stay no-weaker.
        let raw = "bash <<EOF\npsql --password\ntopsecret99\nEOF\n";
        let r = redact_command(raw);
        assert!(!r.text.contains("topsecret99"), "leaked: {}", r.text);
    }

    #[test]
    fn non_heredoc_inputs_match_the_prior_redactor_byte_for_byte() {
        // Regression lock, captured from the pre-heredoc implementation
        // before the T4.1 pre-pass landed: inputs with no here-doc structure —
        // including `<<` text that forms no heredoc (quoted, bare, or
        // arithmetic) — must stay byte-identical, redaction counts included.
        let goldens: &[(&str, &str)] = &[
            ("ls -la /tmp", "ls -la /tmp"),
            ("mysql -ptopsecret -u root", "mysql -p[redacted] -u root"),
            ("sudo mysql -ps3cr3t", "sudo mysql -p[redacted]"),
            (
                "PGPASSWORD=hunter2 pg_dump db",
                "PGPASSWORD=[redacted] pg_dump db",
            ),
            (
                "psql \"postgresql://dba:s3cr3t@prod-db/orders\"",
                "psql \"postgresql://dba:[redacted]@prod-db/orders\"",
            ),
            (
                "curl -H \"X-Api-Key: sk-live-abc123\" https://api",
                "curl -H \"X-Api-Key: [redacted] https://api",
            ),
            (
                "sqlplus system/oracle@orcl",
                "sqlplus system/[redacted]@orcl",
            ),
            (
                "openssl rsa -in k.pem -passin pass:s3cr3t",
                "openssl rsa -in k.pem -passin [redacted]",
            ),
            ("redis-cli -a 'my pass word'", "redis-cli -a [redacted]"),
            (
                "echo one\ncurl -u alice:hunter2 https://x",
                "echo one\ncurl -u [redacted] https://x",
            ),
            ("grep '<<' file", "grep '<<' file"),
            ("echo a << b", "echo a << b"),
            (
                "echo $((2<<4)) && PGPASSWORD=hunter2 true",
                "echo $((2<<4)) && PGPASSWORD=[redacted] true",
            ),
            ("cat << file", "cat << file"),
            (
                "echo \"not << a heredoc\" && PGPASSWORD=hunter2 true",
                "echo \"not << a heredoc\" && PGPASSWORD=[redacted] true",
            ),
            ("bash <<EOF", "bash <<EOF"),
            (
                "x=$(2<<4) ; PGPASSWORD=hunter2 true",
                "x=$(2<<4) ; PGPASSWORD=[redacted] true",
            ),
        ];
        for (input, want) in goldens {
            let got = redact_command(input);
            assert_eq!(&got.text, want, "golden drifted for {input:?}");
            assert_eq!(got.count, got.text.matches(MARKER).count());
        }
    }

    proptest! {
        // Old-vs-new equality, heredoc-free inputs: `redact_region` is the
        // pre-heredoc algorithm preserved verbatim, so for any input without
        // a here-operator the public path must equal it byte-for-byte.
        #[test]
        fn heredoc_free_input_takes_the_unchanged_redaction_path(s in ".*") {
            prop_assume!(!s.contains("<<"));
            prop_assert_eq!(redact_command(&s), redact_region(&s));
        }

        // Structured here-doc noise — random delimiters, unterminated bodies,
        // many heredocs per line, adversarial body content — must terminate,
        // never panic, and keep `count == markers in text`.
        #[test]
        fn heredoc_noise_terminates_and_keeps_marker_count(
            parts in prop::collection::vec(
                prop_oneof![
                    Just("bash <<EOF\n"),
                    Just("cat <<'E O F'\n"),
                    Just("sql <<\"EOF\"\n"),
                    Just("x <<-TAB\n"),
                    Just("env <<< PGPASSWORD=hunter2\n"),
                    Just("y <<E*OF.[x+\n"),
                    Just("z <<<<\n"),
                    Just("<<\n"),
                    Just("<<< \n"),
                    Just("<<- \n"),
                    Just("EOF\n"),
                    Just("E O F\n"),
                    Just("TAB\n"),
                    Just("E*OF.[x+\n"),
                    Just("PGPASSWORD=hunter2\n"),
                    Just("--password\n"),
                    Just("topsecret\n"),
                    Just("it's \"quoted\" x\n"),
                    Just("\tTAB\n"),
                    Just("noise <<IN x\n"),
                    Just("AWS_SECRET_ACCESS_KEY=sk-9\n"),
                    Just("\r\n"),
                    Just("EOF\r\n"),
                    Just("psql postgres://u:pw@h/d\n"),
                    Just("pass:s3cr3t\n"),
                    Just("🦀 café \0\n"),
                    Just("echo <<EOF\n"),
                ],
                0..40,
            ).prop_map(|parts| parts.join(""))
        ) {
            let r = redact_command(&parts);
            prop_assert_eq!(r.count, r.text.matches(MARKER).count());
        }
    }

    #[test]
    fn counts_marker_invariants_and_pathological_sizes() {
        for s in [
            "PGPASSWORD=hunter2 psql postgres://u:p@h/d --token=c",
            "mysql --password=x --password=y",
            "ls -la",
        ] {
            let r = redact_command(s);
            assert_eq!(r.count, r.text.matches(MARKER).count());
            assert_eq!(r.any(), r.count > 0);
        }
        assert_eq!(redact_command(&"x ".repeat(500_000)).count, 0);
        let big = format!("psql postgres://u:{}@h/d", "p".repeat(200_000));
        assert_eq!(redact_command(&big).count, 1);
        for s in ["", "   ", "=:@//$( `", "\"unbalanced", "://@", "://:@"] {
            let _ = redact_command(s);
        }
    }
}
