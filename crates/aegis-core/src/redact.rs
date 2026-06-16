//! Command-line secret redaction.
//!
//! Audit recorders that capture commands verbatim will faithfully store the
//! credentials that appear on a command line — DB connection strings, `mysql
//! -pSECRET`, `PGPASSWORD=…`, bearer tokens. `auditd` does exactly this; `tlog`
//! disables input logging *because* of it. Aegis must not: the event log is
//! append-only and hash-chained (you can't scrub it later), and the security
//! spine forbids secret *values* in the log (rule #6) while still preserving the
//! raw command (rule #3).
//!
//! This module resolves that tension by redacting only the **value span** of a
//! detected credential, leaving the rest of the command verbatim and replacing
//! the secret with a fixed marker so the audit trail stays honest that a secret
//! was present without storing it. It is intentionally **conservative** — when in
//! doubt it over-redacts — because a leaked secret in an immutable log is far
//! worse than an over-redacted one. It does **no I/O** and is allocation-light so
//! it can run on the capture hot path.
//!
//! It is best-effort pattern matching, not a guarantee: a novel flag can slip
//! through. Pair it with operational guidance (use `.pgpass` / secret stores).

/// The placeholder a redacted value is replaced with. ASCII and unambiguous (not
/// `<…>`, which reads like a shell redirect).
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
pub fn redact_command(raw: &str) -> Redaction {
    let mut count = 0usize;
    // Split into alternating whitespace / token segments so we can reassemble
    // the line with its original spacing (verbatim except the redacted spans).
    let segments = split_keep_ws(raw);
    // Indices of the non-whitespace tokens, for lookahead on separated flags.
    let token_idx: Vec<usize> = segments
        .iter()
        .enumerate()
        .filter(|(_, s)| !s.is_ws)
        .map(|(i, _)| i)
        .collect();

    // The program is the first token that is not a `KEY=value` assignment prefix.
    let program = token_idx
        .iter()
        .map(|&i| segments[i].text.as_str())
        .find(|t| env_assignment(t).is_none())
        .map(program_name)
        .unwrap_or_default();

    // Only treat a bare `Bearer`/`Basic` word as an auth-scheme trigger when the
    // line actually mentions an Authorization header — otherwise an unrelated
    // word ("--mode basic") would wrongly redact the next token.
    let has_authz = raw.to_ascii_lowercase().contains("authorization");

    // `redact_next[k] = true` means "the next token's whole value is a secret"
    // (the value of a separated flag like `--password SECRET`).
    let mut redact_next = vec![false; token_idx.len()];

    let mut out = String::with_capacity(raw.len());
    let mut tok_seen = 0usize;
    for seg in &segments {
        if seg.is_ws {
            out.push_str(&seg.text);
            continue;
        }
        let this_tok = tok_seen;
        tok_seen += 1;

        if redact_next[this_tok] {
            out.push_str(MARKER);
            count += 1;
            continue;
        }

        let (redacted, n, takes_next) = redact_token(&seg.text, &program, has_authz);
        count += n;
        if takes_next && this_tok + 1 < redact_next.len() {
            redact_next[this_tok + 1] = true;
        }
        out.push_str(&redacted);
    }

    Redaction { text: out, count }
}

/// Redact secrets *within* a single token. Returns (redacted_token, count,
/// `takes_next`) where `takes_next` means the following token is the secret value
/// of a separated flag (e.g. this token was `--password`).
fn redact_token(tok: &str, program: &str, has_authz: bool) -> (String, usize, bool) {
    // 1. `KEY=value` env assignment with a sensitive key (PGPASSWORD=…, etc.).
    if let Some((key, _val)) = env_assignment(tok) {
        if sensitive_env_key(key) {
            return (format!("{key}={MARKER}"), 1, false);
        }
    }

    // 2. A URI with userinfo: scheme://user:PASSWORD@host -> redact the password.
    if tok.contains("://") {
        if let Some(red) = redact_uri_userinfo(tok) {
            return (red, 1, false);
        }
    }

    // 3. Long credential flags: --password=…, --token=…, --api-key=…, etc.
    if let Some(eq) = tok.find('=') {
        let flag = &tok[..eq];
        if credential_flag(flag) {
            return (format!("{flag}={MARKER}"), 1, false);
        }
    }
    // Separated form: `--password SECRET`, `--token SECRET`, …
    if credential_flag(tok) {
        return (tok.to_string(), 0, true);
    }

    // 4. `Authorization: Bearer <tok>` / `Authorization: Basic <creds>`: after
    //    whitespace-splitting, a bare `Bearer`/`Basic` word means the next token
    //    is the credential. Gated on the line mentioning an Authorization header.
    if has_authz {
        let word: String = tok.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
        if word.eq_ignore_ascii_case("bearer") || word.eq_ignore_ascii_case("basic") {
            return (tok.to_string(), 0, true);
        }
    }

    // 5. Program-gated short flags (avoid redacting `mkdir -p`, `ps -p <pid>`).
    match program {
        "mysql" | "mysqldump" | "mysqladmin" | "mariadb" | "mariadb-dump" => {
            // mysql `-pSECRET` (attached) or `-p SECRET` (separated).
            if tok == "-p" {
                return (tok.to_string(), 0, true);
            }
            if let Some(rest) = tok.strip_prefix("-p") {
                if !rest.is_empty() {
                    return ("-p".to_string() + MARKER, 1, false);
                }
            }
        }
        "redis-cli" => {
            if tok == "-a" || tok == "--pass" {
                return (tok.to_string(), 0, true);
            }
        }
        "curl" | "wget" => {
            // `-u user:pass` (attached `-uuser:pass` is also valid for curl).
            if tok == "-u" || tok == "--user" {
                return (tok.to_string(), 0, true);
            }
            if let Some(rest) = tok.strip_prefix("-u") {
                if !rest.is_empty() {
                    if let Some(c) = rest.find(':') {
                        return (format!("-u{}:{MARKER}", &rest[..c]), 1, false);
                    }
                }
            }
        }
        _ => {}
    }

    (tok.to_string(), 0, false)
}

/// `user:PASSWORD@host` inside a `scheme://…` token → redact the password span.
fn redact_uri_userinfo(tok: &str) -> Option<String> {
    let scheme_end = tok.find("://")? + 3;
    let rest = &tok[scheme_end..];
    // userinfo ends at the first `@`, and must come before the first `/` (path).
    let at = rest.find('@')?;
    let path = rest.find('/').unwrap_or(rest.len());
    if at > path {
        return None; // the `@` is in the path/query, not userinfo
    }
    let userinfo = &rest[..at];
    let colon = userinfo.find(':')?; // need a `user:pass` form
    Some(format!(
        "{}{}:{MARKER}{}",
        &tok[..scheme_end],
        &userinfo[..colon],
        &rest[at..]
    ))
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
    if ok {
        Some((key, &tok[eq + 1..]))
    } else {
        None
    }
}

/// Whether an env-var name names a credential.
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

/// Whether a long/short flag (no value attached) names a credential.
fn credential_flag(flag: &str) -> bool {
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
    )
}

struct Segment {
    text: String,
    is_ws: bool,
}

/// Split `s` into alternating whitespace / non-whitespace segments, preserving
/// every byte so the pieces rejoin to the original.
fn split_keep_ws(s: &str) -> Vec<Segment> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut cur_ws: Option<bool> = None;
    for c in s.chars() {
        let ws = c.is_whitespace();
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

/// Program basename (drops directory and `.exe`).
fn program_name(arg0: &str) -> String {
    let base = arg0.rsplit(['/', '\\']).next().unwrap_or(arg0);
    base.strip_suffix(".exe").unwrap_or(base).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn red(s: &str) -> String {
        redact_command(s).text
    }

    #[test]
    fn redacts_db_connection_string_password() {
        assert_eq!(
            red("psql \"postgresql://dba:s3cr3t@prod-db/orders\""),
            "psql \"postgresql://dba:[redacted]@prod-db/orders\""
        );
        assert_eq!(
            red("mongosh mongodb+srv://u:p@cluster/db"),
            "mongosh mongodb+srv://u:[redacted]@cluster/db"
        );
        // No password component → nothing to redact.
        assert_eq!(red("psql postgres://host/db"), "psql postgres://host/db");
    }

    #[test]
    fn redacts_mysql_password_flag_attached_and_separated() {
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
        // `-p` for a non-DB program must NOT be touched.
        assert_eq!(red("mkdir -p /tmp/a/b"), "mkdir -p /tmp/a/b");
        assert_eq!(red("ps -p 1234"), "ps -p 1234");
    }

    #[test]
    fn redacts_inline_credential_env_assignments() {
        assert_eq!(
            red("PGPASSWORD=hunter2 pg_dump db"),
            "PGPASSWORD=[redacted] pg_dump db"
        );
        assert_eq!(red("MYSQL_PWD=abc mysql"), "MYSQL_PWD=[redacted] mysql");
        assert_eq!(
            red("AWS_SECRET_ACCESS_KEY=zzz aws s3 ls"),
            "AWS_SECRET_ACCESS_KEY=[redacted] aws s3 ls"
        );
        // A non-secret assignment is left alone (PWD is the working dir, not a pw).
        assert_eq!(red("PWD=/tmp ls"), "PWD=/tmp ls");
        assert_eq!(
            red("RUST_LOG=debug cargo test"),
            "RUST_LOG=debug cargo test"
        );
    }

    #[test]
    fn redacts_generic_credential_flags() {
        assert_eq!(
            red("vault login --token=s.abcdef"),
            "vault login --token=[redacted]"
        );
        assert_eq!(
            red("tool --api-key 12345 run"),
            "tool --api-key [redacted] run"
        );
        assert_eq!(
            red("svc --client-secret=xyz"),
            "svc --client-secret=[redacted]"
        );
    }

    #[test]
    fn redacts_bearer_and_basic_auth() {
        // Whitespace-split: the `Bearer` word redacts the following credential
        // token (the trailing quote is consumed into the redacted span).
        assert_eq!(
            red("curl -H \"Authorization: Bearer tok123\" https://api"),
            "curl -H \"Authorization: Bearer [redacted] https://api"
        );
        // A stray "basic"/"bearer" word WITHOUT an Authorization header is left alone.
        assert_eq!(
            red("mytool --mode basic value"),
            "mytool --mode basic value"
        );
        // curl basic-auth: separated `-u` redacts the whole value (conservative);
        // attached `-uuser:pass` keeps the username, redacts the password.
        assert_eq!(
            red("curl -u alice:s3cret https://x"),
            "curl -u [redacted] https://x"
        );
        assert_eq!(
            red("curl -ualice:s3cret https://x"),
            "curl -ualice:[redacted] https://x"
        );
    }

    #[test]
    fn preserves_non_secret_commands_verbatim() {
        for s in [
            "ls -la /tmp",
            "git push --force",
            "psql -h localhost -U readonly -d analytics",
            "rm -rf build",
            "echo \"hello   world\"",
        ] {
            assert_eq!(red(s), s, "must be verbatim: {s}");
        }
    }

    #[test]
    fn preserves_whitespace_exactly() {
        // Original spacing is kept around redacted spans.
        assert_eq!(
            red("mysql   --password=x   -u root"),
            "mysql   --password=[redacted]   -u root"
        );
    }

    #[test]
    fn counts_multiple_redactions() {
        let r = redact_command("PGPASSWORD=a psql postgres://u:b@h/d --token=c");
        assert_eq!(r.count, 3);
        assert!(r.any());
        assert_eq!(redact_command("ls -la").count, 0);
    }

    #[test]
    fn empty_and_weird_input_is_safe() {
        assert_eq!(red(""), "");
        assert_eq!(red("   "), "   ");
        let _ = redact_command("=:@//$( `"); // must not panic
        let _ = redact_command("café://u:p@h"); // multibyte, must not panic
    }
}
