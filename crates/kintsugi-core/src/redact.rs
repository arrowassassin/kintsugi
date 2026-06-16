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
//! through, and secrets typed at a sub-prompt (`psql`→`\password`) or inside a
//! here-doc body are out of scope. Pair it with operational guidance (use
//! `.pgpass` / secret stores) and a periodic log scan for stragglers.

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
pub fn redact_command(raw: &str) -> Redaction {
    let mut count = 0usize;
    let segments = split_keep_ws(raw);
    let token_count = segments.iter().filter(|s| !s.is_ws).count();

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
        if takes_next && this + 1 < redact_next.len() {
            redact_next[this + 1] = true;
        }
        out.push_str(&redacted);
    }

    Redaction { text: out, count }
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

    // 3. A URI: redact userinfo password (last `@` before path), or a colonless
    //    token-as-username (a PAT), and any sensitive query-string parameter.
    if tok.contains("://") {
        if let Some(red) = redact_uri(tok) {
            return (red, 1, false);
        }
    }
    if tok.contains('?') || tok.contains('&') || tok.contains(":_") {
        if let Some(red) = redact_query_params(tok) {
            return (red, 1, false);
        }
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
    let path = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    // userinfo is delimited by the LAST `@` before the path (passwords may contain `@`).
    let at = rest[..path].rfind('@')?;
    let userinfo = &rest[..at];
    let tail = &rest[at..];
    match userinfo.find(':') {
        Some(c) => Some(format!(
            "{}{}:{MARKER}{tail}",
            &tok[..scheme_end],
            &userinfo[..c]
        )),
        // scheme://TOKEN@host with no colon: a PAT-as-username — redact it.
        None => Some(format!("{}{MARKER}{tail}", &tok[..scheme_end])),
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
