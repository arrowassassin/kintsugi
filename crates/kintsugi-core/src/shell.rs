//! A small, dependency-free shell tokenizer.
//!
//! Good enough to recover an `argv` from a command line for recording and for
//! the Tier-1 rule engine: it understands single quotes, double quotes, and
//! backslash escaping. It is deliberately *not* a full shell parser — it does
//! not expand variables, globs, or handle here-docs. The raw command is always
//! preserved separately, so this is only ever an aid, never the source of truth.

/// Split a command line into tokens, honoring `'…'`, `"…"`, and `\` escapes.
///
/// Unterminated quotes are tolerated (the partial token is still emitted), so a
/// malformed line never panics or loses data.
pub fn split(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut has_token = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {
                if has_token {
                    tokens.push(std::mem::take(&mut cur));
                    has_token = false;
                }
            }
            '\'' => {
                has_token = true;
                for q in chars.by_ref() {
                    if q == '\'' {
                        break;
                    }
                    cur.push(q);
                }
            }
            '"' => {
                has_token = true;
                while let Some(q) = chars.next() {
                    match q {
                        '"' => break,
                        '\\' => {
                            // In double quotes, backslash escapes a few metachars.
                            if let Some(&next) = chars.peek() {
                                if matches!(next, '"' | '\\' | '$' | '`') {
                                    cur.push(chars.next().unwrap());
                                } else {
                                    cur.push('\\');
                                }
                            } else {
                                cur.push('\\');
                            }
                        }
                        _ => cur.push(q),
                    }
                }
            }
            '\\' => {
                has_token = true;
                if let Some(next) = chars.next() {
                    cur.push(next);
                } else {
                    cur.push('\\');
                }
            }
            _ => {
                has_token = true;
                cur.push(c);
            }
        }
    }
    if has_token {
        tokens.push(cur);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::split;

    #[test]
    fn plain_words() {
        assert_eq!(split("rm -rf /tmp/x"), vec!["rm", "-rf", "/tmp/x"]);
    }

    #[test]
    fn collapses_whitespace() {
        assert_eq!(split("  ls   -la  "), vec!["ls", "-la"]);
    }

    #[test]
    fn double_quotes() {
        assert_eq!(
            split(r#"git commit -m "two words""#),
            vec!["git", "commit", "-m", "two words"]
        );
    }

    #[test]
    fn single_quotes_are_literal() {
        assert_eq!(split(r#"echo 'a "b" c'"#), vec!["echo", r#"a "b" c"#]);
    }

    #[test]
    fn backslash_escape() {
        assert_eq!(split(r"echo a\ b"), vec!["echo", "a b"]);
    }

    #[test]
    fn empty_quoted_token_is_kept() {
        assert_eq!(split(r#"x "" y"#), vec!["x", "", "y"]);
    }

    #[test]
    fn empty_line_is_no_tokens() {
        assert!(split("   ").is_empty());
        assert!(split("").is_empty());
    }

    #[test]
    fn unterminated_quote_tolerated() {
        assert_eq!(split(r#"echo "oops"#), vec!["echo", "oops"]);
    }
}
