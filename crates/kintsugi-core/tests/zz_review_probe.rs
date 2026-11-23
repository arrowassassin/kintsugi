//! TEMPORARY review probe (not for merge): adversarial checks on the here-doc
//! redactor run against the real implementation.

use kintsugi_core::redact::{redact_command, MARKER};

fn show(s: &str) -> (String, usize) {
    let r = redact_command(s);
    (r.text, r.count)
}

#[test]
fn probe_heredoc_secret_is_redacted() {
    let raw = "bash <<EOF\nAWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\nEOF";
    let (text, n) = show(raw);
    println!("[{n}] {text}");
    assert!(!text.contains("AKIAIOSFODNN7EXAMPLE"), "secret survived: {text}");
    assert!(text.contains(MARKER));
}

#[test]
fn probe_commented_secret_in_body() {
    // A pasted config snippet with a commented-out key — very common shape.
    let raw = "bash <<EOF\n# AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\nEOF";
    let (text, n) = show(raw);
    println!("commented body: [{n}] {text}");
    assert!(
        !text.contains("AKIAIOSFODNN7EXAMPLE"),
        "commented secret survived into the log: {text}"
    );
}

#[test]
fn probe_exported_secret_in_body() {
    let raw = "bash <<EOF\nexport AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\nEOF";
    let (text, n) = show(raw);
    println!("export body: [{n}] {text}");
    assert!(!text.contains("AKIAIOSFODNN7EXAMPLE"), "{text}");
}

#[test]
fn probe_json_secret_in_body() {
    // A pasted JSON/YAML blob (not a command line) — documented out of scope,
    // but measure it.
    let raw = "cat <<EOF\n{\"password\": \"hunter2\"}\nEOF";
    let (text, n) = show(raw);
    println!("json body: [{n}] {text}");
}

#[test]
fn probe_separated_flag_link_across_heredoc_operator() {
    // Old pass: `--password` at the end of the line swallowed the NEXT token
    // (`<<EOF`) as its value. New pass keeps the operator verbatim.
    let raw = "psql --password <<EOF\nselect 1;\nEOF";
    let (text, n) = show(raw);
    println!("sep flag: [{n}] {text}");
}

#[test]
fn probe_heredoc_secret_at_head_of_body_line() {
    // `-p SECRET` inside a body line: program-gated pass must still fire.
    let raw = "bash <<'EOF'\nmysql -uroot -phunter2\nEOF";
    let (text, n) = show(raw);
    println!("body prog flag: [{n}] {text}");
    assert!(!text.contains("hunter2"), "body-line flag secret survived: {text}");
}

#[test]
fn probe_pathological_single_line_operators() {
    // Hostile: 200k operators on one line, no body terminator anywhere.
    let mut s = String::from("cat ");
    for _ in 0..200_000 {
        s.push_str("<<a ");
    }
    let start = std::time::Instant::now();
    let (text, _n) = show(&s);
    println!(
        "pathological: in={} out={} elapsed={:?}",
        s.len(),
        text.len(),
        start.elapsed()
    );
    assert!(start.elapsed().as_secs() < 5, "unbounded work");
}

#[test]
fn probe_many_closed_heredocs() {
    // 20k well-formed heredocs: linear or quadratic?
    let mut s = String::new();
    for _ in 0..20_000 {
        s.push_str("cat <<EOF\nA=1\nEOF\n");
    }
    let start = std::time::Instant::now();
    let (text, _n) = show(&s);
    println!("many heredocs: elapsed={:?} out={}", start.elapsed(), text.len());
    assert!(start.elapsed().as_secs() < 10);
}

#[test]
fn probe_crlf_and_tabs() {
    for raw in [
        "bash <<-EOF\r\n\tA=1\r\n\tEOF\r\n",
        "bash <<EOF\r\nAWS_SECRET_ACCESS_KEY=x\r\nEOF\r\n",
        "bash <<'EOF'\r\nAWS_SECRET_ACCESS_KEY=x\r\nEOF\r\n",
    ] {
        let (text, n) = show(raw);
        println!("crlf: [{n}] {text:?}");
        assert!(text.contains("A=1") || text.contains(MARKER), "{text:?}");
    }
}

#[test]
fn probe_delimiter_that_looks_like_a_secret() {
    // The delimiter word is Glue (verbatim). A secret used AS the delimiter
    // lands in the log.
    let raw = "bash <<'TOKEN=AKIAIOSFODNN7EXAMPLE'\nbody\nTOKEN=AKIAIOSFODNN7EXAMPLE\n";
    let (text, n) = show(raw);
    println!("delim secret: [{n}] {text:?}");
}

#[test]
fn probe_nested_heredoc_in_body() {
    let raw = "bash <<OUTER\ncat <<INNER\nAWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\nINNER\nOUTER\n";
    let (text, n) = show(raw);
    println!("nested: [{n}] {text}");
    assert!(!text.contains("AKIAIOSFODNN7EXAMPLE"), "{text}");
}
