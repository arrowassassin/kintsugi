//! Robustness / DoS campaign: millions of adversarial inputs must never panic,
//! abort, or hang the classifier.
//!
//! There is no `cargo-fuzz`/libFuzzer on stable Rust, so this is a deterministic,
//! seeded, in-process fuzzer: a fast xorshift PRNG drives three generators —
//! arbitrary Unicode, shell-metacharacter soup, and pathological structures
//! (deep `$(…)` nesting, operator floods, megabyte lines). The test *completing*
//! is the proof: a real stack overflow inside the parser is an uncatchable abort
//! that would kill the process, so reaching the asserts at the end means none of
//! the inputs triggered one. Reproducible by seed for any failure triage.

use kintsugi_core::redact::redact_command;
use kintsugi_core::{classify_line, Class};
use std::time::Instant;

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Metacharacters + fragments most likely to reach parser edge cases.
const ALPHABET: &[&str] = &[
    "rm",
    "-rf",
    "/",
    "git",
    "push",
    "--force",
    ";",
    "&&",
    "||",
    "|",
    "&",
    "$(",
    ")",
    "`",
    "{",
    "}",
    "(",
    ")",
    "<",
    ">",
    ">>",
    "<<",
    "<<<",
    "\"",
    "'",
    "\\",
    "$",
    "${",
    "}",
    "sh",
    "-c",
    "echo",
    "EOF",
    "\n",
    "\t",
    " ",
    "cat",
    ".env",
    "dd",
    "of=/dev/sda",
    "café",
    "🦀",
    "\0",
    "if",
    "then",
    "fi",
    "for",
    "do",
    "done",
    "=",
    "x",
];

fn classify_all(s: &str) -> Class {
    // Exercise the full entry point (which internally drives the AST parser too).
    classify_line(s).class
}

#[test]
#[ignore = "fuzz campaign (slow): run with `--release -- --ignored`"]
fn fuzz_arbitrary_unicode_never_panics() {
    let mut rng = XorShift(0x9E3779B97F4A7C15);
    let mut buf = String::new();
    let iters = 600_000;
    let start = Instant::now();
    for _ in 0..iters {
        buf.clear();
        let len = rng.below(160);
        for _ in 0..len {
            // Mix ASCII, control, and multibyte codepoints.
            let cp = match rng.below(4) {
                0 => rng.below(0x80),
                1 => 0x20 + rng.below(0x5F),
                2 => 0x80 + rng.below(0x800),
                _ => 0x1F000 + rng.below(0x600),
            };
            if let Some(c) = char::from_u32(cp as u32) {
                buf.push(c);
            }
        }
        let _ = classify_all(&buf);
    }
    let secs = start.elapsed().as_secs_f64();
    println!(
        "\n[fuzz] arbitrary-unicode: {iters} inputs, no panic/abort, {:.0} classifications/s",
        iters as f64 / secs
    );
}

#[test]
#[ignore = "fuzz campaign (slow): run with `--release -- --ignored`"]
fn fuzz_shell_metachar_soup_never_panics() {
    let mut rng = XorShift(0xD1B54A32D192ED03);
    let mut buf = String::new();
    let iters = 800_000;
    let start = Instant::now();
    for _ in 0..iters {
        buf.clear();
        let tokens = 1 + rng.below(40);
        for _ in 0..tokens {
            buf.push_str(ALPHABET[rng.below(ALPHABET.len())]);
            if rng.below(3) == 0 {
                buf.push(' ');
            }
        }
        let _ = classify_all(&buf);
    }
    let secs = start.elapsed().as_secs_f64();
    println!(
        "[fuzz] shell-metachar-soup: {iters} inputs, no panic/abort, {:.0} classifications/s",
        iters as f64 / secs
    );
}

#[test]
fn dos_pathological_inputs_are_bounded_and_never_abort() {
    // Each of these would crash a naive recursive-descent parser or blow the
    // latency budget. They must return (proving the pre-parse caps held) and a
    // dangerous one must never come back Safe.
    let deep_sub = format!("echo {}rm -rf /{}", "$(".repeat(5000), ")".repeat(5000));
    let deep_brace = format!("{}true{}", "{ ".repeat(4000), " ;}".repeat(4000));
    let pipe_flood = "echo a".to_string() + &" | echo a".repeat(20_000);
    let amp_flood = "true".to_string() + &" & true".repeat(20_000);
    let long_word = "a".repeat(2_000_000);
    let many_quotes = "\"".repeat(100_000);
    let backtick_bomb = "`".repeat(50_000);
    let kw_bomb = "if true; then ".repeat(5_000);
    let nul_spam = "\0rm -rf /\0".repeat(10_000);
    // Regression: the heredoc+substitution heap-exhaustion the fuzzer found
    // (brush-parser attempted a ~1.75GB allocation on these 23 bytes).
    let heredoc_dos = ")x<< .env$( (.envfiEOF ".to_string();

    let cases: &[(&str, &str)] = &[
        ("heredoc DoS", &heredoc_dos),
        ("deep $()", &deep_sub),
        ("deep braces", &deep_brace),
        ("pipe flood", &pipe_flood),
        ("amp flood", &amp_flood),
        ("2MB word", &long_word),
        ("100k quotes", &many_quotes),
        ("backtick bomb", &backtick_bomb),
        ("keyword bomb", &kw_bomb),
        ("NUL spam", &nul_spam),
    ];

    let start = Instant::now();
    for (name, input) in cases {
        let t = Instant::now();
        let class = classify_line(input).class;
        let ms = t.elapsed().as_secs_f64() * 1e3;
        println!("[dos] {name:<14} {ms:>8.2} ms  -> {class:?}");
        // Bounded: no single pathological line may take longer than a generous
        // ceiling (real abort/hang would never reach this print).
        assert!(ms < 2000.0, "{name} took {ms:.0}ms — possible DoS");
        // A buried catastrophe inside a pathological line must not be Safe.
        if input.contains("rm -rf /") {
            assert_ne!(class, Class::Safe, "{name} leaked a catastrophe to Safe");
        }
    }
    println!(
        "[dos] all {} pathological inputs bounded in {:.2}s total\n",
        cases.len(),
        start.elapsed().as_secs_f64()
    );
}

/// Building blocks for structured here-doc noise: operators, delimiters
/// (plain / quoted / "regex-ish"), and body lines carrying secrets, shell
/// noise, unbalanced quotes, CRLF, NULs, and marker-lookalike text.
const HEREDOC_PARTS: &[&str] = &[
    // operators + delimiters
    "bash <<EOF\n",
    "cat << EOF\n",
    "x <<-TAB\n",
    "y <<'E O F'\n",
    "z <<\"Q\"\n",
    "w <<E*OF.[x+\n",
    "v <<-\n",
    "u <<\n",
    "t <<< word\n",
    "s <<< 'PGPASSWORD=hunter2'\n",
    "r <<< \"X-Api-Key: v\"\n",
    "q <<<<\n",
    "p 2<<FD\n",
    "o <<EOF<<B\n",
    // delimiters / terminators (also valid body lines)
    "EOF\n",
    "E O F\n",
    "TAB\n",
    "\tTAB\n",
    "Q\n",
    "E*OF.[x+\n",
    "FD\n",
    "B\n",
    "EOF",
    "EOF\r\n",
    // body content: secrets in every shape the passes know
    "PGPASSWORD=hunter2\n",
    "AWS_SECRET_ACCESS_KEY=sk-fuzz-1\n",
    "mysql -ptopsecret -u root\n",
    "psql postgres://u:pw@h/d\n",
    "openssl x -passin pass:s3cr3t\n",
    "curl -H \"X-Api-Key: sk-fuzz-2\" https://x\n",
    "--password\n",
    "topsecret\n",
    // adversarial body noise
    "it's \"unbalanced\n",
    "noise <<IN more <<EOF x\n",
    "\0rm -rf /\0\n",
    "🦀 café\n",
    "\r\n",
    "\n",
    "[redacted]\n",
    "<<EOF\n",
    "<<<<<<<<<<\n",
    "x=$(cat <<A\n",
    "A\n",
];

/// Assemble one structured here-doc-noise input from `n` random parts.
fn heredoc_noise(rng: &mut XorShift, n: usize) -> String {
    let mut s = String::new();
    for _ in 0..n {
        s.push_str(HEREDOC_PARTS[rng.below(HEREDOC_PARTS.len())]);
    }
    s
}

/// Redact-and-check one input: terminates (the call returning is the proof),
/// the marker-count invariant holds, and a zero-count result must be
/// byte-identical to the input (every piece is verbatim — the rejoin is
/// structurally byte-exact).
fn redact_and_check(s: &str) {
    let r = redact_command(s);
    let markers = r.text.matches("[redacted]").count();
    if s.contains("[redacted]") {
        // Adversarial marker-lookalike input: each redaction inserts one
        // marker (and a value span may swallow pre-existing literal
        // markers), so the sound bound is "at least `count` present".
        assert!(
            markers >= r.count,
            "markers missing for {s:?} -> {:?}",
            r.text
        );
    } else {
        assert_eq!(r.count, markers, "count/markers mismatch for {s:?}");
    }
    if r.count == 0 {
        assert_eq!(r.text, s, "zero redactions must rejoin byte-exactly");
    }
}

#[test]
fn heredoc_redaction_noise_is_bounded_and_total() {
    // T4.1: the here-doc pre-pass must survive adversarial here-doc noise —
    // random delimiters, unterminated bodies, many heredocs per line, body
    // text full of quotes/operators/NUL/unicode — without panic, hang, or
    // losing bytes. Deterministic by seed, like the campaigns above.
    let mut rng = XorShift(0xA5A5A5A5DEADBEEF);
    let iters = 20_000;
    let start = Instant::now();
    for _ in 0..iters {
        let n = 1 + rng.below(30);
        let s = heredoc_noise(&mut rng, n);
        redact_and_check(&s);
        // Every so often drive the classifier too: the redaction pre-pass and
        // the AST classifier's here-operator neutralization are independent,
        // and both must stay bounded on the same adversarial input.
        if rng.below(16) == 0 {
            let _ = classify_line(&s);
        }
    }
    // The known DoS reproducer and its redaction-side variants, timed
    // individually like `dos_pathological_inputs_are_bounded_and_never_abort`.
    let dos_variants: &[&str] = &[
        ")x<< .env$( (.envfiEOF ",
        "bash <<EOF\nAWS_SECRET_ACCESS_KEY=sk-dos\nEOF\n",
        "bash <<EOF\nAWS_SECRET_ACCESS_KEY=sk-dos\n", // unterminated
        "x <<A <<B <<C\nTOKEN=t\n",                   // many, unclosed
        "bash <<<<<<<<<<<<<<<<<<<<\nTOKEN=t\n",
        &"<<EOF\n".repeat(64),
    ];
    for (i, input) in dos_variants.iter().enumerate() {
        let t = Instant::now();
        redact_and_check(input);
        let ms = t.elapsed().as_secs_f64() * 1e3;
        println!(
            "[heredoc-dos] variant {i} {:>8.3} ms ({} bytes)",
            ms,
            input.len()
        );
        assert!(
            ms < 2000.0,
            "heredoc variant {i} took {ms:.0}ms — possible DoS"
        );
    }
    let secs = start.elapsed().as_secs_f64();
    println!(
        "\n[heredoc-fuzz] {iters} structured inputs, no panic, byte-exact rejoin, {:.0} redactions/s",
        iters as f64 / secs
    );
}

#[test]
#[ignore = "fuzz campaign (slow): run with `--release -- --ignored`"]
fn fuzz_heredoc_noise_never_panics() {
    let mut rng = XorShift(0xC0FFEE123456789);
    let iters = 400_000;
    let start = Instant::now();
    for _ in 0..iters {
        let n = 1 + rng.below(24);
        let s = heredoc_noise(&mut rng, n);
        redact_and_check(&s);
        if rng.below(32) == 0 {
            let _ = classify_line(&s);
        }
    }
    let secs = start.elapsed().as_secs_f64();
    println!(
        "[fuzz] heredoc-noise: {iters} inputs, no panic/abort, byte-exact rejoin, {:.0} redactions/s",
        iters as f64 / secs
    );
}
