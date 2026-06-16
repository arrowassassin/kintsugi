//! P1.1 property tests: invariants the classifier must hold for *any* input.
//!
//! The security spine in property form — most importantly, model/caller input
//! can never talk the classifier *down*: appending a catastrophic segment always
//! wins, and dangerous patterns survive arbitrary surrounding noise.

use kintsugi_core::{classify_line, Class};
use proptest::prelude::*;

/// A few representative safe commands to use as "innocent" prefixes/suffixes.
fn safe_command() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec![
        "ls",
        "pwd",
        "cat README.md",
        "git status",
        "cargo build",
        "echo hi",
        "grep x y",
    ])
}

/// Representative catastrophic commands.
fn catastrophic_command() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec![
        "rm -rf /",
        "git push --force",
        "terraform destroy",
        "kubectl delete ns prod",
        "dd if=/dev/zero of=/dev/sda",
    ])
}

proptest! {
    // 1. Never panics, always returns a class.
    #[test]
    fn never_panics_on_arbitrary_input(s in ".*") {
        let _ = classify_line(&s);
    }

    #[test]
    fn never_panics_on_structured_noise(
        parts in prop::collection::vec(
            prop_oneof![Just(";"), Just("&&"), Just("|"), Just("rm"), Just("-rf"),
                        Just("\""), Just("'"), Just("/"), Just("git")],
            0..20,
        )
    ) {
        let line = parts.join(" ");
        let _ = classify_line(&line);
    }

    // 2. Chaining a catastrophic command after anything safe is catastrophic.
    #[test]
    fn appending_catastrophe_wins(safe in safe_command(), cat in catastrophic_command()) {
        let line = format!("{safe} && {cat}");
        prop_assert_eq!(classify_line(&line).class, Class::Catastrophic);
    }

    // 3. ...and prepending too (worst-of across segments, order-independent).
    #[test]
    fn prepending_catastrophe_wins(safe in safe_command(), cat in catastrophic_command()) {
        let line = format!("{cat} ; {safe}");
        prop_assert_eq!(classify_line(&line).class, Class::Catastrophic);
    }

    // 4. A catastrophic command stays catastrophic under a sudo prefix.
    #[test]
    fn sudo_never_downgrades(cat in catastrophic_command()) {
        prop_assert_eq!(classify_line(&format!("sudo {cat}")).class, Class::Catastrophic);
    }

    // 5. A recursive rm is catastrophic regardless of trailing arguments.
    #[test]
    fn recursive_rm_always_catastrophic(extra in "[a-z/.]{0,20}") {
        let line = format!("rm -rf {extra}");
        prop_assert_eq!(classify_line(&line).class, Class::Catastrophic);
    }

    // 6. A safe command never becomes catastrophic by adding plain-word args.
    #[test]
    fn safe_stays_non_catastrophic_with_word_args(word in "[a-zA-Z0-9_.-]{1,12}") {
        let line = format!("ls {word}");
        prop_assert_ne!(classify_line(&line).class, Class::Catastrophic);
    }
}
