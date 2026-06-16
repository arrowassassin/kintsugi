//! Filtering, search, session grouping, redaction, and hard-purge re-chain.

use kintsugi_core::{Class, Decision, EventLog, Filter, ProposedCommand, Verdict};
use time::{Duration, OffsetDateTime};

fn cmd(agent: &str, session: Option<&str>, raw: &str) -> ProposedCommand {
    ProposedCommand::new(
        agent,
        "/tmp/project",
        raw.split_whitespace().map(str::to_string).collect(),
        raw,
    )
    .with_session(session.map(str::to_string))
}

fn allow() -> Verdict {
    Verdict::rules(Class::Safe, Decision::Allow, "test")
}

fn cat() -> Verdict {
    Verdict::rules(Class::Catastrophic, Decision::Deny, "disk:rm")
}

fn seed() -> EventLog {
    let log = EventLog::open_in_memory().unwrap();
    log.log_event(
        &cmd("claude-code", Some("s1"), "git status"),
        &allow(),
        None,
    )
    .unwrap();
    log.log_event(
        &cmd("claude-code", Some("s1"), "rm -rf build"),
        &cat(),
        None,
    )
    .unwrap();
    log.log_event(&cmd("cursor", Some("s2"), "npm test"), &allow(), None)
        .unwrap();
    log.log_event(&cmd("shim", None, "git push --force"), &cat(), None)
        .unwrap();
    log
}

#[test]
fn limit_and_offset_paginate_newest_first() {
    let log = seed(); // 4 events: git status, rm -rf build, npm test, git push --force
                      // Page 1 (limit 2, offset 0) = the two newest, returned oldest-first.
    let page1 = log
        .query(&Filter {
            limit: Some(2),
            offset: Some(0),
            ..Filter::default()
        })
        .unwrap();
    assert_eq!(page1.len(), 2);
    assert_eq!(page1[0].command, "npm test");
    assert_eq!(page1[1].command, "git push --force");

    // Page 2 (limit 2, offset 2) = the next two older.
    let page2 = log
        .query(&Filter {
            limit: Some(2),
            offset: Some(2),
            ..Filter::default()
        })
        .unwrap();
    assert_eq!(page2.len(), 2);
    assert_eq!(page2[0].command, "git status");
    assert_eq!(page2[1].command, "rm -rf build");

    // Past the end → empty.
    let page3 = log
        .query(&Filter {
            limit: Some(2),
            offset: Some(4),
            ..Filter::default()
        })
        .unwrap();
    assert!(page3.is_empty());
}

#[test]
fn filters_by_agent_session_class_and_grep() {
    let log = seed();

    let by_agent = log
        .query(&Filter {
            agent: Some("claude-code".into()),
            ..Filter::default()
        })
        .unwrap();
    assert_eq!(by_agent.len(), 2);
    assert!(by_agent.iter().all(|e| e.agent == "claude-code"));

    let by_session = log
        .query(&Filter {
            session: Some("s2".into()),
            ..Filter::default()
        })
        .unwrap();
    assert_eq!(by_session.len(), 1);
    assert_eq!(by_session[0].command, "npm test");
    assert_eq!(by_session[0].session.as_deref(), Some("s2"));

    let cats = log
        .query(&Filter {
            class: Some(Class::Catastrophic),
            ..Filter::default()
        })
        .unwrap();
    assert_eq!(cats.len(), 2);

    let grep = log
        .query(&Filter {
            grep: Some("push".into()),
            ..Filter::default()
        })
        .unwrap();
    assert_eq!(grep.len(), 1);
    assert_eq!(grep[0].command, "git push --force");
}

#[test]
fn grep_treats_wildcards_literally() {
    let log = EventLog::open_in_memory().unwrap();
    log.log_event(&cmd("shim", None, "echo 100% done"), &allow(), None)
        .unwrap();
    log.log_event(&cmd("shim", None, "echo nothing"), &allow(), None)
        .unwrap();
    let hits = log
        .query(&Filter {
            grep: Some("100%".into()),
            ..Filter::default()
        })
        .unwrap();
    assert_eq!(hits.len(), 1, "'%' must match literally, not as a wildcard");
}

#[test]
fn since_until_window_selects_by_time() {
    let log = seed();
    let now = OffsetDateTime::now_utc();
    let all = log
        .query(&Filter {
            since: Some(now - Duration::hours(1)),
            ..Filter::default()
        })
        .unwrap();
    assert_eq!(all.len(), 4);
    let none = log
        .query(&Filter {
            since: Some(now + Duration::hours(1)),
            ..Filter::default()
        })
        .unwrap();
    assert!(none.is_empty());
}

#[test]
fn redaction_hides_from_views_but_keeps_chain_intact() {
    let log = seed();
    let target = log
        .query(&Filter {
            grep: Some("push".into()),
            ..Filter::default()
        })
        .unwrap()[0]
        .clone();

    assert!(log
        .redact(&target.id.to_string(), "contained a token")
        .unwrap());
    // Idempotent: a second redaction reports "nothing new".
    assert!(!log.redact(&target.id.to_string(), "again").unwrap());

    // Hidden from the default view, visible with include_redacted.
    let visible = log.query(&Filter::default()).unwrap();
    assert_eq!(visible.len(), 3);
    assert!(visible.iter().all(|e| e.command != "git push --force"));

    let with_redacted = log
        .query(&Filter {
            include_redacted: true,
            ..Filter::default()
        })
        .unwrap();
    assert_eq!(with_redacted.len(), 4);
    assert!(with_redacted
        .iter()
        .any(|e| e.redacted && e.command == "git push --force"));

    // The chain is untouched — redaction never mutates events.
    assert!(log.verify_chain().unwrap().is_intact());
}

#[test]
fn redact_unknown_id_is_false() {
    let log = seed();
    assert!(!log.redact("not-a-real-id", "x").unwrap());
}

#[test]
fn bulk_redact_by_filter() {
    let log = seed();
    let n = log
        .redact_matching(
            &Filter {
                agent: Some("claude-code".into()),
                ..Filter::default()
            },
            "cleanup",
        )
        .unwrap();
    assert_eq!(n, 2);
    assert!(log.query(&Filter::default()).unwrap().len() == 2);
    assert!(log.verify_chain().unwrap().is_intact());
}

#[test]
fn hard_purge_removes_rows_rechains_and_logs_marker() {
    let log = seed();
    let removed = log
        .purge_matching(
            &Filter {
                agent: Some("claude-code".into()),
                ..Filter::default()
            },
            "privacy",
        )
        .unwrap();
    assert_eq!(removed, 2);

    // The two claude-code rows are gone; a purge marker was appended.
    let all = log
        .query(&Filter {
            include_redacted: true,
            ..Filter::default()
        })
        .unwrap();
    assert!(all.iter().all(|e| e.agent != "claude-code"));
    assert!(all.iter().any(|e| e.reason == "audit:purge"));

    // After re-chain the chain is valid again.
    assert!(
        log.verify_chain().unwrap().is_intact(),
        "purge must rebuild a valid chain"
    );
}

#[test]
fn purge_matching_nothing_is_a_noop() {
    let log = seed();
    let removed = log
        .purge_matching(
            &Filter {
                agent: Some("nobody".into()),
                ..Filter::default()
            },
            "x",
        )
        .unwrap();
    assert_eq!(removed, 0);
    // No marker event added when nothing matched.
    assert_eq!(log.count().unwrap(), 4);
    assert!(log.verify_chain().unwrap().is_intact());
}

#[test]
fn count_matching_respects_filter() {
    let log = seed();
    assert_eq!(
        log.count_matching(&Filter {
            class: Some(Class::Catastrophic),
            ..Filter::default()
        })
        .unwrap(),
        2
    );
}
