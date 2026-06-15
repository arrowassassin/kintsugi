//! Coverage for the approval-queue storage on the event log.

use aegis_core::{Class, EventLog, ProposedCommand};

fn cmd(raw: &str) -> ProposedCommand {
    ProposedCommand::new("mcp", "/tmp", vec![raw.into()], raw)
}

#[test]
fn enqueue_list_status_resolve() {
    let log = EventLog::open_in_memory().unwrap();
    let a = cmd("rm a.txt");
    let b = cmd("make deploy");
    log.enqueue_pending(&a, Class::Ambiguous, "ambiguous:rm")
        .unwrap();
    log.enqueue_pending(&b, Class::Ambiguous, "ambiguous:make")
        .unwrap();

    let pending = log.list_pending().unwrap();
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].command.raw, "rm a.txt"); // oldest first
    assert_eq!(pending[0].reason, "ambiguous:rm");

    let id = a.id.to_string();
    assert_eq!(log.pending_status(&id).unwrap().as_deref(), Some("pending"));
    assert_eq!(log.pending_command(&id).unwrap().unwrap().raw, "rm a.txt");

    log.set_pending_status(&id, "approved").unwrap();
    assert_eq!(
        log.pending_status(&id).unwrap().as_deref(),
        Some("approved")
    );
    // Resolved entries leave the queue listing.
    assert_eq!(log.list_pending().unwrap().len(), 1);
}

#[test]
fn enqueue_is_idempotent_on_id() {
    let log = EventLog::open_in_memory().unwrap();
    let c = cmd("rm x");
    log.enqueue_pending(&c, Class::Ambiguous, "r").unwrap();
    log.enqueue_pending(&c, Class::Ambiguous, "r").unwrap();
    assert_eq!(log.list_pending().unwrap().len(), 1);
}

#[test]
fn unknown_id_has_no_status_or_command() {
    let log = EventLog::open_in_memory().unwrap();
    assert!(log.pending_status("nope").unwrap().is_none());
    assert!(log.pending_command("nope").unwrap().is_none());
}

#[test]
fn cas_transitions_exactly_once() {
    let log = EventLog::open_in_memory().unwrap();
    let c = cmd("rm a.txt");
    log.enqueue_pending(&c, Class::Ambiguous, "r").unwrap();
    let id = c.id.to_string();

    // First claim wins; a second claim from `pending` loses (already moved).
    assert!(log.cas_pending_status(&id, "pending", "approved").unwrap());
    assert!(!log.cas_pending_status(&id, "pending", "approved").unwrap());
    // And it's no longer in the queue.
    assert!(log.list_pending().unwrap().is_empty());
    // CAS on an unknown id is a no-op, not an error.
    assert!(!log
        .cas_pending_status("nope", "pending", "approved")
        .unwrap());
}
