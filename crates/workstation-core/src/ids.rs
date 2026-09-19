//! Prefixed, sortable identifiers (`task_01J...`). IDs are opaque handles and
//! never serve as authorization on their own.

use ulid::Ulid;

pub fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", Ulid::new())
}

pub fn task_id() -> String {
    new_id("task")
}
pub fn approval_id() -> String {
    new_id("apr")
}
pub fn client_id() -> String {
    new_id("cl")
}
pub fn credential_id() -> String {
    new_id("cred")
}
pub fn session_id() -> String {
    new_id("ses")
}
pub fn event_id() -> String {
    new_id("evt")
}
pub fn share_id() -> String {
    new_id("shr")
}
pub fn execution_id() -> String {
    new_id("exe")
}
pub fn project_id() -> String {
    new_id("prj")
}
pub fn request_id() -> String {
    new_id("req")
}

/// Returns true if `id` has the given prefix and a well-formed ULID suffix.
pub fn is_valid(id: &str, prefix: &str) -> bool {
    match id.split_once('_') {
        Some((p, rest)) => p == prefix && Ulid::from_string(rest).is_ok(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_prefixed_and_valid() {
        let id = task_id();
        assert!(id.starts_with("task_"));
        assert!(is_valid(&id, "task"));
        assert!(!is_valid(&id, "apr"));
        assert!(!is_valid("task_nope", "task"));
    }
}
