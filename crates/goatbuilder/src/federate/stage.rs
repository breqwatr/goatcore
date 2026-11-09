//! The words of `goatbuilder federate`: the stages a peering goes through
//! (`plan`, `deploy`, `test`, `status`), each runnable alone, and the six
//! package verbs. None of them can name a partner.

/// Words that can never be a partner's name.
pub const RESERVED: &[&str] = &[
    "init", "lint", "compose", "diff", "verify", "apply", "status", "plan", "deploy", "test",
];

/// The partner-name check every config gets: a reserved word cannot be one.
pub fn reserved_partner(with: &str) -> Option<String> {
    RESERVED.contains(&with).then(|| {
        format!(
            "'{with}' is a word of `goatbuilder federate` ({}) and cannot name a partner",
            RESERVED.join(", ")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_words_never_name_a_partner() {
        for w in RESERVED {
            assert!(reserved_partner(w).is_some(), "{w}");
        }
        assert!(reserved_partner("xab").is_none());
    }
}
