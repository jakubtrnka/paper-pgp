use crate::backup::WORDLIST;
use std::fmt::Write;

/// A standalone Typst document sharing its layout with the Nix-built PDF.
/// Embed the pinned wordlist so this export can be compiled outside the repo.
pub fn template() -> String {
    let mut source = String::from(include_str!("../paper-backup/template.typ"));
    source.push_str("\n#backup-document((\n");
    for word in WORDLIST.lines() {
        // The pinned wordlist contains only lowercase ASCII letters.
        writeln!(source, "  \"{word}\",").unwrap();
    }
    source.push_str("))\n");
    source
}
