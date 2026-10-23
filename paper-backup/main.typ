#import "template.typ": backup-document

// Compile with the repository root: the wordlist is shared with the Rust app.
#let words = read("../data/slip39.txt").trim().split("\n")
#backup-document(words)
