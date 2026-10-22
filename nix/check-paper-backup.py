"""Validate the actual A5 recovery artifact against the Rust scheme and wordlist."""
import hashlib
import re
import subprocess
import sys
from pathlib import Path


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


pdf, wordlist_path, backup_path, master_path, kind = sys.argv[1:]
require(kind in ("compact", "raw"), "Unknown backup variant")
backup_source = Path(backup_path).read_text()
constant = "RAW_WORD_COUNT" if kind == "raw" else "COMPACT_WORD_COUNT"
words = int(re.search(rf"{constant}:\s*usize\s*=\s*(\d+)", backup_source)[1])
payload = 32 if kind == "raw" else 20
body_length = 18 + payload
tag = 0 if kind == "raw" else 1
info = command("pdfinfo", "-f", "1", "-l", "10000", pdf)
count = int(re.search(r"^Pages:\s+(\d+)", info, re.MULTILINE)[1])
require(count == 10, f"Expected 10 A5 pages, got {count}")
sizes = re.findall(r"Page\s+\d+ size:\s+([\d.]+) x ([\d.]+) pts", info)
require(len(sizes) == count, "Cannot inspect every PDF page size")
for width, height in sizes:
    require(abs(float(width) - 148 / 25.4 * 72) < 0.1, "Page width is not A5")
    require(abs(float(height) - 210 / 25.4 * 72) < 0.1, "Page height is not A5")

text = command("pdftotext", "-layout", pdf, "-")
pages = text.split("\f")
first_count = (words + 1) // 2
for page, first, end in [(pages[0], 1, first_count), (pages[1], first_count + 1, words)]:
    slots = [int(value) for value in re.findall(r"\b(\d{2})\.", page)]
    require(slots == list(range(first, end + 1)), "Handwriting slots are missing or out of order")
require(f"{words} words" in pages[0], "Incorrect word count on the cover")
require("Decode the backup" in pages[2], "Seed recovery instructions moved or are missing")
require("Restore the master key" in pages[3], "OpenPGP recovery instructions moved or are missing")
require("BE32" in pages[3] and "Reuse this stored time" in pages[3], "Stored timestamp recovery is missing")
recovery_text = re.sub(r"\s+", " ", pages[3])
require(
    re.search(r"Self-certify.*?current export time, certification-only flags", recovery_text),
    "Self-certification must use current export time, not the stored key timestamp",
)
require("Recovery certifies the written User ID anew" in recovery_text, "Fresh certification semantics are missing")
require("fresh signatures can reactivate retired User IDs" in recovery_text, "Certificate merge caveat is missing")

wordlist_bytes = Path(wordlist_path).read_bytes()
expected_words = wordlist_bytes.decode("ascii").splitlines()
actual_words = re.findall(r"(?<!\S)([0-9]{4})[ \t]+([a-z]+)\b", "\n".join(pages[4:]))
require(actual_words == [(f"{i:04}", word) for i, word in enumerate(expected_words)], "Indexed appendix differs from the canonical wordlist")
expected_hash = re.search(r'WORDLIST_SHA256:\s*&str\s*=\s*"([a-f0-9]{64})"', backup_source)[1]
require(hashlib.sha256(wordlist_bytes).hexdigest() == expected_hash, "Wordlist hash is not pinned correctly")
compact_text = re.sub(r"\s+", "", text)
require("else[" not in compact_text, "Typst conditional was printed as recovery instructions")
require(expected_hash in compact_text, "Printed wordlist hash is wrong")
checksum_domain = re.search(r'CHECKSUM_DOMAIN:.*?b"([^"\\]+)', backup_source)[1]
require(checksum_domain in text, "Printed checksum domain is wrong")
version = int(re.search(r"SCHEME_VERSION:\s*u8\s*=\s*(\d+)", backup_source)[1])
for expected in [
    f"Version{version:02x}",
    "[13,17)Creationtimestamp:unsignedbig-endianUnixseconds",
    f"[17,18)Tag{tag:02x}:",
    f"[18,{body_length}){payload}bytesofsecretpayload",
    f"[{body_length},{body_length + 5})First5bytes",
    f"serialized_bytes[0:{body_length}]",
]:
    require(expected in compact_text, f"Printed binary field differs from the scheme: {expected}")
master_source = Path(master_path).read_text()
if kind == "compact":
    require("final 6 bits are zero" in text, "Compact padding validation is missing")
    for name in ["MASTER_SALT", "MASTER_INFO"]:
        value = re.search(rf'{name}:.*?b"([^"]+)"', master_source)[1]
        require(value in text, f"Printed HKDF parameter differs: {name}")
    require("stored 20-byte entropy" in text, "Compact HKDF input size is wrong")
else:
    require("There are no padding bits" in text, "Raw padding instructions are wrong")
    require("DonotapplyHKDF" in compact_text, "Raw recovery must explicitly bypass HKDF")
print(f"Verified {kind}: {count} A5 pages, {words} handwriting slots, recovery parameters, and all {len(expected_words)} words")
