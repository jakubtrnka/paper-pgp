"""Check the compiled recovery artifact, including every indexed word and A5 page."""
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


pdf, wordlist_path, backup_path, master_path = sys.argv[1:]
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
for page, first in [(pages[0], 1), (pages[1], 21)]:
    slots = [int(value) for value in re.findall(r"\b(\d{2})\.", page)]
    require(slots == list(range(first, first + 20)), "Handwriting slots are missing or out of order")
require("Decode the backup" in pages[2], "Seed recovery instructions moved or are missing")
require("Restore the master key" in pages[3], "OpenPGP recovery instructions moved or are missing")

wordlist_bytes = Path(wordlist_path).read_bytes()
expected_words = wordlist_bytes.decode("ascii").splitlines()
actual_words = re.findall(r"(?<!\S)([0-9]{4})[ \t]+([a-z]+)\b", "\n".join(pages[4:]))
require(actual_words == [(f"{i:04}", word) for i, word in enumerate(expected_words)], "Indexed appendix differs from the canonical wordlist")

# Check the printed parameters against the actual Rust scheme, not another copy.
backup_source = Path(backup_path).read_text()
expected_hash = re.search(r'WORDLIST_SHA256:\s*&str\s*=\s*"([a-f0-9]{64})"', backup_source)[1]
require(hashlib.sha256(wordlist_bytes).hexdigest() == expected_hash, "Wordlist hash is not pinned correctly")
compact_text = re.sub(r"\s+", "", text)
require(expected_hash in compact_text, "Printed wordlist hash is wrong")
checksum_domain = re.search(r'CHECKSUM_DOMAIN:.*?b"([^"\\]+)', backup_source)[1]
require(checksum_domain in text, "Printed checksum domain is wrong")
master_source = Path(master_path).read_text()
time = re.search(r"CREATION_TIME:\s*u64\s*=\s*([\d_]+)", master_source)[1].replace("_", "")
require(time in text, "Printed OpenPGP timestamp is wrong")
for parameter in ["gpg-keys/master/v1", "ed25519-certification"]:
    require(parameter in master_source and parameter in text, f"Printed HKDF parameter differs: {parameter}")
print(f"Verified {count} A5 pages, 40 handwriting slots, recovery parameters, and all {len(expected_words)} words")
