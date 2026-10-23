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


pdf, wordlist_path, backup_path, master_path = sys.argv[1:]
backup_source = Path(backup_path).read_text()
data_words = int(re.search(r"DATA_WORDS:\s*usize\s*=\s*(\d+)", backup_source)[1])
checksum_words = int(re.search(r"CHECKSUM_WORDS:\s*usize\s*=\s*(\d+)", backup_source)[1])
words = data_words + checksum_words
time_shift = int(re.search(r"TIME_SHIFT:\s*u32\s*=\s*(\d+)", backup_source)[1])
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
require(f"multiplied by {1 << time_shift}" in pages[3] and "Reuse this stored time" in pages[3], "Stored timestamp recovery is missing")
recovery_text = re.sub(r"\s+", " ", pages[3])
require(
    re.search(r"Self-certify.*?current export time, certification-only flags", recovery_text),
    "Self-certification must use current export time, not the stored key timestamp",
)
require("it signs nothing" in recovery_text, "Restore-into-certificate recovery is missing")
require("recovery certifies the written User ID anew" in recovery_text, "Fresh certification semantics are missing")
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

decode_text = re.sub(r"\s+", " ", pages[2])
customization = re.search(r'CUSTOMIZATION:.*?b"([a-z]+)"', backup_source)[1]
codes = " ".join(str(ord(c)) for c in customization)
require(f"`{customization}` ({codes})" in decode_text or f"{customization} ({codes})" in decode_text, "Printed customization string is wrong")
generators = re.findall(r"0x[0-9a-f]+", re.search(r"GEN:\s*\[u32;\s*10\]\s*=\s*\[(.*?)\];", backup_source, re.DOTALL)[1])
require(len(generators) == 10, "Cannot read the generator constants from the source")
for generator in generators:
    require(generator in compact_text, f"Generator constant {generator} is not printed")
version = int(re.search(r"SCHEME_VERSION:\s*u8\s*=\s*(\d+)", backup_source)[1])
entropy_len = int(re.search(r"ENTROPY_LEN:\s*usize\s*=\s*(\d+)", backup_source)[1])
time_bits = 32 - time_shift
for expected in [
    f"[0,8)Version{version:02x}",
    f"[8,{8 + time_bits})Creationtimedividedby{1 << time_shift}",
    f"[{8 + time_bits},{data_words * 10}){entropy_len * 8}bitsofentropy",
    f"{data_words * 10}bits",
]:
    require(expected in compact_text, f"Printed bit field differs from the scheme: {expected}")
master_source = Path(master_path).read_text()
for name in ["MASTER_SALT", "MASTER_INFO"]:
    value = re.search(rf'{name}:.*?b"([^"]+)"', master_source)[1]
    require(value in text, f"Printed HKDF parameter differs: {name}")
require(f"stored {entropy_len}-byte entropy" in text, "HKDF input size is wrong")
print(f"Verified: {count} A5 pages, {words} handwriting slots, recovery parameters, and all {len(expected_words)} words")
