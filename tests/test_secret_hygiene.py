import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCAN_ROOTS = [
    ROOT / "docs",
    ROOT / "knowledge",
    ROOT / "governance",
    ROOT / ".github",
]
SCAN_FILES = [ROOT / "README.md", ROOT / "AGENTS.md"]
TEXT_SUFFIXES = {".md", ".json", ".yml", ".yaml", ".txt", ".ini", ".env"}

PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "github_token": re.compile(r"\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "bearer_token": re.compile(r"\bBearer\s+[A-Za-z0-9._~-]{20,}\b", re.IGNORECASE),
    "credential_url": re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/:]+:[^\s/@]{4,}@", re.IGNORECASE),
    "literal_secret_assignment": re.compile(
        r"(?im)^\s*[\"']?(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)[\"']?\s*[:=]\s*[\"']([^\"']{8,})[\"']\s*,?\s*$"
    ),
}

SAFE_LITERAL_VALUES = {
    "<redacted>",
    "<masked>",
    "redacted",
    "placeholder",
    "changeme",
    "example-only",
}


def iter_scanned_files():
    yielded = set()
    for path in SCAN_FILES:
        if path.is_file():
            yielded.add(path)
            yield path
    for root in SCAN_ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES and path not in yielded:
                yielded.add(path)
                yield path


def test_docs_knowledge_governance_and_examples_contain_no_likely_secrets():
    violations = []
    for path in iter_scanned_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for name, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                if name == "literal_secret_assignment":
                    value = match.group(1).strip().lower()
                    if value in SAFE_LITERAL_VALUES or value.startswith("${"):
                        continue
                line = text.count("\n", 0, match.start()) + 1
                violations.append(f"{path.relative_to(ROOT)}:{line}:{name}")

    assert not violations, "Potential committed secret material detected: " + ", ".join(violations)


def test_read_only_inventory_cli_has_no_password_argument():
    text = (ROOT / "cbs250_readonly_inventory.py").read_text(encoding="utf-8")
    assert 'add_argument("--password"' not in text
    assert "getpass.getpass" in text
