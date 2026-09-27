from __future__ import annotations

import re
import sys
from pathlib import Path

ALLOWED_SUFFIXES = {
    ".html", ".css", ".js", ".json", ".xml", ".txt",
    ".svg", ".png", ".jpg", ".jpeg", ".webp", ".ico",
}
ALLOWED_SPECIAL_FILES = {".nojekyll"}
FORBIDDEN_NAMES = {
    ".env", ".env.local", ".env.production", "secrets.json",
    "delivered_articles.json", "seen_articles.json", "delivery_manifest.json",
    "sources.json", "requirements.txt",
}
FORBIDDEN_SUFFIXES = {
    ".py", ".pyc", ".yml", ".yaml", ".pem", ".key", ".p12", ".pfx",
    ".sqlite", ".sqlite3", ".db", ".csv", ".zip", ".tar", ".gz",
}
MAX_PUBLIC_FILE_BYTES = 5 * 1024 * 1024
TEXT_SUFFIXES = {".html", ".css", ".js", ".json", ".xml", ".txt", ".svg"}

SECRET_PATTERNS = [
    ("GitHub token", re.compile(r"(?:github_pat_[A-Za-z0-9_]{40,}|gh[pousr]_[A-Za-z0-9]{20,})")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("OpenAI-style API key", re.compile(r"sk-[A-Za-z0-9_-]{20,}")),
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("JWT / bearer token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    (
        "Credential assignment",
        re.compile(
            r"(?i)(?:api[_-]?key|access[_-]?token|secret|password|authorization)"
            r"\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{16,}"
        ),
    ),
]

FORBIDDEN_MARKERS = {
    "SUPABASE_SECRET_KEY",
    "GEMINI_API_KEY",
    "LINE_CHANNEL_ACCESS_TOKEN",
    "YUI_AI_NEWS_PUBLISH_TOKEN",
    "SUPABASE_SERVICE_ROLE_KEY",
}


def fail(message: str) -> None:
    print(f"PUBLICATION BLOCKED: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "site").resolve()
    if not root.is_dir():
        fail(f"missing site directory: {root}")

    files = [p for p in root.rglob("*") if p.is_file()]
    if not files:
        fail("site is empty")

    problems = []
    for path in files:
        rel = path.relative_to(root)
        name = path.name
        suffix = path.suffix.lower()

        if name in FORBIDDEN_NAMES:
            problems.append(f"{rel}: forbidden filename")
            continue
        if name.startswith(".") and name not in ALLOWED_SPECIAL_FILES:
            problems.append(f"{rel}: unexpected hidden file")
            continue
        if suffix in FORBIDDEN_SUFFIXES:
            problems.append(f"{rel}: forbidden file type {suffix}")
            continue
        if name not in ALLOWED_SPECIAL_FILES and suffix not in ALLOWED_SUFFIXES:
            problems.append(f"{rel}: file type is not on allowlist")
            continue
        if path.stat().st_size > MAX_PUBLIC_FILE_BYTES:
            problems.append(f"{rel}: unexpectedly large public file")
            continue

        if suffix in TEXT_SUFFIXES or name in ALLOWED_SPECIAL_FILES:
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                problems.append(f"{rel}: expected UTF-8 text")
                continue

            for marker in FORBIDDEN_MARKERS:
                if marker in text:
                    problems.append(f"{rel}: contains forbidden internal marker {marker}")
            for label, pattern in SECRET_PATTERNS:
                if pattern.search(text):
                    problems.append(f"{rel}: possible {label}")

    if problems:
        fail("\n- " + "\n- ".join(problems))

    print(f"Public Pages security gate OK: {len(files)} files checked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
