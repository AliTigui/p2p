#!/usr/bin/env python3
"""Static guard for diagnostic-output regressions.

The guard is intentionally small and dependency-free so it can run in CI before
Rust compilation. It rejects:

* raw stdout/stderr macros in production Rust code unless the line, or one of
  the three preceding lines, carries an auditable
  ``diagnostic-guard-allow: <reason>`` marker;
* derived ``Debug`` on types that deliberately use a hand-written redacted
  implementation;
* derived ``Debug`` on types whose name or named fields indicate secret
  material.

Inline ``#[cfg(test)]`` modules and dedicated test directories are skipped so
test-only assertions and debug comparisons remain possible. The checker runs a
small self-test before scanning the repository so a broken regex fails closed.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[1]

ALLOW_MARKER = "diagnostic-guard-allow:"
RAW_OUTPUT_MACRO = re.compile(r"\b(?:println|eprintln|dbg|print|eprint)!\s*\(")
LINE_COMMENT = re.compile(r"//.*$")

DERIVE_DEBUG = re.compile(
    r"#\[derive\((?P<derive>[^\]\n]*\bDebug\b[^\]\n]*)\)\][ \t]*\n"
    r"(?:#\[[^\]\n]*\][ \t]*\n)*"
    r"[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?"
    r"(?:struct|enum|union|type)[ \t]+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
NAMED_FIELD = re.compile(
    r"(?m)^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*:"
)
TEST_MODULE_ATTR = re.compile(r"#\[cfg\([^\]]*\btest\b[^\]]*\)\]")
TEST_MODULE_DECL = re.compile(r"^[ \t]*(?:pub[ \t]+)?mod[ \t]+[A-Za-z_][A-Za-z0-9_]*")

# Types whose Debug output is intentionally hand-written, omitted, or known to
# carry local data that must not enter diagnostics. Adding a derived Debug to
# one of these must fail review.
PROTECTED_TYPES = frozenset(
    {
        "AttachmentMeta",
        "ChannelFrame",
        "ChannelFrameKind",
        "ChannelInfo",
        "ChannelState",
        "ChatMessage",
        "Conversation",
        "ConversationState",
        "ControlEvent",
        "DecryptedApplication",
        "DecryptedMessage",
        "EncryptedIdentity",
        "Envelope",
        "FileConfig",
        "FileEnvelope",
        "FileEvent",
        "FileMessage",
        "Fingerprint",
        "Identity",
        "IdentitySigner",
        "IncomingFile",
        "MessengerController",
        "MlsConversation",
        "MlsKeyPackage",
        "MlsSession",
        "OutgoingFile",
        "PendingKeyPackage",
        "PendingOperation",
        "ProfileRecord",
        "QueuedMessage",
        "ReleasedFile",
        "RequestOutcome",
        "ScanRequest",
        "SecurityConfig",
        "Session",
        "SetupEnvelope",
        "SetupEvent",
        "SetupMessage",
        "Subkeys",
        "Vault",
    }
)

# Names that clearly advertise secret material. Deliberately narrower than a
# generic "key" match so public-key and request-ID view types remain allowed.
SECRET_TYPE_NAME = re.compile(
    r"(?i)(?:password|passwd|secret|private[_-]?key|master[_-]?key|"
    r"wrapped[_-]?master|kek|ciphertext|plaintext|cleartext|"
    r"content[_-]?key|file[_-]?key|identity[_-]?key|signature|nonce)"
)

# Named fields that must never be printed by a derived Debug implementation.
SECRET_FIELD_NAME = re.compile(
    r"(?i)(?:password|passwd|secret|private[_-]?key|master|wrapped|kek|"
    r"key[_-]?package|welcome|commit[_-]?bytes|signature|signed[_-]?bytes|"
    r"ciphertext|encrypted[_-]?bytes|plaintext|cleartext|content[_-]?key|"
    r"file[_-]?key|identity[_-]?key|nonce|credential|"
    r"response[_-]?bytes|envelope[_-]?bytes|key[_-]?bytes|scan[_-]?bytes)"
)


class Violation(NamedTuple):
    path: str
    line: int
    message: str


def test_ranges(source: str) -> list[tuple[int, int]]:
    """Return inclusive 1-based line ranges for inline #[cfg(test)] modules."""
    lines = source.splitlines()
    ranges: list[tuple[int, int]] = []
    for index, line in enumerate(lines):
        if not TEST_MODULE_ATTR.search(line):
            continue
        declaration = None
        for lookahead in range(index + 1, min(index + 4, len(lines))):
            if TEST_MODULE_DECL.match(lines[lookahead]):
                declaration = lookahead
                break
        if declaration is None:
            continue

        depth = 0
        started = False
        for cursor in range(declaration, len(lines)):
            for character in lines[cursor]:
                if character == "{":
                    depth += 1
                    started = True
                elif character == "}":
                    depth -= 1
            if started and depth <= 0:
                ranges.append((index + 1, cursor + 1))
                break
    return ranges


def in_test_region(line_number: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= line_number <= end for start, end in ranges)


def is_test_path(relative: Path) -> bool:
    parts = relative.parts
    return "tests" in parts or relative.name.startswith("test_") or relative.name.endswith("_test.rs")


def has_allow_marker(lines: list[str], index: int) -> bool:
    """Allow a marker on the macro line or up to three lines above it."""
    for candidate in lines[max(0, index - 3) : index + 1]:
        if ALLOW_MARKER not in candidate:
            continue
        reason = candidate.split(ALLOW_MARKER, 1)[1].strip()
        if len(reason) >= 8:
            return True
    return False


def item_body(source: str, match: re.Match[str]) -> str:
    """Return the body of a derived struct/enum, or tuple-field text."""
    start = match.start()
    tail = source[start : start + 8192]
    relative_end = match.end() - start
    open_brace = tail.find("{", relative_end)
    semicolon = tail.find(";", relative_end)

    if semicolon != -1 and (open_brace == -1 or semicolon < open_brace):
        return tail[relative_end:semicolon]
    if open_brace == -1:
        return ""

    depth = 0
    for offset in range(open_brace, len(tail)):
        if tail[offset] == "{":
            depth += 1
        elif tail[offset] == "}":
            depth -= 1
            if depth == 0:
                return tail[open_brace + 1 : offset]
    return tail[open_brace + 1 :]


def scan_source(source: str, relative: Path) -> list[Violation]:
    if is_test_path(relative):
        return []

    lines = source.splitlines()
    ranges = test_ranges(source)
    violations: list[Violation] = []

    for index, raw_line in enumerate(lines):
        line_number = index + 1
        if in_test_region(line_number, ranges):
            continue
        code = LINE_COMMENT.sub("", raw_line)
        if RAW_OUTPUT_MACRO.search(code) and not has_allow_marker(lines, index):
            violations.append(
                Violation(
                    str(relative),
                    line_number,
                    "raw output macro needs a diagnostic-guard-allow marker",
                )
            )

    for match in DERIVE_DEBUG.finditer(source):
        line_number = source.count("\n", 0, match.start()) + 1
        if in_test_region(line_number, ranges):
            continue

        name = match.group("name")
        reason: str | None = None
        if name in PROTECTED_TYPES:
            reason = f"type {name} requires a hand-written or omitted Debug"
        elif SECRET_TYPE_NAME.search(name):
            reason = f"type name {name} indicates secret material"
        else:
            for field in NAMED_FIELD.findall(item_body(source, match)):
                # Length/count metadata is not secret material.
                if field.endswith("_len") or field in {"len", "size", "count"}:
                    continue
                if SECRET_FIELD_NAME.search(field):
                    reason = f"field {field} in {name} indicates secret material"
                    break

        if reason is not None:
            violations.append(Violation(str(relative), line_number, reason))

    return violations


def rust_files() -> list[Path]:
    """Prefer tracked files; fall back to a local walk outside a git checkout."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "*.rs"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        )
        tracked = [Path(raw.decode("utf-8")) for raw in result.stdout.split(b"\0") if raw]
        if tracked:
            return tracked
    except (OSError, subprocess.CalledProcessError):
        pass

    return [
        Path(os.path.relpath(path, ROOT))
        for path in ROOT.rglob("*.rs")
        if "target" not in path.parts and ".git" not in path.parts
    ]


def run_self_tests() -> None:
    checks = [
        (
            'fn main() { println!("{}", secret); }',
            "src/main.rs",
            True,
            "raw macro is detected",
        ),
        (
            "fn main() {\n    // diagnostic-guard-allow: static build guidance only\n    eprintln!(\"hint\");\n}",
            "src/main.rs",
            False,
            "marked static macro is allowed",
        ),
        (
            "#[derive(Debug)]\npub struct Vault { directory: PathBuf }",
            "src/storage.rs",
            True,
            "protected type is detected",
        ),
        (
            "#[derive(Debug)]\npub struct Export { password: String }",
            "src/export.rs",
            True,
            "sensitive field is detected",
        ),
        (
            "#[derive(Debug)]\npub struct Status { count: usize }",
            "src/status.rs",
            False,
            "plain view type is allowed",
        ),
        (
            "#[cfg(test)]\nmod tests {\n    #[derive(Debug)]\n    struct Fixture { secret: Vec<u8> }\n}",
            "src/lib.rs",
            False,
            "inline test module is skipped",
        ),
    ]
    for source, path, should_fail, label in checks:
        found = bool(scan_source(source, Path(path)))
        if found != should_fail:
            raise AssertionError(f"self-test failed: {label}")


def main() -> int:
    try:
        run_self_tests()
    except AssertionError as error:
        print(f"Diagnostic guard self-test failed: {error}", file=sys.stderr)
        return 1

    files = rust_files()
    violations: list[Violation] = []
    for relative in files:
        path = ROOT / relative
        if not path.is_file():
            continue
        violations.extend(scan_source(path.read_text(encoding="utf-8"), relative))

    if violations:
        print(f"Diagnostic guard failed for {len(violations)} finding(s):", file=sys.stderr)
        for violation in violations:
            print(
                f"  {violation.path}:{violation.line}: {violation.message}",
                file=sys.stderr,
            )
        return 1

    print(f"Diagnostic guard passed: {len(files)} Rust source file(s) checked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
