"""Small, dependency-free high-recall scanner used to seed model analysis."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re


@dataclass(frozen=True)
class StaticHit:
    file: str
    line: int
    pattern: str
    code: str
    priority: int


PATTERNS: tuple[tuple[str, re.Pattern[str], int], ...] = (
    ("raw-copy", re.compile(r"\b(memcpy|memmove|strcpy|strcat|sprintf|vsprintf)\s*\("), 9),
    ("formatted-input", re.compile(r"\b(scanf|sscanf|fscanf|getwd|gets)\s*\("), 9),
    ("manual-free", re.compile(r"\b(delete|free|realloc)\b"), 8),
    ("pointer-deref", re.compile(r"(?:->|\*\s*[A-Za-z_][A-Za-z0-9_]*)"), 6),
    ("integer-boundary", re.compile(r"\b(static_cast|reinterpret_cast|uint\d+_t|int\d+_t)\b"), 5),
    ("shared-state", re.compile(r"\b(std::thread|mutex|lock_guard|PostSyncTask|EventHandler)\b"), 5),
)


class StaticCodeAnalyzer:
    """Produce compact source evidence; it intentionally does not verdict findings."""

    ignored_dirs = {".git", "build", "out", "node_modules", "test", "tests", "unittest", "fuzztest"}
    source_suffixes = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}

    def __init__(self, max_files: int = 2000, max_hits: int = 80):
        self.max_files = max_files
        self.max_hits = max_hits

    def _files(self, repo_path: Path) -> list[Path]:
        files: list[Path] = []
        for path in repo_path.rglob("*"):
            if len(files) >= self.max_files:
                break
            if not path.is_file() or path.suffix.lower() not in self.source_suffixes:
                continue
            if any(part.lower() in self.ignored_dirs for part in path.relative_to(repo_path).parts):
                continue
            files.append(path)
        return files

    def find_suspicious_functions(self, repo_path: Path) -> list[dict]:
        hits: list[StaticHit] = []
        for path in self._files(repo_path):
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            relative = path.relative_to(repo_path).as_posix()
            for line_number, line in enumerate(lines, 1):
                for pattern_name, pattern, priority in PATTERNS:
                    if pattern.search(line):
                        hits.append(StaticHit(relative, line_number, pattern_name, line.strip(), priority))
                        break
        hits.sort(key=lambda hit: (-hit.priority, hit.file, hit.line))
        return [
            {
                "file": hit.file,
                "function": "unknown",
                "line": hit.line,
                "reason": hit.pattern,
                "code": hit.code,
                "priority": hit.priority,
            }
            for hit in hits[: self.max_hits]
        ]

    def analyze_repository(self, repo_path: Path) -> str:
        files = self._files(repo_path)
        hits = self.find_suspicious_functions(repo_path)
        by_reason: dict[str, int] = {}
        for hit in hits:
            by_reason[hit["reason"]] = by_reason.get(hit["reason"], 0) + 1
        lines = [
            f"C/C++ source files indexed: {len(files)}",
            "Static scan is high-recall triage only; no hit is a verdict.",
            "Hit counts: " + ", ".join(f"{key}={value}" for key, value in sorted(by_reason.items())),
            "Top source candidates:",
        ]
        lines.extend(
            f"- {hit['file']}:{hit['line']} [{hit['reason']}] {hit['code']}"
            for hit in hits[:40]
        )
        return "\n".join(lines)


__all__ = ["StaticCodeAnalyzer"]
