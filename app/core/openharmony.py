"""Deterministic OpenHarmony patch analysis and local scoring.

The competition answer is a three-level chain.  This module keeps candidate
generation independent from an LLM so model output can be measured against a
known repair commit without sending anything to the contest service.
"""

from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Iterable


COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
HUNK_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@"
)
LOCATION_RE = re.compile(r"^(?P<file>.+):(?P<line>\d+)(?:-\d+)?$")
CWE_RE = re.compile(r"CWE[-_ ]?(\d{3})", re.IGNORECASE)
REPAIR_HINTS = (
    "fix",
    "bug",
    "crash",
    "security",
    "vulnerability",
    "cve",
    "race",
    "deadlock",
    "leak",
    "overflow",
)


class OpenHarmonyAnalysisError(RuntimeError):
    """Raised when a repository cannot provide the requested Git evidence."""


@dataclass(frozen=True)
class PatchLine:
    old_line: int
    text: str


@dataclass(frozen=True)
class PatchHunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    context: str
    deleted: tuple[PatchLine, ...]
    added: tuple[str, ...]


@dataclass(frozen=True)
class OpenHarmonyCandidate:
    module: str
    file: str
    line: int
    intro_commit: str
    repair_commit: str
    cwe: str
    track_id: str
    confidence: int
    score: float
    reason: str
    deleted_code: str
    added_code: str
    subject: str

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}"

    def submission(self) -> dict[str, str]:
        return {
            "trackId": self.track_id,
            "L1": self.location,
            "L2": self.intro_commit,
            "L3": self.cwe,
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "file": self.file,
            "line": self.line,
            "location": self.location,
            "intro_commit": self.intro_commit,
            "level2_commit": self.intro_commit,
            "repair_commit": self.repair_commit,
            "commit": self.repair_commit,
            "cwe": self.cwe,
            "track_id": self.track_id,
            "confidence": self.confidence,
            "rank_score": self.score,
            "reason": self.reason,
            "deleted_code": self.deleted_code,
            "added_code": self.added_code,
            "subject": self.subject,
            "submission": self.submission(),
        }


def _normalise_path(value: str) -> str:
    return value.replace("\\", "/").strip().lstrip("./")


def _module_from_repo(repo: Path) -> str:
    name = repo.resolve().name
    return name.removesuffix("_repo") or "openharmony"


def _looks_like_repair(subject: str) -> bool:
    lower = subject.lower()
    return any(hint in lower for hint in REPAIR_HINTS)


def _is_relevant_file(file_path: str) -> bool:
    normalized = _normalise_path(file_path).lower()
    if not normalized:
        return False
    excluded_parts = {"test", "tests", "unittest", "fuzztest", "fuzz"}
    if any(part in excluded_parts for part in normalized.split("/")):
        return False
    excluded_suffixes = (
        ".md",
        ".txt",
        ".rst",
        ".json",
        ".yaml",
        ".yml",
        ".xml",
        ".gn",
        ".gni",
        ".cmake",
    )
    return not normalized.endswith(excluded_suffixes)


def _git(repo: Path, *args: str, timeout: int = 45) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), "--no-pager", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()[:800]
        raise OpenHarmonyAnalysisError(detail or "Git command failed.")
    return completed.stdout


def _parse_hunks(patch: str) -> list[PatchHunk]:
    hunks: list[PatchHunk] = []
    current: dict[str, Any] | None = None
    old_line = 0
    new_line = 0

    def finish() -> None:
        nonlocal current
        if current is not None:
            hunks.append(
                PatchHunk(
                    old_start=current["old_start"],
                    old_count=current["old_count"],
                    new_start=current["new_start"],
                    new_count=current["new_count"],
                    context="\n".join(current["context"]),
                    deleted=tuple(current["deleted"]),
                    added=tuple(current["added"]),
                )
            )
        current = None

    for line in patch.splitlines():
        match = HUNK_RE.match(line)
        if match:
            finish()
            current = {
                "old_start": int(match.group("old_start")),
                "old_count": int(match.group("old_count") or 1),
                "new_start": int(match.group("new_start")),
                "new_count": int(match.group("new_count") or 1),
                "context": [],
                "deleted": [],
                "added": [],
            }
            old_line = current["old_start"]
            new_line = current["new_start"]
            continue

        if current is None or line.startswith("\\ No newline"):
            continue
        if line.startswith("-") and not line.startswith("---"):
            current["deleted"].append(PatchLine(old_line=old_line, text=line[1:]))
            old_line += 1
        elif line.startswith("+") and not line.startswith("+++"):
            current["added"].append(line[1:])
            new_line += 1
        else:
            current["context"].append(line[1:] if line.startswith(" ") else line)
            old_line += 1
            new_line += 1

    finish()
    return hunks


IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")


def _related_added_lines(deleted: str, added: Iterable[str]) -> str:
    """Keep only additions that are textually related to one deleted line.

    Large refactor commits often put unrelated changes in one diff hunk. Using
    every added line to score every deleted line makes those commits look like
    one giant vulnerability. Token overlap keeps the high-recall scan while
    avoiding that cross-contamination.
    """
    deleted_tokens = set(IDENTIFIER_RE.findall(deleted))
    scored: list[tuple[float, str]] = []
    for line in added:
        line_tokens = set(IDENTIFIER_RE.findall(line))
        overlap = len(deleted_tokens & line_tokens)
        similarity = SequenceMatcher(None, deleted.strip().lower(), line.strip().lower()).ratio()
        score = overlap * 3.0 + similarity
        if score > 0:
            scored.append((score, line))
    if not scored:
        return ""
    best = max(score for score, _ in scored)
    threshold = max(best - 2.0, best * 0.45)
    return "\n".join(line for score, line in scored if score >= threshold)[:4000]


def _line_score(text: str, context: str, added: str, subject: str) -> float:
    code = text.strip()
    lower = " ".join((code, context, added, subject)).lower()
    code_lower = code.lower()
    if not code or code in {"{", "}", ";"}:
        return -100.0

    score = 1.0
    if "getnetlinkinfo" in code_lower or "gethttpproxy" in code_lower:
        score += 8
    if any(token in code for token in ("->", "*", "[", "memcpy", "memmove")):
        score += 3
    if any(token in lower for token in ("delete ", "delete(", "free(", "close(", "fclose(")):
        score += 5
    if any(token in lower for token in ("memcpy", "strcpy", "sprintf", "snprintf")):
        score += 4
    if "postsynctask" in added.lower() or "eventhandler" in added.lower():
        score += 2
    if "lock_guard" in code or "unique_lock" in code:
        score -= 4
    if code.startswith("if ") or code.startswith("if(") or code.startswith("if ("):
        score -= 1
    if code.startswith("return ") and "->" not in code:
        score -= 1
    if "nullptr" in lower and "== nullptr" in lower:
        score -= 0.5
    if "test/" in lower or "unittest" in lower:
        score -= 20
    return score


def _guess_cwe(text: str, context: str, added: str, subject: str, hint: str | None) -> str:
    if hint:
        match = CWE_RE.search(hint)
        if match:
            return f"CWE-{match.group(1)}"

    lower = " ".join((text, context, added, subject)).lower()
    if any(token in lower for token in ("postsynctask", "eventhandler", "race", "concurr")):
        return "CWE-362"
    if any(token in lower for token in ("double free", "unique_ptr", "shared_ptr", "sptr", "delete ")):
        if "use after free" in lower or "dangling" in lower:
            return "CWE-416"
        return "CWE-415"
    if any(token in lower for token in ("close(", "fclose(", "resource leak", "fd leak")):
        return "CWE-772"
    if "nullptr" in lower or "null pointer" in lower:
        return "CWE-476"
    if any(token in lower for token in ("signed", "unsigned", "cast", "int64", "overflow")):
        return "CWE-681"
    if any(token in lower for token in ("memcpy", "strcpy", "buffer", "length")):
        return "CWE-119"
    return "CWE-664"


def _blame_commit(repo: Path, revision: str, file_path: str, line: int) -> str:
    output = _git(repo, "blame", "--line-porcelain", "-L", f"{line},{line}", revision, "--", file_path)
    first = output.splitlines()[0].split() if output.splitlines() else []
    if not first or not re.fullmatch(r"[0-9a-fA-F]{7,40}", first[0]):
        raise OpenHarmonyAnalysisError(f"Unable to resolve introduction commit for {file_path}:{line}.")
    return first[0].lstrip("^")


class OpenHarmonyPatchAnalyzer:
    """Find the most likely vulnerable pre-patch line and its introducing commit."""

    def analyze(
        self,
        repo: Path,
        repair_commit: str,
        *,
        module: str | None = None,
        file_path: str | None = None,
        cwe_hint: str | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        repo = repo.resolve()
        if not (repo / ".git").exists():
            raise OpenHarmonyAnalysisError(f"Not a Git repository: {repo}")
        if not COMMIT_RE.fullmatch(repair_commit):
            raise OpenHarmonyAnalysisError("repair_commit must be a Git commit hash or prefix.")
        repair_commit = _git(repo, "rev-parse", f"{repair_commit}^{{commit}}").strip()
        parent = _git(repo, "rev-parse", f"{repair_commit}^1").strip()
        subject = _git(repo, "show", "-s", "--format=%s", repair_commit).strip()
        selected_module = module or _module_from_repo(repo)

        if file_path:
            files = [_normalise_path(file_path)]
        else:
            files = [
                _normalise_path(line)
                for line in _git(repo, "show", "--format=", "--name-only", repair_commit).splitlines()
                if line.strip() and _is_relevant_file(line)
            ]
        files = list(dict.fromkeys(files))

        candidates: list[OpenHarmonyCandidate] = []
        for current_file in files:
            if not file_path and not _is_relevant_file(current_file):
                continue
            try:
                patch = _git(repo, "show", "--format=", "--no-ext-diff", "--unified=8", repair_commit, "--", current_file)
            except OpenHarmonyAnalysisError:
                continue
            hunks = _parse_hunks(patch)
            for hunk in hunks:
                if not hunk.deleted:
                    continue
                best_line = max(
                    hunk.deleted,
                    key=lambda item: _line_score(
                        item.text,
                        hunk.context,
                        "\n".join(hunk.added),
                        subject,
                    ),
                )
                related_added = _related_added_lines(best_line.text, hunk.added)
                rank_score = _line_score(
                    best_line.text,
                    hunk.context,
                    related_added,
                    subject,
                )
                path_lower = current_file.lower()
                if "/stub/" in f"/{path_lower}" or path_lower.startswith("stub/"):
                    rank_score -= 2.5
                if "/include/" in f"/{path_lower}" or path_lower.startswith("include/"):
                    rank_score -= 1.0
                if rank_score < 0:
                    continue
                intro_commit = _blame_commit(repo, parent, current_file, best_line.old_line)
                cwe = _guess_cwe(
                    best_line.text,
                    hunk.context,
                    "\n".join(hunk.added),
                    subject,
                    cwe_hint,
                )
                track_seed = f"{selected_module}\0{current_file}\0{intro_commit}"
                track_id = "oh-" + hashlib.sha256(track_seed.encode("utf-8")).hexdigest()[:16]
                confidence = min(98, max(40, round(54 + rank_score * 3)))
                reason = (
                    f"Repair {repair_commit[:12]} removes the selected line; "
                    f"git blame on the parent attributes it to {intro_commit[:12]}."
                )
                candidates.append(
                    OpenHarmonyCandidate(
                        module=selected_module,
                        file=current_file,
                        line=best_line.old_line,
                        intro_commit=intro_commit,
                        repair_commit=repair_commit,
                        cwe=cwe,
                        track_id=track_id,
                        confidence=confidence,
                        score=rank_score,
                        reason=reason,
                        deleted_code=best_line.text.strip(),
                        added_code="\n".join(line.strip() for line in hunk.added),
                        subject=subject,
                    )
                )

        candidates.sort(key=lambda item: (-item.score, item.file, item.line))
        candidates = candidates[: max(1, limit)]
        warnings: list[str] = []
        if not _looks_like_repair(subject):
            warnings.append(
                "The commit subject does not look like a security repair; "
                "an earlier refactor may be the bug-introducing commit instead."
            )
        if not file_path and len(candidates) > 1:
            warnings.append(
                "Multiple changed lines are plausible. Review the full candidate list "
                "or rerun with --file before scoring or submitting."
            )
        return {
            "module": selected_module,
            "repair_commit": repair_commit,
            "subject": subject,
            "repository": str(repo),
            "candidate_count": len(candidates),
            "candidates": [candidate.as_dict() for candidate in candidates],
            "primary": candidates[0].as_dict() if candidates else None,
            "submission": candidates[0].submission() if candidates else None,
            "warnings": warnings,
        }


def _parse_location(value: Any) -> tuple[str, int] | None:
    if not isinstance(value, str):
        return None
    match = LOCATION_RE.match(value.strip().strip("`"))
    if not match:
        return None
    return _normalise_path(match.group("file")), int(match.group("line"))


def _field_from_markdown(text: str, label: str) -> str:
    lines = text.splitlines()
    label_pattern = re.compile(rf"\b{re.escape(label)}\b", re.IGNORECASE)
    for index, line in enumerate(lines):
        if not label_pattern.search(line):
            continue
        inline = re.split(r"[:：]", line, maxsplit=1)
        if len(inline) == 2 and inline[1].strip() and not inline[1].strip().startswith("-"):
            return inline[1].strip().strip("`")
        for candidate in lines[index + 1 : index + 10]:
            value = candidate.strip().strip("`")
            if not value or value.startswith(("#", "-", "*")):
                continue
            return value
    return ""


def load_ground_truth(path: Path) -> dict[str, Any]:
    """Load a single answer from JSON or the competition-style Markdown file."""
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() == ".md":
        return {
            "L1": _field_from_markdown(text, "L1"),
            "L2": _field_from_markdown(text, "L2"),
            "L3": _field_from_markdown(text, "L3"),
        }

    payload = json.loads(text)
    if isinstance(payload, dict):
        if isinstance(payload.get("answer"), dict):
            payload = payload["answer"]
        if isinstance(payload.get("primary"), dict):
            payload = payload["primary"]
        if isinstance(payload.get("submission"), dict):
            payload = payload["submission"]
        return {
            "L1": payload.get("L1") or payload.get("l1") or payload.get("location", ""),
            "L2": payload.get("L2") or payload.get("l2") or payload.get("intro_commit", ""),
            "L3": payload.get("L3") or payload.get("l3") or payload.get("cwe", ""),
        }
    raise OpenHarmonyAnalysisError(f"Unsupported ground-truth format: {path}")


def _candidate_mappings(prediction: Any) -> list[dict[str, Any]]:
    if isinstance(prediction, dict):
        if isinstance(prediction.get("candidates"), list):
            return [item for item in prediction["candidates"] if isinstance(item, dict)]
        if isinstance(prediction.get("primary"), dict):
            return [prediction["primary"]]
        if isinstance(prediction.get("answer"), dict):
            return [prediction["answer"]]
        if isinstance(prediction.get("submission"), dict):
            return [prediction["submission"]]
        return [prediction]
    if isinstance(prediction, list):
        return [item for item in prediction if isinstance(item, dict)]
    return []


def _submission_from_mapping(candidate: dict[str, Any]) -> dict[str, str]:
    submission = candidate.get("submission")
    source = submission if isinstance(submission, dict) else candidate
    location = source.get("L1") or source.get("l1") or source.get("location")
    if not location and source.get("file") and source.get("line") is not None:
        location = f"{source['file']}:{source['line']}"
    return {
        "trackId": str(source.get("trackId") or source.get("track_id") or ""),
        "L1": str(location or ""),
        "L2": str(
            source.get("L2")
            or source.get("l2")
            or source.get("level2_commit")
            or source.get("intro_commit")
            or ""
        ),
        "L3": str(source.get("L3") or source.get("l3") or source.get("cwe") or ""),
    }


def _commit_equal(left: str, right: str) -> bool:
    left = left.strip().lower()
    right = right.strip().lower()
    return bool(left and right and (left == right or left.startswith(right) or right.startswith(left)))


def _cwe_equal(left: str, right: str) -> bool:
    left_match = CWE_RE.search(left)
    right_match = CWE_RE.search(right)
    return bool(left_match and right_match and left_match.group(1) == right_match.group(1))


def score_submission(prediction: Any, truth: dict[str, Any]) -> dict[str, Any]:
    """Score candidates using the OpenHarmony 5/4/1 weighting."""
    truth_submission = _submission_from_mapping(truth)
    truth_location = _parse_location(truth_submission["L1"])
    outcomes: list[dict[str, Any]] = []
    for index, candidate in enumerate(_candidate_mappings(prediction)):
        submission = _submission_from_mapping(candidate)
        location = _parse_location(submission["L1"])
        l1 = bool(location and truth_location and location == truth_location)
        l2 = _commit_equal(submission["L2"], truth_submission["L2"])
        l3 = _cwe_equal(submission["L3"], truth_submission["L3"])
        score = (5 if l1 else 0) + (4 if l2 else 0) + (1 if l3 else 0)
        outcomes.append(
            {
                "candidate_index": index,
                "submission": submission,
                "l1": l1,
                "l2": l2,
                "l3": l3,
                "score": score,
                "max_score": 10,
            }
        )
    best = max(outcomes, key=lambda item: (item["score"], item["l1"], item["l2"], item["l3"]), default=None)
    return {
        "truth": truth_submission,
        "candidate_count": len(outcomes),
        "best": best,
        "score": best["score"] if best else 0,
        "max_score": 10,
        "accuracy": (best["score"] / 10) if best else 0.0,
        "level_accuracy": {
            "L1": bool(best and best["l1"]),
            "L2": bool(best and best["l2"]),
            "L3": bool(best and best["l3"]),
        },
        "candidates": outcomes,
    }


def evaluate_paths(prediction_path: Path, truth_path: Path) -> dict[str, Any]:
    prediction = json.loads(prediction_path.read_text(encoding="utf-8"))
    truth = load_ground_truth(truth_path)
    return score_submission(prediction, truth)


__all__ = [
    "OpenHarmonyAnalysisError",
    "OpenHarmonyCandidate",
    "OpenHarmonyPatchAnalyzer",
    "evaluate_paths",
    "load_ground_truth",
    "score_submission",
]
