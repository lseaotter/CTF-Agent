"""Read and normalize CyberGem run artifacts for the local workbench."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
from typing import Any


RUN_FILE_PATTERN = re.compile(
    r"^(?P<module>[a-z0-9_]+)_(?P<run_id>\d{8}_\d{6})\.json$"
)
COMMIT_PATTERN = re.compile(r"^[0-9a-fA-F]{7,40}$")
LOCATION_PATTERN = re.compile(r"^(?P<file>.+):(?P<line>\d+)(?:-\d+)?$")


class ResultStoreError(RuntimeError):
    pass


class RunNotFound(ResultStoreError):
    pass


class FindingNotFound(ResultStoreError):
    pass


class SourceAccessError(ResultStoreError):
    pass


def _iso_timestamp(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime).astimezone().isoformat()


def _severity(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"critical", "high", "medium", "low"}:
        return normalized
    return "unrated"


def _line_range(file_path: str, lines: list[int]) -> str:
    if not lines:
        return file_path
    if len(lines) == 1:
        return f"{file_path}:{lines[0]}"
    return f"{file_path}:{lines[0]}-{lines[-1]}"


def _snippet(source: str, start: int, end: int) -> dict[str, Any]:
    lines = source.splitlines()
    bounded_start = max(1, start)
    bounded_end = min(len(lines), max(bounded_start, end))
    numbered = [
        {"line": index, "text": lines[index - 1]}
        for index in range(bounded_start, bounded_end + 1)
    ]
    return {
        "start": bounded_start,
        "end": bounded_end,
        "lines": numbered,
        "text": "\n".join(
            f"{item['line']:>5}  {item['text']}" for item in numbered
        ),
    }


def _artifact_module(path: Path, payload: Any) -> str:
    if isinstance(payload, dict) and payload.get("module"):
        return str(payload["module"])
    stem = path.stem
    for suffix in (
        "_all_chains",
        "_chains",
        "_final_answer",
        "_answer",
        "_analysis",
        "_enhanced",
        "_dual_ai",
    ):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    timestamp_match = re.match(r"^(?P<module>.+)_\d{8}_\d{6}$", stem)
    return timestamp_match.group("module") if timestamp_match else stem


def _run_id_for(path: Path, payload: Any | None = None) -> str:
    if isinstance(payload, dict) and payload.get("session_id"):
        return str(payload["session_id"])
    return path.stem


def _parse_location(value: Any) -> tuple[str, int | None]:
    if not isinstance(value, str):
        return "", None
    match = LOCATION_PATTERN.match(value.strip().strip("`"))
    if not match:
        return value.strip().replace("\\", "/"), None
    return match.group("file").replace("\\", "/"), int(match.group("line"))


class ResultStore:
    def __init__(self, project_dir: Path):
        self.project_dir = project_dir.resolve()
        self.results_dir = (self.project_dir / "results").resolve()

    def _run_files(self) -> list[Path]:
        if not self.results_dir.is_dir():
            return []
        files = [
            path
            for path in self.results_dir.iterdir()
            if path.is_file() and path.suffix.lower() == ".json"
        ]
        return sorted(files, key=lambda path: path.stat().st_mtime, reverse=True)

    @staticmethod
    def _load_payload(path: Path) -> Any:
        if path.stat().st_size > 20 * 1024 * 1024:
            raise ResultStoreError(f"Run artifact is too large: {path.name}")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ResultStoreError(f"Cannot read run artifact {path.name}: {exc}") from exc
        if not isinstance(payload, (dict, list)):
            raise ResultStoreError(f"Run artifact is not a JSON object or array: {path.name}")
        return payload

    def _path_for_run(self, run_id: str) -> Path:
        for path in self._run_files():
            if path.stem == run_id:
                return path
            try:
                payload = self._load_payload(path)
            except ResultStoreError:
                continue
            if _run_id_for(path, payload) == run_id:
                return path
        raise RunNotFound(f"Unknown run: {run_id}")

    @staticmethod
    def _payload_rows(payload: Any, path: Path) -> list[dict[str, Any]]:
        """Flatten old scanners, chain reports and answer files into rows."""
        rows: list[dict[str, Any]] = []
        module = _artifact_module(path, payload)

        def append_row(row: Any, defaults: dict[str, Any] | None = None) -> None:
            if not isinstance(row, dict):
                return
            normalized = dict(defaults or {})
            normalized.update(row)
            normalized.setdefault("module", module)
            rows.append(normalized)

        if isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict) and isinstance(item.get("vulnerabilities"), list):
                    defaults = {
                        "repair_commit": item.get("commit") or item.get("fix_commit"),
                        "module": module,
                    }
                    for row in item["vulnerabilities"]:
                        append_row(row, defaults)
                else:
                    append_row(item)
            return rows

        if isinstance(payload.get("primary"), dict):
            append_row(payload["primary"], {"module": module, "source_kind": "deterministic-analyzer"})
        elif isinstance(payload.get("candidates"), list):
            for candidate in payload["candidates"]:
                append_row(candidate, {"module": module, "source_kind": "deterministic-analyzer"})

        if isinstance(payload.get("chains"), list):
            for chain in payload["chains"]:
                append_row(
                    chain,
                    {
                        "module": module,
                        "source_kind": "chain",
                        "repair_commit": chain.get("fix_commit") if isinstance(chain, dict) else None,
                    },
                )

        answer = payload.get("answer")
        if isinstance(answer, dict):
            append_row(answer, {"module": module, "source_kind": "answer"})
            for candidate in answer.get("all_candidates", []):
                append_row(candidate, {"module": module, "source_kind": "answer-candidate"})

        for key in ("vulnerabilities", "findings", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                for row in value:
                    append_row(row, {"module": module, "source_kind": key})

        if not rows and any(key in payload for key in ("L1", "l1", "location", "file")):
            append_row(payload, {"module": module, "source_kind": "submission"})
        return rows

    @staticmethod
    def _normalize_row(row: dict[str, Any], path: Path) -> dict[str, Any]:
        module = str(row.get("module") or _artifact_module(path, row))
        location = row.get("L1") or row.get("l1") or row.get("location")
        file_path = str(row.get("file") or "")
        line_value = row.get("line")
        if location and (not file_path or line_value is None):
            parsed_file, parsed_line = _parse_location(location)
            file_path = file_path or parsed_file
            line_value = line_value if line_value is not None else parsed_line
        try:
            line = int(line_value) if line_value is not None and str(line_value).isdigit() else None
        except (TypeError, ValueError):
            line = None

        repair_commit = str(
            row.get("repair_commit")
            or row.get("fix_commit")
            or row.get("commit")
            or ""
        )
        level2_commit = str(
            row.get("level2_commit")
            or row.get("intro_commit")
            or row.get("L2")
            or row.get("l2")
            or ""
        )
        cwe = str(row.get("L3") or row.get("l3") or row.get("cwe") or "Unclassified")
        finding_type = str(
            row.get("type")
            or row.get("vulnerability_type")
            or row.get("pattern")
            or "OpenHarmony candidate"
        )
        description = str(
            row.get("description")
            or row.get("explanation")
            or row.get("reasoning")
            or row.get("note")
            or "No description recorded."
        )
        track_id = str(row.get("track_id") or row.get("trackId") or "")
        if not track_id:
            identity = "\0".join((module, file_path, str(line or ""), level2_commit, repair_commit))
            track_id = "oh-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
        confidence = row.get("confidence")
        try:
            confidence = int(confidence) if confidence is not None else None
        except (TypeError, ValueError):
            confidence = None
        return {
            "module": module,
            "file": file_path.replace("\\", "/"),
            "line": line,
            "repair_commit": repair_commit,
            "level2_commit": level2_commit,
            "cwe": cwe,
            "type": finding_type,
            "description": description,
            "confidence": confidence,
            "severity": row.get("severity") or row.get("ai_severity"),
            "ai_verified": bool(row.get("ai_verified")),
            "date": row.get("date") or "",
            "fixed_code": row.get("fixed_code") or "",
            "vulnerable_code": row.get("code") or row.get("deleted_code") or "",
            "track_id": track_id,
            "source_kind": row.get("source_kind") or "artifact",
            "artifact": path.name,
        }

    def list_runs(self) -> list[dict[str, Any]]:
        runs: list[dict[str, Any]] = []
        for path in self._run_files():
            try:
                payload = self._load_payload(path)
                findings = self._group_findings(payload, path)
                rows = self._payload_rows(payload, path)
                runs.append(
                    {
                        "run_id": _run_id_for(path, payload),
                        "module": _artifact_module(path, payload),
                        "timestamp": payload.get("timestamp") if isinstance(payload, dict) else _iso_timestamp(path),
                        "updated_at": _iso_timestamp(path),
                        "raw_total": len(rows),
                        "grouped_total": len(findings),
                        "artifact": path.name,
                        "status": "completed",
                    }
                )
            except ResultStoreError as exc:
                runs.append(
                    {
                        "run_id": path.stem,
                        "module": "unknown",
                        "timestamp": _iso_timestamp(path),
                        "updated_at": _iso_timestamp(path),
                        "raw_total": 0,
                        "grouped_total": 0,
                        "artifact": path.name,
                        "status": "invalid",
                        "error": str(exc),
                    }
                )
        return runs

    def get_run(self, run_id: str) -> dict[str, Any]:
        path = self._path_for_run(run_id)
        payload = self._load_payload(path)
        findings = self._group_findings(payload, path)
        rows = self._payload_rows(payload, path)
        return {
            "run_id": _run_id_for(path, payload),
            "module": _artifact_module(path, payload),
            "timestamp": payload.get("timestamp") if isinstance(payload, dict) else _iso_timestamp(path),
            "updated_at": _iso_timestamp(path),
            "raw_total": len(rows),
            "grouped_total": len(findings),
            "artifact": path.name,
            "status": "completed",
            "findings": findings,
        }

    def _group_findings(
        self,
        payload: Any,
        path: Path,
    ) -> list[dict[str, Any]]:
        rows = [self._normalize_row(row, path) for row in self._payload_rows(payload, path)]
        groups: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            group_key = (
                str(row.get("file") or ""),
                str(row.get("repair_commit") or ""),
                str(row.get("level2_commit") or ""),
                str(row.get("cwe") or ""),
                str(row.get("type") or ""),
                str(row.get("description") or ""),
                str(row.get("track_id") or ""),
            )
            groups[group_key].append(row)

        run_id = _run_id_for(path, payload)
        module = _artifact_module(path, payload)
        findings: list[dict[str, Any]] = []
        for group_key, evidence_rows in groups.items():
            file_path, repair_commit, level2_commit, cwe, finding_type, description, track_id = group_key
            lines = sorted(
                {
                    int(row["line"])
                    for row in evidence_rows
                    if isinstance(row.get("line"), int)
                }
            )
            identity = "\0".join((run_id, *group_key))
            finding_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
            fixed_lines = [
                str(row.get("fixed_code") or "")
                for row in sorted(
                    evidence_rows,
                    key=lambda item: int(item.get("line") or 0),
                )
                if row.get("fixed_code")
            ]
            explicit_confidence = next(
                (
                    row.get("confidence")
                    for row in evidence_rows
                    if row.get("confidence") is not None
                ),
                None,
            )
            ai_verified = any(bool(row.get("ai_verified")) for row in evidence_rows)
            confidence = next(
                (row.get("confidence") for row in evidence_rows if row.get("confidence") is not None),
                None,
            )
            submission = {
                "trackId": track_id,
                "L1": _line_range(file_path, lines),
                "L2": level2_commit,
                "L3": cwe,
            }
            finding = {
                "id": finding_id,
                "run_id": run_id,
                "module": module,
                "type": finding_type or "Unclassified finding",
                "description": description or "No description recorded.",
                "file": file_path,
                "line_start": lines[0] if lines else None,
                "line_end": lines[-1] if lines else None,
                "lines": lines,
                "location": _line_range(file_path, lines),
                "commit": repair_commit,
                "repair_commit": repair_commit,
                "level2_commit": level2_commit,
                "commit_short": repair_commit[:8] if repair_commit else "",
                "cwe": cwe or "Unclassified",
                "severity": _severity(
                    next(
                        (
                            row.get("severity") or row.get("ai_severity")
                            for row in evidence_rows
                            if row.get("severity") or row.get("ai_severity")
                        ),
                        None,
                    )
                ),
                "confidence": explicit_confidence if explicit_confidence is not None else confidence,
                "status": "verified" if ai_verified else "needs-review",
                "ai_verified": ai_verified,
                "date": next(
                    (str(row.get("date")) for row in evidence_rows if row.get("date")),
                    "",
                ),
                "fixed_code": "\n".join(fixed_lines),
                "vulnerable_code": "\n".join(
                    str(row.get("vulnerable_code") or "")
                    for row in evidence_rows
                    if row.get("vulnerable_code")
                ),
                "track_id": track_id,
                "submission": submission,
                "raw_evidence_count": len(evidence_rows),
                "evidence_kind": next(
                    (str(row.get("source_kind")) for row in evidence_rows if row.get("source_kind")),
                    "artifact",
                ),
                "artifacts": sorted({str(row.get("artifact")) for row in evidence_rows}),
            }
            findings.append(finding)

        findings.sort(
            key=lambda item: (
                item["file"],
                item["line_start"] if item["line_start"] is not None else 10**9,
                item["commit"],
            )
        )
        return findings

    def get_findings(
        self,
        run_id: str,
        *,
        query: str = "",
        cwe: str = "",
        state: str = "",
    ) -> list[dict[str, Any]]:
        findings = self.get_run(run_id)["findings"]
        query_normalized = query.strip().lower()
        cwe_normalized = cwe.strip().lower()
        state_normalized = state.strip().lower()
        filtered = []
        for finding in findings:
            searchable = " ".join(
                str(finding.get(key) or "")
                for key in ("type", "description", "file", "location", "commit", "cwe")
            ).lower()
            if query_normalized and query_normalized not in searchable:
                continue
            if cwe_normalized and finding["cwe"].lower() != cwe_normalized:
                continue
            if state_normalized and finding["status"].lower() != state_normalized:
                continue
            filtered.append(finding)
        return filtered

    def get_finding(self, finding_id: str) -> dict[str, Any]:
        for run in self.list_runs():
            if run["status"] != "completed":
                continue
            for finding in self.get_run(run["run_id"])["findings"]:
                if finding["id"] == finding_id:
                    evidence = self.get_evidence(finding)
                    return {
                        **finding,
                        "evidence": evidence,
                        "report": self._report_readiness(finding, evidence),
                    }
        raise FindingNotFound(f"Unknown finding: {finding_id}")

    def _repo_for_module(self, module: str) -> Path:
        candidate = (self.results_dir / f"{module}_repo").resolve()
        if not candidate.is_dir() or not (candidate / ".git").exists():
            raise SourceAccessError(f"Source repository is unavailable for {module}.")
        if not candidate.is_relative_to(self.results_dir):
            raise SourceAccessError("Source repository escaped the results directory.")
        return candidate

    @staticmethod
    def _validate_relative_source(file_path: str) -> str:
        normalized = PurePosixPath(file_path.replace("\\", "/"))
        if normalized.is_absolute() or ".." in normalized.parts or not normalized.parts:
            raise SourceAccessError("Invalid source path.")
        return normalized.as_posix()

    @staticmethod
    def _git(repo: Path, *args: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(repo), "--no-pager", *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )
        if completed.returncode != 0:
            return ""
        return completed.stdout[:200_000]

    def get_evidence(self, finding: dict[str, Any]) -> dict[str, Any]:
        try:
            repo = self._repo_for_module(str(finding["module"]))
            file_path = self._validate_relative_source(str(finding["file"]))
        except SourceAccessError as exc:
            return {
                "available": False,
                "error": str(exc),
                "diff": "",
                "before": None,
                "after": None,
            }

        commit = str(finding.get("commit") or "")
        if not COMMIT_PATTERN.fullmatch(commit):
            return {
                "available": False,
                "error": "The recorded commit is invalid.",
                "diff": "",
                "before": None,
                "after": None,
            }

        diff = self._git(
            repo,
            "show",
            "--format=fuller",
            "--unified=8",
            commit,
            "--",
            file_path,
        )
        before_source = self._git(repo, "show", f"{commit}^:{file_path}")
        after_source = self._git(repo, "show", f"{commit}:{file_path}")
        line_start = int(finding.get("line_start") or 1)
        before = _snippet(before_source, line_start - 8, line_start + 10) if before_source else None
        after = _snippet(after_source, line_start - 8, line_start + 14) if after_source else None

        recommended_cwe = str(finding.get("cwe") or "Unclassified")
        recommendation_reason = "No classification refinement was applied."
        diff_lower = diff.lower()
        if (
            "null pointer" in str(finding.get("type") or "").lower()
            and "new (std::nothrow)" in diff_lower
            and "== nullptr" in diff_lower
        ):
            recommended_cwe = "CWE-690"
            recommendation_reason = (
                "The repair checks a nothrow allocation before the subsequent "
                "dereference; CWE-690 is more specific than the scanner's "
                "generic null-dereference classification."
            )

        return {
            "available": bool(diff),
            "error": None if diff else "Git evidence could not be loaded.",
            "diff": diff,
            "before": before,
            "after": after,
            "repository": str(repo),
            "classification": {
                "scanner": finding.get("cwe"),
                "recommended": recommended_cwe,
                "reason": recommendation_reason,
                "requires_manual_confirmation": True,
            },
        }

    @staticmethod
    def _report_readiness(
        finding: dict[str, Any],
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        fields = [
            {
                "key": "source_path",
                "label": "Source path",
                "complete": bool(finding.get("location")),
                "value": finding.get("location"),
            },
            {
                "key": "level2_commit",
                "label": "L2 introducing commit",
                "complete": bool(finding.get("level2_commit")),
                "value": finding.get("level2_commit"),
            },
            {
                "key": "cwe",
                "label": "L3 CWE",
                "complete": bool(finding.get("cwe") and finding.get("cwe") != "Unclassified"),
                "value": finding.get("cwe"),
            },
            {
                "key": "git_evidence",
                "label": "Git repair evidence",
                "complete": bool(evidence.get("available")),
                "value": finding.get("repair_commit"),
            },
        ]
        complete_count = sum(1 for field in fields if field["complete"])
        return {
            "fields": fields,
            "complete_count": complete_count,
            "total_count": len(fields),
            "ready": complete_count == len(fields),
            "classification": "openharmony-chain",
            "warnings": [
                "A local Git chain is evidence, not a contest submission.",
                "The same trackId must be used for L1, L2 and L3.",
                "Confirm the competition task and cooldown rules before submitting.",
            ],
        }

    def read_source(
        self,
        run_id: str,
        file_path: str,
        start: int,
        end: int,
    ) -> dict[str, Any]:
        run = self.get_run(run_id)
        repo = self._repo_for_module(run["module"])
        normalized = self._validate_relative_source(file_path)
        candidate = (repo / Path(normalized)).resolve()
        if not candidate.is_relative_to(repo) or not candidate.is_file():
            raise SourceAccessError("Source file is outside the authorized repository.")
        if candidate.stat().st_size > 2 * 1024 * 1024:
            raise SourceAccessError("Source file is too large to preview.")
        if end < start or end - start > 400:
            raise SourceAccessError("Source preview is limited to 400 lines.")
        content = candidate.read_text(encoding="utf-8", errors="replace")
        return {
            "path": normalized,
            "snippet": _snippet(content, start, end),
        }

    def export_markdown(self, run_id: str) -> str:
        run = self.get_run(run_id)
        lines = [
            f"# CyberGem run {run['run_id']}",
            "",
            f"- Module: {run['module']}",
            f"- Timestamp: {run['timestamp']}",
            f"- Raw evidence rows: {run['raw_total']}",
            f"- Grouped findings: {run['grouped_total']}",
            "",
            "## Findings",
            "",
        ]
        for index, finding in enumerate(run["findings"], 1):
            lines.extend(
                [
                    f"### {index}. {finding['type']}",
                    "",
                    f"- Location: {finding['location']}",
                    f"- Commit: {finding['commit']}",
                    f"- Scanner CWE: {finding['cwe']}",
                    f"- Review state: {finding['status']}",
                    f"- Repair evidence rows: {finding['raw_evidence_count']}",
                    "",
                    finding["description"],
                    "",
                    "> Reproduction steps and an input sample are not recorded. "
                    "Manual verification is required before submission.",
                    "",
                ]
            )
        return "\n".join(lines)
