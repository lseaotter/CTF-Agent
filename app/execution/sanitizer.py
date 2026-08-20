"""Run PoCs with sanitizers and return structured, repeatable observations."""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


PocType = Literal["input_file", "command_args", "stdin"]


@dataclass
class SanitizerResult:
    exit_code: int
    stdout: str
    stderr: str
    crashed: bool
    crash_type: str | None
    crash_location: str | None
    sanitizer_report: str | None


class SanitizerRunner:
    """Execute a candidate in a clean child process with inherited runtime env."""

    def __init__(self, timeout: int = 60):
        self.timeout = timeout

    def run_with_asan(
        self,
        binary: Path,
        poc: Path,
        args: list[str] | None = None,
        poc_type: PocType = "input_file",
    ) -> SanitizerResult:
        return self._run_poc(
            binary,
            poc,
            args,
            poc_type,
            {"ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1:symbolize=1:print_stats=1"},
        )

    def run_with_ubsan(
        self,
        binary: Path,
        poc: Path,
        args: list[str] | None = None,
        poc_type: PocType = "input_file",
    ) -> SanitizerResult:
        return self._run_poc(
            binary,
            poc,
            args,
            poc_type,
            {"UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1"},
        )

    def run_with_msan(
        self,
        binary: Path,
        poc: Path,
        args: list[str] | None = None,
        poc_type: PocType = "input_file",
    ) -> SanitizerResult:
        return self._run_poc(
            binary,
            poc,
            args,
            poc_type,
            {"MSAN_OPTIONS": "print_stats=1"},
        )

    def _run_poc(
        self,
        binary: Path,
        poc: Path,
        args: list[str] | None,
        poc_type: PocType,
        env: dict[str, str],
    ) -> SanitizerResult:
        if poc_type == "stdin":
            try:
                input_data = poc.read_bytes()
            except OSError as exc:
                return self._error_result(str(exc))
            return self._run_binary([str(binary)], env, input_data=input_data)

        command = [str(binary)]
        if poc_type == "command_args":
            command.extend(args or self._read_args(poc))
        elif args:
            command.extend(args)
        else:
            command.append(str(poc))
        return self._run_binary(command, env)

    @staticmethod
    def _read_args(poc: Path) -> list[str]:
        try:
            content = poc.read_text(encoding="utf-8")
        except OSError:
            return []
        return [line.strip() for line in content.splitlines() if line.strip()]

    @staticmethod
    def _error_result(message: str) -> SanitizerResult:
        return SanitizerResult(
            exit_code=-1,
            stdout="",
            stderr=message,
            crashed=False,
            crash_type=None,
            crash_location=None,
            sanitizer_report=None,
        )

    def _run_binary(
        self,
        command: list[str],
        sanitizer_env: dict[str, str],
        *,
        input_data: bytes | None = None,
    ) -> SanitizerResult:
        try:
            environment = os.environ.copy()
            environment.update(sanitizer_env)
            result = subprocess.run(
                command,
                capture_output=True,
                timeout=self.timeout,
                env=environment,
                input=input_data,
                text=False,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return self._error_result("Timeout")
        except Exception as exc:
            return self._error_result(str(exc))

        stdout = (result.stdout or b"").decode("utf-8", errors="replace")
        stderr = (result.stderr or b"").decode("utf-8", errors="replace")
        crash_type, crash_location, report = self._parse_sanitizer_output(stderr)
        crashed = bool(report or result.returncode < 0 or result.returncode >= 128)
        return SanitizerResult(
            exit_code=result.returncode,
            stdout=stdout,
            stderr=stderr,
            crashed=crashed,
            crash_type=crash_type,
            crash_location=crash_location,
            sanitizer_report=report,
        )

    @staticmethod
    def _parse_sanitizer_output(stderr: str) -> tuple[str | None, str | None, str | None]:
        report_markers = (
            "AddressSanitizer",
            "UndefinedBehaviorSanitizer",
            "MemorySanitizer",
            "runtime error:",
        )
        if not any(marker in stderr for marker in report_markers):
            return None, None, None

        crash_type: str | None = None
        crash_location: str | None = None
        asan_match = re.search(r"ERROR: AddressSanitizer: ([\w-]+)", stderr)
        if asan_match:
            crash_type = asan_match.group(1)
        if "runtime error:" in stderr:
            crash_type = "undefined-behavior"
        if "use-of-uninitialized-value" in stderr:
            crash_type = "uninitialized-memory"

        location_match = re.search(r"#0 .*? in .*? ([^\s:]+):(\d+)", stderr)
        if location_match:
            crash_location = f"{location_match.group(1)}:{location_match.group(2)}"
        if crash_location is None:
            location_match = re.search(r"([^\s:]+):(\d+):(\d+): runtime error:", stderr)
            if location_match:
                crash_location = f"{location_match.group(1)}:{location_match.group(2)}"
        return crash_type, crash_location, stderr[:2000]


class SanitizerParser:
    """Parse and compare ASan observations for independent replay checks."""

    @staticmethod
    def parse_asan_report(report: str) -> dict:
        result = {
            "crash_type": None,
            "crash_address": None,
            "access_type": None,
            "access_size": None,
            "stack_trace": [],
        }
        if not report:
            return result
        match = re.search(r"ERROR: AddressSanitizer: ([\w-]+)", report)
        if match:
            result["crash_type"] = match.group(1)
        match = re.search(r"(READ|WRITE) of size (\d+)", report)
        if match:
            result["access_type"] = match.group(1)
            result["access_size"] = int(match.group(2))
        match = re.search(r"on address (0x[0-9a-fA-F]+)", report)
        if match:
            result["crash_address"] = match.group(1)
        result["stack_trace"] = [
            line.strip() for line in report.splitlines() if line.strip().startswith("#")
        ]
        return result

    @staticmethod
    def is_same_crash(report1: str | None, report2: str | None) -> bool:
        parsed1 = SanitizerParser.parse_asan_report(report1 or "")
        parsed2 = SanitizerParser.parse_asan_report(report2 or "")
        if parsed1["crash_type"] != parsed2["crash_type"]:
            return False
        if parsed1["stack_trace"] and parsed2["stack_trace"]:
            return parsed1["stack_trace"][0] == parsed2["stack_trace"][0]
        return bool(parsed1["crash_type"] and parsed1["crash_type"] == parsed2["crash_type"])


__all__ = ["PocType", "SanitizerParser", "SanitizerResult", "SanitizerRunner"]
