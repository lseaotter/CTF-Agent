"""CyberGem local security research workbench."""

from __future__ import annotations

import argparse
from collections import deque
from datetime import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn

from app.core.providers import all_provider_configs, probe_provider
from app.core.openharmony import load_ground_truth, score_submission
from app.core.results import (
    FindingNotFound,
    ResultStore,
    ResultStoreError,
    RunNotFound,
    SourceAccessError,
)


PROJECT_DIR = Path(__file__).resolve().parent
WEB_DIR = PROJECT_DIR / "web"
RESULTS_DIR = PROJECT_DIR / "results"
SERVER_AGENT = PROJECT_DIR / "server_agent.py"
ARCHITECTURE_IMAGE = (
    RESULTS_DIR
    / "medical_sensor_repo"
    / "figures"
    / "zh-cn_image_medical_sensor_fwk.png"
)
GROUND_TRUTH = RESULTS_DIR / "communication_netmanager_base_CORRECT_ANSWER.md"

result_store = ResultStore(PROJECT_DIR)
app = FastAPI(
    title="CyberGem Research Console",
    version="3.0.0",
    docs_url=None,
    redoc_url=None,
)


class ScanRequest(BaseModel):
    module: Literal["medical_sensor", "sensors", "arkui", "communication"]


class ScanController:
    """Own the one local scanner process started from this web server."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._process: subprocess.Popen[str] | None = None
        self._logs: deque[str] = deque(maxlen=300)
        self._state: dict[str, Any] = {
            "status": "idle",
            "module": None,
            "started_at": None,
            "finished_at": None,
            "exit_code": None,
        }

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            process = self._process
            if process is not None and process.poll() is None:
                self._state["status"] = "running"
            return {
                **self._state,
                "logs": list(self._logs)[-80:],
            }

    def start(self, module: str) -> dict[str, Any]:
        with self._lock:
            if self._process is not None and self._process.poll() is None:
                raise RuntimeError("A scan is already running.")

            command = [
                sys.executable,
                str(SERVER_AGENT),
                "--module",
                module,
                "--output",
                str(RESULTS_DIR),
            ]
            self._logs.clear()
            self._logs.append(f"Starting local scan for {module}.")
            self._state = {
                "status": "starting",
                "module": module,
                "started_at": datetime.now().astimezone().isoformat(),
                "finished_at": None,
                "exit_code": None,
            }
            self._process = subprocess.Popen(
                command,
                cwd=PROJECT_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
            )
            thread = threading.Thread(target=self._consume_output, daemon=True)
            thread.start()
            return self.snapshot()

    def _consume_output(self) -> None:
        process = self._process
        if process is None:
            return
        if process.stdout is not None:
            for line in process.stdout:
                cleaned = line.rstrip()
                if cleaned:
                    with self._lock:
                        self._logs.append(cleaned)
        exit_code = process.wait()
        with self._lock:
            self._state["exit_code"] = exit_code
            self._state["finished_at"] = datetime.now().astimezone().isoformat()
            self._state["status"] = "completed" if exit_code == 0 else "failed"
            self._logs.append(
                "Scan completed." if exit_code == 0 else f"Scan failed with exit code {exit_code}."
            )

    def stop(self) -> dict[str, Any]:
        with self._lock:
            process = self._process
            if process is None or process.poll() is not None:
                raise RuntimeError("No scan is currently running.")
            self._state["status"] = "stopping"
            self._logs.append("Stop requested by the local operator.")
            process.terminate()
        return self.snapshot()


scan_controller = ScanController()
_probe_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_probe_lock = threading.Lock()


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    )
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


app.mount("/assets", StaticFiles(directory=WEB_DIR), name="assets")


def _raise_store_error(exc: ResultStoreError) -> None:
    if isinstance(exc, (RunNotFound, FindingNotFound)):
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if isinstance(exc, SourceAccessError):
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    raise HTTPException(status_code=500, detail=str(exc)) from exc


def _is_local_request(request: Request) -> bool:
    if request.client is None:
        return False
    return request.client.host in {"127.0.0.1", "::1", "localhost", "testclient"}


@app.get("/", include_in_schema=False)
async def root() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


@app.get("/api/v1/health")
async def health() -> dict[str, Any]:
    runs = result_store.list_runs()
    latest = runs[0] if runs else None
    return {
        "status": "ok",
        "version": app.version,
        "server_time": datetime.now().astimezone().isoformat(),
        "results_readable": RESULTS_DIR.is_dir(),
        "run_count": len(runs),
        "latest_run": latest,
        "scan": scan_controller.snapshot(),
    }


@app.get("/api/v1/runs")
async def list_runs(
    limit: int = Query(default=50, ge=1, le=100),
) -> dict[str, Any]:
    runs = result_store.list_runs()[:limit]
    return {"items": runs, "count": len(runs)}


@app.get("/api/v1/runs/{run_id}")
async def get_run(run_id: str) -> dict[str, Any]:
    try:
        run = result_store.get_run(run_id)
        return {key: value for key, value in run.items() if key != "findings"}
    except ResultStoreError as exc:
        _raise_store_error(exc)


@app.get("/api/v1/runs/{run_id}/findings")
async def get_findings(
    run_id: str,
    q: str = Query(default="", max_length=200),
    cwe: str = Query(default="", max_length=40),
    state_filter: str = Query(default="", alias="state", max_length=40),
) -> dict[str, Any]:
    try:
        findings = result_store.get_findings(
            run_id,
            query=q,
            cwe=cwe,
            state=state_filter,
        )
        return {"items": findings, "count": len(findings)}
    except ResultStoreError as exc:
        _raise_store_error(exc)


@app.get("/api/v1/evaluation")
async def evaluate_latest(run_id: str | None = Query(default=None, max_length=120)) -> dict[str, Any]:
    """Score local findings against the checked-in competition regression answer."""
    if not GROUND_TRUTH.is_file():
        raise HTTPException(status_code=404, detail="Local OpenHarmony ground truth is unavailable.")
    runs = result_store.list_runs()
    selected_run_id = run_id or (runs[0]["run_id"] if runs else None)
    if not selected_run_id:
        raise HTTPException(status_code=404, detail="No local result artifacts are available.")
    try:
        run = result_store.get_run(selected_run_id)
        truth = load_ground_truth(GROUND_TRUTH)
        prediction = {"candidates": [finding["submission"] for finding in run["findings"]]}
        return {
            "run_id": selected_run_id,
            "artifact": run["artifact"],
            "truth_artifact": GROUND_TRUTH.name,
            **score_submission(prediction, truth),
        }
    except ResultStoreError as exc:
        _raise_store_error(exc)


@app.get("/api/v1/findings/{finding_id}")
async def get_finding(finding_id: str) -> dict[str, Any]:
    try:
        return result_store.get_finding(finding_id)
    except ResultStoreError as exc:
        _raise_store_error(exc)


@app.get("/api/v1/source")
async def source_preview(
    run_id: str,
    path: str,
    start: int = Query(default=1, ge=1),
    end: int = Query(default=120, ge=1),
) -> dict[str, Any]:
    try:
        return result_store.read_source(run_id, path, start, end)
    except ResultStoreError as exc:
        _raise_store_error(exc)


@app.get("/api/v1/runs/{run_id}/export")
async def export_run(
    run_id: str,
    format: Literal["json", "md"] = "json",
):
    try:
        run = result_store.get_run(run_id)
        if format == "md":
            response = PlainTextResponse(
                result_store.export_markdown(run_id),
                media_type="text/markdown; charset=utf-8",
            )
            extension = "md"
        else:
            response = JSONResponse(run)
            extension = "json"
        response.headers["Content-Disposition"] = (
            f'attachment; filename="cybergem-{run_id}.{extension}"'
        )
        return response
    except ResultStoreError as exc:
        _raise_store_error(exc)


@app.get("/api/v1/providers")
async def providers() -> dict[str, Any]:
    return {
        "items": [config.public_dict() for config in all_provider_configs()],
    }


@app.post("/api/v1/diagnostics/providers/{provider_key}/probe")
async def probe(provider_key: str, request: Request) -> dict[str, Any]:
    if not _is_local_request(request):
        raise HTTPException(status_code=403, detail="Provider diagnostics are local-only.")
    configs = {config.key: config for config in all_provider_configs()}
    config = configs.get(provider_key)
    if config is None:
        raise HTTPException(status_code=404, detail="Unknown provider.")

    now = time.monotonic()
    with _probe_lock:
        cached = _probe_cache.get(provider_key)
        if cached and now - cached[0] < 5:
            return {**cached[1], "cached": True}

    result = await run_in_threadpool(probe_provider, config)
    with _probe_lock:
        _probe_cache[provider_key] = (now, result)
    return {**result, "cached": False}


@app.get("/api/v1/scans/status")
async def scan_status() -> dict[str, Any]:
    return scan_controller.snapshot()


@app.post("/api/v1/scans", status_code=status.HTTP_202_ACCEPTED)
async def start_scan(payload: ScanRequest, request: Request) -> dict[str, Any]:
    if not _is_local_request(request):
        raise HTTPException(status_code=403, detail="Scan control is local-only.")
    try:
        return scan_controller.start(payload.module)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/v1/scans/stop", status_code=status.HTTP_202_ACCEPTED)
async def stop_scan(request: Request) -> dict[str, Any]:
    if not _is_local_request(request):
        raise HTTPException(status_code=403, detail="Scan control is local-only.")
    try:
        return scan_controller.stop()
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/v1/assets/architecture")
async def architecture_image() -> FileResponse:
    if not ARCHITECTURE_IMAGE.is_file():
        raise HTTPException(status_code=404, detail="Architecture image is unavailable.")
    return FileResponse(ARCHITECTURE_IMAGE, media_type="image/png")


# Compatibility aliases for the original demo page.
@app.get("/api/status")
async def legacy_status() -> dict[str, Any]:
    runs = result_store.list_runs()
    findings: list[dict[str, Any]] = []
    if runs and runs[0]["status"] == "completed":
        findings = result_store.get_findings(runs[0]["run_id"])
    scan = scan_controller.snapshot()
    return {
        "status": scan["status"],
        "message": f"Local scanner is {scan['status']}.",
        "vulnerabilities": findings,
    }


@app.get("/api/results")
async def legacy_results() -> dict[str, Any]:
    runs = result_store.list_runs()
    if not runs:
        return {"results": [], "total": 0}
    findings = result_store.get_findings(runs[0]["run_id"])
    return {"results": findings, "total": len(findings)}


def main() -> None:
    parser = argparse.ArgumentParser(description="CyberGem local research console")
    parser.add_argument(
        "--host",
        default=os.getenv("CYBERGEM_HOST", "127.0.0.1"),
        help="Bind address; defaults to localhost for safety.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("CYBERGEM_PORT", "8000")),
    )
    args = parser.parse_args()

    print("CyberGem Research Console")
    print(f"Local URL: http://{args.host}:{args.port}")
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        print("WARNING: the console is exposed beyond localhost.")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
