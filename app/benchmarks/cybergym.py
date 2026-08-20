"""CyberGym dataset loader with real downloads and safe archive extraction."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import tarfile
from typing import Any
from urllib.parse import urlparse

import httpx
from datasets import load_dataset


@dataclass
class CyberGymTask:
    task_id: str
    project_name: str
    project_language: str
    vulnerability_description: str
    level: int
    repo_vul_path: Path
    repo_fix_path: Path | None
    description_file: Path | None
    error_file: Path | None
    patch_file: Path | None
    docker_image: str | None
    binary_path: str | None
    metadata: dict[str, Any]


class CyberGymLoader:
    def __init__(self, cache_dir: Path | None = None, dataset_name: str | None = None):
        configured_cache = os.getenv("CYBERGYM_CACHE_DIR")
        self.cache_dir = (cache_dir or Path(configured_cache or "./storage/cybergym_cache")).resolve()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.dataset_name = dataset_name or os.getenv("CYBERGYM_DATASET", "sunblaze-ucb/cybergym")
        self.dataset: Any = None
        self._loaded_tasks: dict[tuple[str, int], CyberGymTask] = {}

    def load_dataset(self) -> Any:
        if self.dataset is None:
            self.dataset = load_dataset(self.dataset_name, cache_dir=str(self.cache_dir / "hf_cache"))
        return self.dataset

    def _train_rows(self) -> Any:
        dataset = self.load_dataset()
        if "train" in dataset:
            return dataset["train"]
        first_split = next(iter(dataset.keys()), None)
        if first_split is None:
            raise RuntimeError("CyberGym dataset contains no split.")
        return dataset[first_split]

    def list_tasks(self, limit: int = 10) -> list[dict[str, Any]]:
        tasks: list[dict[str, Any]] = []
        for row in self._train_rows():
            if len(tasks) >= limit:
                break
            description = str(row.get("vulnerability_description") or "").strip()
            tasks.append(
                {
                    "task_id": row.get("task_id"),
                    "project_name": row.get("project_name"),
                    "language": row.get("project_language"),
                    "description": description[:100] + ("..." if len(description) > 100 else ""),
                }
            )
        return tasks

    def load_task(self, task_id: str, level: int = 1) -> CyberGymTask:
        if level not in {0, 1, 2, 3}:
            raise ValueError("CyberGym level must be 0, 1, 2 or 3.")
        cache_key = (task_id, level)
        if cache_key in self._loaded_tasks:
            return self._loaded_tasks[cache_key]

        row = next((item for item in self._train_rows() if item.get("task_id") == task_id), None)
        if row is None:
            raise ValueError(f"Task not found: {task_id}")
        level_files = row.get(f"level{level}")
        if not isinstance(level_files, (list, tuple)):
            raise ValueError(f"Task {task_id} does not provide level {level} artifacts.")

        task_dir = self.cache_dir / "tasks" / task_id / f"level{level}"
        task_dir.mkdir(parents=True, exist_ok=True)
        repo_vul_path: Path | None = None
        repo_fix_path: Path | None = None
        description_file: Path | None = None
        error_file: Path | None = None
        patch_file: Path | None = None

        for entry in level_files:
            name, url = self._artifact_entry(entry)
            name_lower = name.lower()
            if "repo-vul" in name_lower and name_lower.endswith((".tar.gz", ".tgz", ".tar")):
                repo_vul_path = self._download_and_extract(url, task_dir / "repo-vul")
            elif "repo-fix" in name_lower and name_lower.endswith((".tar.gz", ".tgz", ".tar")):
                repo_fix_path = self._download_and_extract(url, task_dir / "repo-fix")
            elif "description" in name_lower:
                description_file = self._download_file(url, task_dir / "description.txt")
            elif "error" in name_lower:
                error_file = self._download_file(url, task_dir / "error.txt")
            elif "patch" in name_lower:
                patch_file = self._download_file(url, task_dir / "patch.diff")

        description = str(row.get("vulnerability_description") or "").strip()
        if description_file and description_file.is_file():
            description = description_file.read_text(encoding="utf-8", errors="replace").strip()
        if repo_vul_path is None:
            raise RuntimeError(f"Task {task_id} level {level} has no repo-vul artifact.")

        task = CyberGymTask(
            task_id=task_id,
            project_name=str(row.get("project_name") or "unknown"),
            project_language=str(row.get("project_language") or "unknown"),
            vulnerability_description=description,
            level=level,
            repo_vul_path=repo_vul_path,
            repo_fix_path=repo_fix_path,
            description_file=description_file,
            error_file=error_file,
            patch_file=patch_file,
            docker_image=f"n132/arvo:{task_id.removeprefix('arvo-')}-vul",
            binary_path=self.find_binary(repo_vul_path),
            metadata=dict(row),
        )
        self._loaded_tasks[cache_key] = task
        return task

    @staticmethod
    def _artifact_entry(entry: Any) -> tuple[str, str]:
        if isinstance(entry, dict):
            url = str(entry.get("url") or entry.get("path") or entry.get("file") or "")
            name = str(entry.get("name") or Path(urlparse(url).path).name or url)
        else:
            url = str(entry)
            name = Path(urlparse(url).path).name or url
        if not url:
            raise ValueError("Dataset artifact has no URL or path.")
        return name, url

    def _download_file(self, url: str, target_path: Path) -> Path:
        if target_path.is_file() and target_path.stat().st_size > 0:
            return target_path
        target_path.parent.mkdir(parents=True, exist_ok=True)
        parsed = urlparse(url)
        temp_path = target_path.with_name(f".{target_path.name}.download")
        try:
            if parsed.scheme in {"", "file"}:
                source = Path(parsed.path if parsed.scheme == "file" else url).expanduser().resolve()
                if not source.is_file():
                    raise FileNotFoundError(f"Dataset artifact is unavailable: {source}")
                shutil.copyfile(source, temp_path)
            else:
                with httpx.stream("GET", url, follow_redirects=True, timeout=120.0) as response:
                    response.raise_for_status()
                    with temp_path.open("wb") as handle:
                        for chunk in response.iter_bytes(1024 * 1024):
                            handle.write(chunk)
            os.replace(temp_path, target_path)
            return target_path
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def _download_and_extract(self, url: str, target_dir: Path) -> Path:
        marker = target_dir / ".complete"
        if marker.is_file():
            return self._collapse_single_root(target_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        archive_path = target_dir.with_name(target_dir.name + ".archive")
        self._download_file(url, archive_path)
        try:
            base = target_dir.resolve()
            with tarfile.open(archive_path, "r:*") as archive:
                members = archive.getmembers()
                for member in members:
                    if member.issym() or member.islnk():
                        raise RuntimeError(f"Refusing archive link: {member.name}")
                    destination = (base / member.name).resolve()
                    if not destination.is_relative_to(base):
                        raise RuntimeError(f"Archive path escapes target: {member.name}")
                archive.extractall(base)
            marker.write_text("ok\n", encoding="ascii")
            return self._collapse_single_root(target_dir)
        finally:
            if archive_path.exists():
                archive_path.unlink()

    @staticmethod
    def _collapse_single_root(target_dir: Path) -> Path:
        entries = [entry for entry in target_dir.iterdir() if entry.name != ".complete"]
        if len(entries) == 1 and entries[0].is_dir():
            return entries[0]
        return target_dir

    @staticmethod
    def find_binary(repo_path: Path | None) -> str | None:
        if repo_path is None or not repo_path.exists():
            return None
        for relative in ("out/fuzzer", "out/target", "out/runner", "fuzzer", "target"):
            candidate = repo_path / relative
            if candidate.is_file():
                return str(candidate)
        for candidate in sorted(repo_path.rglob("*")):
            if candidate.is_file() and (os.access(candidate, os.X_OK) or candidate.suffix.lower() == ".exe"):
                return str(candidate)
        return None


class CyberGymBenchmark:
    def __init__(self, loader: CyberGymLoader):
        self.loader = loader

    def get_benchmark_tasks(
        self,
        level: int = 1,
        limit: int = 10,
        filter_language: str | None = None,
    ) -> list[CyberGymTask]:
        tasks: list[CyberGymTask] = []
        for row in self.loader._train_rows():
            if len(tasks) >= limit:
                break
            language = str(row.get("project_language") or "")
            if filter_language and language.lower() != filter_language.lower():
                continue
            if f"level{level}" not in row:
                continue
            try:
                tasks.append(self.loader.load_task(str(row["task_id"]), level))
            except (OSError, RuntimeError, ValueError) as exc:
                print(f"Skipping {row.get('task_id')}: {exc}")
        return tasks

    @staticmethod
    def print_task_info(task: CyberGymTask) -> None:
        print(f"Task: {task.task_id}")
        print(f"Project: {task.project_name} ({task.project_language})")
        print(f"Level: {task.level}")
        print(f"Vulnerability: {task.vulnerability_description[:240]}")
        print(f"Pre-patch repo: {task.repo_vul_path}")
        print(f"Post-patch repo: {task.repo_fix_path or 'not provided'}")
        print(f"Pre-patch binary: {task.binary_path or 'not found'}")


__all__ = ["CyberGymBenchmark", "CyberGymLoader", "CyberGymTask"]
