"""Persistent hypothesis board shared by manager and solver agents."""

from __future__ import annotations

import json
import os
import threading
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal


IdeaType = Literal["memory_safety", "logic_bug", "injection", "other"]
IdeaStatus = Literal["pending", "in_progress", "verified", "rejected"]


@dataclass
class Idea:
    id: str
    task_id: str
    type: IdeaType
    location: str
    description: str
    priority: int
    status: IdeaStatus
    assigned_to: str | None
    created_by: str
    created_at: str
    updated_at: str

    @classmethod
    def create(
        cls,
        task_id: str,
        type: IdeaType,
        location: str,
        description: str,
        priority: int,
        created_by: str,
    ) -> "Idea":
        now = datetime.now(timezone.utc).isoformat()
        return cls(
            id=f"idea-{uuid.uuid4().hex[:8]}",
            task_id=task_id,
            type=type,
            location=location,
            description=description,
            priority=max(1, min(10, int(priority))),
            status="pending",
            assigned_to=None,
            created_by=created_by,
            created_at=now,
            updated_at=now,
        )


class IdeaBoard:
    """JSON-backed board with atomic writes and in-process claim serialization."""

    _io_lock = threading.RLock()

    def __init__(self, storage_path: Path):
        self.storage_path = storage_path
        self.storage_path.mkdir(parents=True, exist_ok=True)

    def _task_file(self, task_id: str) -> Path:
        return self.storage_path / f"{task_id}_ideas.json"

    def _load_ideas(self, task_id: str) -> dict[str, Idea]:
        task_file = self._task_file(task_id)
        if not task_file.exists():
            return {}
        with task_file.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return {idea_id: Idea(**idea_data) for idea_id, idea_data in data.items()}

    def _save_ideas(self, task_id: str, ideas: dict[str, Idea]) -> None:
        task_file = self._task_file(task_id)
        temp_file = task_file.with_name(f".{task_file.name}.{uuid.uuid4().hex}.tmp")
        try:
            with temp_file.open("w", encoding="utf-8") as handle:
                json.dump(
                    {idea_id: asdict(idea) for idea_id, idea in ideas.items()},
                    handle,
                    ensure_ascii=False,
                    indent=2,
                )
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_file, task_file)
        finally:
            if temp_file.exists():
                temp_file.unlink()

    def add(self, idea: Idea) -> None:
        with self._io_lock:
            ideas = self._load_ideas(idea.task_id)
            ideas[idea.id] = idea
            self._save_ideas(idea.task_id, ideas)

    def get(self, idea_id: str, task_id: str) -> Idea | None:
        with self._io_lock:
            return self._load_ideas(task_id).get(idea_id)

    def claim(self, task_id: str, solver_id: str) -> Idea | None:
        with self._io_lock:
            ideas = self._load_ideas(task_id)
            pending = [idea for idea in ideas.values() if idea.status == "pending"]
            if not pending:
                return None
            idea = max(pending, key=lambda item: (item.priority, item.created_at, item.id))
            idea.status = "in_progress"
            idea.assigned_to = solver_id
            idea.updated_at = datetime.now(timezone.utc).isoformat()
            self._save_ideas(task_id, ideas)
            return idea

    def update_status(self, idea_id: str, task_id: str, status: IdeaStatus) -> None:
        with self._io_lock:
            ideas = self._load_ideas(task_id)
            if idea_id not in ideas:
                return
            ideas[idea_id].status = status
            ideas[idea_id].updated_at = datetime.now(timezone.utc).isoformat()
            self._save_ideas(task_id, ideas)

    def list_pending(self, task_id: str) -> list[Idea]:
        with self._io_lock:
            ideas = self._load_ideas(task_id)
            return sorted(
                (idea for idea in ideas.values() if idea.status == "pending"),
                key=lambda item: (item.priority, item.created_at),
                reverse=True,
            )

    def list_all(self, task_id: str) -> list[Idea]:
        with self._io_lock:
            return list(self._load_ideas(task_id).values())

    def get_stats(self, task_id: str) -> dict[str, int]:
        with self._io_lock:
            ideas = list(self._load_ideas(task_id).values())
        return {
            "total": len(ideas),
            "pending": sum(idea.status == "pending" for idea in ideas),
            "in_progress": sum(idea.status == "in_progress" for idea in ideas),
            "verified": sum(idea.status == "verified" for idea in ideas),
            "rejected": sum(idea.status == "rejected" for idea in ideas),
        }
