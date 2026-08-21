"""证据存储系统 - Append-only事件存储"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal


@dataclass
class Evidence:
    """证据事件"""

    id: str
    timestamp: str  # ISO format
    type: Literal["hypothesis", "experiment", "poc", "verified", "negative"]
    agent_id: str
    task_id: str
    content: dict

    @classmethod
    def create(
        cls,
        type: Literal["hypothesis", "experiment", "poc", "verified", "negative"],
        agent_id: str,
        task_id: str,
        content: dict,
    ) -> Evidence:
        """创建新证据"""
        return cls(
            id=f"ev-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            type=type,
            agent_id=agent_id,
            task_id=task_id,
            content=content,
        )


class EvidenceStore:
    """Append-only证据存储"""

    def __init__(self, storage_path: Path):
        self.storage_path = storage_path
        self.storage_path.mkdir(parents=True, exist_ok=True)

    def _task_file(self, task_id: str) -> Path:
        """获取任务的证据文件"""
        return self.storage_path / f"{task_id}.jsonl"

    def append(self, evidence: Evidence) -> str:
        """追加证据（不覆盖）"""
        task_file = self._task_file(evidence.task_id)
        with task_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(evidence), ensure_ascii=False) + "\n")
        return evidence.id

    def query(
        self,
        task_id: str | None = None,
        type: str | None = None,
        agent_id: str | None = None,
    ) -> list[Evidence]:
        """查询证据"""
        if task_id:
            task_file = self._task_file(task_id)
            if not task_file.exists():
                return []

            results = []
            with task_file.open("r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        ev = Evidence(**data)
                        if (type is None or ev.type == type) and (agent_id is None or ev.agent_id == agent_id):
                            results.append(ev)
            return results
        else:
            # 查询所有任务
            results = []
            for task_file in self.storage_path.glob("*.jsonl"):
                with task_file.open("r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            data = json.loads(line)
                            ev = Evidence(**data)
                            if (type is None or ev.type == type) and (agent_id is None or ev.agent_id == agent_id):
                                results.append(ev)
            return results

    def get_latest(self, task_id: str, limit: int = 10) -> list[Evidence]:
        """获取最近N条证据"""
        all_evidence = self.query(task_id=task_id)
        return all_evidence[-limit:]

    def count(self, task_id: str, type: str | None = None) -> int:
        """统计证据数量"""
        return len(self.query(task_id=task_id, type=type))

    def get_summary(self, task_id: str) -> dict:
        """获取任务证据摘要"""
        all_evidence = self.query(task_id=task_id)
        return {
            "total": len(all_evidence),
            "by_type": {
                "hypothesis": len([e for e in all_evidence if e.type == "hypothesis"]),
                "experiment": len([e for e in all_evidence if e.type == "experiment"]),
                "poc": len([e for e in all_evidence if e.type == "poc"]),
                "verified": len([e for e in all_evidence if e.type == "verified"]),
                "negative": len([e for e in all_evidence if e.type == "negative"]),
            },
            "by_agent": {},  # TODO: 按agent统计
        }
