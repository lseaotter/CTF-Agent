"""Memory看板 - 已验证事实管理"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal


@dataclass
class Memory:
    """已验证事实"""

    id: str
    task_id: str
    type: Literal["poc_success", "poc_fail", "negative_evidence", "insight"]
    content: dict
    related_idea: str | None  # 关联的Idea ID
    created_by: str  # Agent ID
    created_at: str  # ISO format


class MemoryBoard:
    """已验证事实看板"""

    def __init__(self, storage_path: Path):
        self.storage_path = storage_path
        self.storage_path.mkdir(parents=True, exist_ok=True)

    def _task_file(self, task_id: str) -> Path:
        """获取任务的memory文件"""
        return self.storage_path / f"{task_id}_memories.jsonl"

    def add(self, memory: Memory) -> str:
        """添加记忆（append-only）"""
        task_file = self._task_file(memory.task_id)
        with task_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(memory), ensure_ascii=False) + "\n")
        return memory.id

    def create_and_add(
        self,
        task_id: str,
        type: Literal["poc_success", "poc_fail", "negative_evidence", "insight"],
        content: dict,
        created_by: str,
        related_idea: str | None = None,
    ) -> str:
        """创建并添加记忆"""
        memory = Memory(
            id=f"mem-{uuid.uuid4().hex[:8]}",
            task_id=task_id,
            type=type,
            content=content,
            related_idea=related_idea,
            created_by=created_by,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        return self.add(memory)

    def get_all(self, task_id: str) -> list[Memory]:
        """获取所有记忆"""
        task_file = self._task_file(task_id)
        if not task_file.exists():
            return []

        memories = []
        with task_file.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    memories.append(Memory(**json.loads(line)))
        return memories

    def get_latest(self, task_id: str, limit: int = 10) -> list[Memory]:
        """获取最近N条记忆"""
        all_memories = self.get_all(task_id)
        return all_memories[-limit:]

    def search(self, task_id: str, type: str | None = None) -> list[Memory]:
        """搜索记忆"""
        all_memories = self.get_all(task_id)
        if type:
            return [m for m in all_memories if m.type == type]
        return all_memories

    def get_summary(self, task_id: str, last_n: int = 10) -> str:
        """获取摘要（上下文压缩）"""
        recent = self.get_latest(task_id, last_n)
        if not recent:
            return "暂无记忆"

        lines = []
        for mem in recent:
            if mem.type == "poc_success":
                lines.append(f"✓ PoC成功: {mem.content.get('vulnerability_type', 'unknown')}")
            elif mem.type == "poc_fail":
                lines.append(f"✗ PoC失败: {mem.content.get('reason', 'unknown')}")
            elif mem.type == "negative_evidence":
                lines.append(f"- 负面证据: {mem.content.get('reason', 'unknown')}")
            elif mem.type == "insight":
                lines.append(f"💡 发现: {mem.content.get('summary', 'unknown')}")

        return "\n".join(lines)

    def get_stats(self, task_id: str) -> dict:
        """获取统计信息"""
        all_memories = self.get_all(task_id)
        return {
            "total": len(all_memories),
            "poc_success": len([m for m in all_memories if m.type == "poc_success"]),
            "poc_fail": len([m for m in all_memories if m.type == "poc_fail"]),
            "negative_evidence": len([m for m in all_memories if m.type == "negative_evidence"]),
            "insight": len([m for m in all_memories if m.type == "insight"]),
        }

    def has_success(self, task_id: str) -> bool:
        """检查是否有成功的PoC"""
        memories = self.search(task_id, type="poc_success")
        return len(memories) > 0

    def compress(self, task_id: str, keep_recent: int = 10) -> None:
        """压缩旧记忆（保留最近N条，其余合并为insight）"""
        all_memories = self.get_all(task_id)
        if len(all_memories) <= keep_recent:
            return

        old_memories = all_memories[:-keep_recent]
        recent_memories = all_memories[-keep_recent:]

        # 生成摘要
        summary = f"压缩了{len(old_memories)}条旧记忆:\n"
        summary += f"- PoC成功: {len([m for m in old_memories if m.type == 'poc_success'])}\n"
        summary += f"- PoC失败: {len([m for m in old_memories if m.type == 'poc_fail'])}\n"
        summary += f"- 负面证据: {len([m for m in old_memories if m.type == 'negative_evidence'])}\n"

        # 重写文件（只保留最近的）
        task_file = self._task_file(task_id)
        with task_file.open("w", encoding="utf-8") as f:
            # 添加压缩摘要
            compressed_memory = Memory(
                id=f"mem-compressed-{uuid.uuid4().hex[:8]}",
                task_id=task_id,
                type="insight",
                content={"summary": summary, "compressed_count": len(old_memories)},
                related_idea=None,
                created_by="memory_board",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            f.write(json.dumps(asdict(compressed_memory), ensure_ascii=False) + "\n")

            # 写入最近的记忆
            for mem in recent_memories:
                f.write(json.dumps(asdict(mem), ensure_ascii=False) + "\n")
