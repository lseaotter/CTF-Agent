"""Observer Agent - 策略监督与纠偏"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from app.core.evidence_store import EvidenceStore
from app.memory.idea_board import IdeaBoard
from app.memory.memory_board import MemoryBoard


class ObserverAgent:
    """Observer Agent - 策略监督器"""

    def __init__(
        self,
        idea_board: IdeaBoard,
        memory_board: MemoryBoard,
        evidence_store: EvidenceStore,
        config: dict | None = None,
    ):
        self.idea_board = idea_board
        self.memory_board = memory_board
        self.evidence_store = evidence_store

        # 配置
        self.config = config or {}
        self.check_interval = self.config.get("check_interval_seconds", 30)
        self.context_window = self.config.get("context_window", 10)
        self.duplicate_threshold = self.config.get("duplicate_threshold", 0.85)
        self.auto_compress = self.config.get("auto_compress", True)

        self.running = False

    async def monitor(self, task_id: str):
        """监控任务进度

        Args:
            task_id: 任务ID
        """
        print(f"[Observer] 开始监控任务: {task_id}")
        self.running = True

        while self.running:
            try:
                # 1. 检测重复Idea
                await self._check_duplicates(task_id)

                # 2. 检测目标漂移
                await self._check_drift(task_id)

                # 3. 压缩上下文
                if self.auto_compress:
                    await self._compress_context(task_id)

                # 4. 生成进度报告
                self._log_progress(task_id)

                # 等待下一次检查
                await asyncio.sleep(self.check_interval)

            except Exception as e:
                print(f"[Observer] 监控出错: {e}")
                await asyncio.sleep(self.check_interval)

    def stop(self):
        """停止监控"""
        print("[Observer] 停止监控")
        self.running = False

    async def _check_duplicates(self, task_id: str):
        """检测重复Idea

        查找相似度过高的Idea，合并或标记
        """
        ideas = self.idea_board.list_pending(task_id)

        # 简单实现：检查描述相似度
        # 生产环境可以使用embedding相似度
        for i, idea1 in enumerate(ideas):
            for idea2 in ideas[i + 1 :]:
                # 简单的文本相似度检查
                if self._text_similarity(idea1.description, idea2.description) > self.duplicate_threshold:
                    print(f"[Observer] 发现重复Idea: {idea1.id} 和 {idea2.id}")
                    # 保留优先级高的，标记优先级低的为rejected
                    if idea1.priority > idea2.priority:
                        self.idea_board.update_status(idea2.id, task_id, "rejected")
                    else:
                        self.idea_board.update_status(idea1.id, task_id, "rejected")

    def _text_similarity(self, text1: str, text2: str) -> float:
        """计算文本相似度（简单实现）

        Returns:
            相似度分数 (0-1)
        """
        # 简单的单词重叠率
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())

        if not words1 or not words2:
            return 0.0

        intersection = words1 & words2
        union = words1 | words2

        return len(intersection) / len(union)

    async def _check_drift(self, task_id: str):
        """检测目标漂移

        检查最近的Memory是否偏离了原始任务目标
        """
        # 获取最近的Memory
        recent_memories = self.memory_board.get_latest(task_id, limit=5)

        if not recent_memories:
            return

        # 检查是否有太多失败
        fail_count = sum(1 for m in recent_memories if m.type in ["poc_fail", "negative_evidence"])

        if fail_count >= 4:
            print(f"[Observer] ⚠️  检测到目标可能漂移：最近5次有{fail_count}次失败")

            # 记录insight
            self.memory_board.create_and_add(
                task_id=task_id,
                type="insight",
                content={
                    "summary": f"检测到高失败率（{fail_count}/5），建议调整策略",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
                created_by="observer",
            )

    async def _compress_context(self, task_id: str):
        """压缩上下文

        保留最近N条Memory，将旧的合并为摘要
        """
        all_memories = self.memory_board.get_all(task_id)

        if len(all_memories) > self.context_window * 2:
            print(f"[Observer] 压缩上下文：{len(all_memories)} -> {self.context_window}")
            self.memory_board.compress(task_id, keep_recent=self.context_window)

    def _log_progress(self, task_id: str):
        """记录进度"""
        idea_stats = self.idea_board.get_stats(task_id)
        memory_stats = self.memory_board.get_stats(task_id)
        evidence_summary = self.evidence_store.get_summary(task_id)

        print(f"""
[Observer] 任务进度 - {task_id}
  Ideas:
    - 总计: {idea_stats['total']}
    - 待处理: {idea_stats['pending']}
    - 进行中: {idea_stats['in_progress']}
    - 已验证: {idea_stats['verified']}
    - 已拒绝: {idea_stats['rejected']}

  Memories:
    - 总计: {memory_stats['total']}
    - PoC成功: {memory_stats['poc_success']}
    - PoC失败: {memory_stats['poc_fail']}
    - 负面证据: {memory_stats['negative_evidence']}

  Evidence:
    - 总计: {evidence_summary['total']}
""")

    def broadcast_correction(self, task_id: str, message: str):
        """广播纠偏消息

        当检测到问题时，通知所有Solver调整策略

        Args:
            task_id: 任务ID
            message: 纠偏消息
        """
        print(f"[Observer] 📢 广播纠偏: {message}")

        # 记录到Memory
        self.memory_board.create_and_add(
            task_id=task_id,
            type="insight",
            content={
                "type": "correction",
                "message": message,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            created_by="observer",
        )

        # TODO: 实现真正的消息广播机制
        # 可以使用事件系统或消息队列
