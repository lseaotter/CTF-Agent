"""Manager Agent - 任务调度器"""

from __future__ import annotations

import asyncio
from pathlib import Path

from app.agents.observer import ObserverAgent
from app.agents.solver import SolverAgent
from app.core.evidence_store import EvidenceStore
from app.core.hypothesis import HypothesisGenerator
from app.memory.idea_board import IdeaBoard
from app.memory.memory_board import MemoryBoard


class ManagerAgent:
    """Manager Agent - 任务调度器"""

    def __init__(
        self,
        workspace: Path,
        idea_board: IdeaBoard,
        memory_board: MemoryBoard,
        evidence_store: EvidenceStore,
        config: dict | None = None,
    ):
        self.workspace = workspace
        self.idea_board = idea_board
        self.memory_board = memory_board
        self.evidence_store = evidence_store

        # 配置
        self.config = config or {}
        self.max_solvers = self.config.get("max_solvers", 3)
        self.budget_tokens = self.config.get("budget_tokens", 200000)
        self.timeout_seconds = self.config.get("timeout_seconds", 600)

        # 状态
        self.active_solvers: dict[str, SolverAgent] = {}
        self.observer: ObserverAgent | None = None
        self.hypothesis_generator = HypothesisGenerator()

        # 统计
        self.tokens_used = 0

    async def schedule_task(
        self,
        task_id: str,
        task_description: str,
        code_summary: str | None,
        pre_patch_binary: Path,
        post_patch_binary: Path,
    ) -> dict:
        """调度任务

        Args:
            task_id: 任务ID
            task_description: 漏洞描述
            code_summary: 代码摘要
            pre_patch_binary: Pre-Patch二进制
            post_patch_binary: Post-Patch二进制

        Returns:
            任务结果
        """
        print(f"[Manager] 开始调度任务: {task_id}")

        # 1. 生成初始假设（Stage 1: 便宜模型）
        print(f"[Manager] 生成假设...")
        ideas = await self.hypothesis_generator.generate(
            task_description=task_description,
            task_id=task_id,
            code_summary=code_summary,
        )

        print(f"[Manager] 生成了 {len(ideas)} 个假设")
        for idea in ideas:
            self.idea_board.add(idea)
            print(f"  - [{idea.priority}] {idea.location}: {idea.description[:60]}...")

        # 2. 启动Observer
        self.observer = ObserverAgent(
            idea_board=self.idea_board,
            memory_board=self.memory_board,
            evidence_store=self.evidence_store,
            config=self.config.get("observer", {}),
        )
        observer_task = asyncio.create_task(self.observer.monitor(task_id))

        # 3. 启动Solvers（并行）
        solver_tasks = []
        for i in range(self.max_solvers):
            solver = self._create_solver(f"solver-{i}")
            self.active_solvers[solver.id] = solver

            task = asyncio.create_task(
                solver.work(
                    task_id=task_id,
                    pre_patch_binary=pre_patch_binary,
                    post_patch_binary=post_patch_binary,
                )
            )
            solver_tasks.append(task)

        # 4. 等待任何一个Solver成功，或所有Solver完成，或超时
        try:
            done, pending = await asyncio.wait(
                solver_tasks,
                timeout=self.timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,  # 任何一个完成就返回
            )

            # 检查是否有成功的
            success = False
            for task in done:
                if task.result():
                    success = True
                    print(f"[Manager] ✅ 找到有效PoC！")
                    break

            if not success:
                # 等待所有Solver完成
                print(f"[Manager] 等待其他Solver完成...")
                results = await asyncio.gather(*pending, return_exceptions=True)
                success = any(r for r in results if isinstance(r, bool) and r)

            # 停止Observer
            self.observer.stop()
            await observer_task

            # 收集统计信息
            stats = self._collect_stats(task_id)

            return {
                "task_id": task_id,
                "success": success,
                "stats": stats,
            }

        except asyncio.TimeoutError:
            print(f"[Manager] ⏰ 任务超时")

            # 取消所有任务
            for task in solver_tasks:
                task.cancel()

            self.observer.stop()
            await observer_task

            stats = self._collect_stats(task_id)

            return {
                "task_id": task_id,
                "success": False,
                "stats": stats,
                "timeout": True,
            }

    def _create_solver(self, solver_id: str) -> SolverAgent:
        """创建Solver Agent

        Args:
            solver_id: Solver ID

        Returns:
            Solver实例
        """
        return SolverAgent(
            id=solver_id,
            workspace=self.workspace,
            idea_board=self.idea_board,
            memory_board=self.memory_board,
            evidence_store=self.evidence_store,
            config=self.config.get("solver", {}),
        )

    def _collect_stats(self, task_id: str) -> dict:
        """收集统计信息

        Args:
            task_id: 任务ID

        Returns:
            统计信息
        """
        idea_stats = self.idea_board.get_stats(task_id)
        memory_stats = self.memory_board.get_stats(task_id)
        evidence_summary = self.evidence_store.get_summary(task_id)

        return {
            "ideas": idea_stats,
            "memories": memory_stats,
            "evidence": evidence_summary,
            "tokens_used": self.tokens_used,
            "budget_tokens": self.budget_tokens,
            "budget_remaining": self.budget_tokens - self.tokens_used,
        }

    def check_stopping_condition(self, task_id: str) -> tuple[bool, str]:
        """检查停止条件

        Args:
            task_id: 任务ID

        Returns:
            (should_stop, reason)
        """
        # 1. 检查是否找到有效PoC
        if self.memory_board.has_success(task_id):
            return True, "找到有效PoC"

        # 2. 检查预算
        if self.tokens_used >= self.budget_tokens:
            return True, "Token预算耗尽"

        # 3. 检查是否还有待处理的Idea
        pending_ideas = self.idea_board.list_pending(task_id)
        if not pending_ideas:
            return True, "没有待处理的Idea"

        return False, ""
