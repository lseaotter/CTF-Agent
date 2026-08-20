"""核心编排器 - 协调所有Agent"""

from __future__ import annotations

from pathlib import Path

from app.agents.manager import ManagerAgent
from app.core.evidence_store import EvidenceStore
from app.core.static_scan import StaticCodeAnalyzer
from app.memory.idea_board import IdeaBoard
from app.memory.memory_board import MemoryBoard


class Orchestrator:
    """核心编排器"""

    def __init__(self, storage_root: Path, config: dict | None = None):
        self.storage_root = storage_root
        self.storage_root.mkdir(parents=True, exist_ok=True)

        self.config = config or {}

        # 初始化存储
        self.evidence_store = EvidenceStore(storage_root / "evidence")
        self.idea_board_storage = storage_root / "ideas"
        self.idea_board_storage.mkdir(parents=True, exist_ok=True)
        self.memory_board_storage = storage_root / "memories"
        self.memory_board_storage.mkdir(parents=True, exist_ok=True)

        # 代码分析器
        self.code_analyzer = StaticCodeAnalyzer()

    async def run_task(
        self,
        task_id: str,
        task_description: str,
        repo_path: Path,
        pre_patch_binary: Path,
        post_patch_binary: Path,
    ) -> dict:
        """运行单个任务

        Args:
            task_id: 任务ID
            task_description: 漏洞描述
            repo_path: 代码仓库路径
            pre_patch_binary: Pre-Patch二进制
            post_patch_binary: Post-Patch二进制

        Returns:
            任务结果
        """
        print(f"[Orchestrator] 开始任务: {task_id}")
        print(f"[Orchestrator] 漏洞描述: {task_description[:100]}...")

        # 创建任务工作空间
        task_workspace = self.storage_root / "tasks" / task_id
        task_workspace.mkdir(parents=True, exist_ok=True)

        # 分析代码库
        print(f"[Orchestrator] 分析代码库...")
        code_summary = self.code_analyzer.analyze_repository(repo_path)

        # 创建看板
        idea_board = IdeaBoard(self.idea_board_storage)
        memory_board = MemoryBoard(self.memory_board_storage)

        # 创建Manager
        manager = ManagerAgent(
            workspace=task_workspace,
            idea_board=idea_board,
            memory_board=memory_board,
            evidence_store=self.evidence_store,
            config=self.config.get("manager", {}),
        )

        # 执行任务
        result = await manager.schedule_task(
            task_id=task_id,
            task_description=task_description,
            code_summary=code_summary,
            pre_patch_binary=pre_patch_binary,
            post_patch_binary=post_patch_binary,
        )

        print(f"[Orchestrator] 任务完成: {task_id}")
        print(f"[Orchestrator] 成功: {result['success']}")

        return result

    async def run_benchmark(self, tasks: list[dict]) -> dict:
        """运行完整benchmark

        Args:
            tasks: 任务列表，每个任务包含：
                - task_id: str
                - description: str
                - repo_path: Path
                - pre_patch_binary: Path
                - post_patch_binary: Path

        Returns:
            Benchmark结果
        """
        print(f"[Orchestrator] 开始Benchmark，共 {len(tasks)} 个任务")

        results = []
        for i, task in enumerate(tasks, 1):
            print(f"\n{'='*60}")
            print(f"任务 {i}/{len(tasks)}: {task['task_id']}")
            print(f"{'='*60}\n")

            result = await self.run_task(
                task_id=task["task_id"],
                task_description=task["description"],
                repo_path=task["repo_path"],
                pre_patch_binary=task["pre_patch_binary"],
                post_patch_binary=task["post_patch_binary"],
            )

            results.append(result)

        # 统计
        total = len(results)
        success_count = sum(1 for r in results if r["success"])
        success_rate = success_count / total if total > 0 else 0

        total_tokens = sum(r["stats"]["tokens_used"] for r in results)
        avg_tokens = total_tokens / total if total > 0 else 0

        print(f"\n{'='*60}")
        print(f"Benchmark结果")
        print(f"{'='*60}")
        print(f"总任务数: {total}")
        print(f"成功数: {success_count}")
        print(f"成功率: {success_rate:.1%}")
        print(f"总Token消耗: {total_tokens:,}")
        print(f"平均Token: {avg_tokens:,.0f}")
        print(f"{'='*60}\n")

        return {
            "total": total,
            "success": success_count,
            "success_rate": success_rate,
            "total_tokens": total_tokens,
            "avg_tokens": avg_tokens,
            "results": results,
        }

    def get_task_report(self, task_id: str) -> dict:
        """获取任务报告

        Args:
            task_id: 任务ID

        Returns:
            报告内容
        """
        idea_board = IdeaBoard(self.idea_board_storage)
        memory_board = MemoryBoard(self.memory_board_storage)

        return {
            "task_id": task_id,
            "ideas": idea_board.get_stats(task_id),
            "memories": memory_board.get_stats(task_id),
            "evidence": self.evidence_store.get_summary(task_id),
            "success": memory_board.has_success(task_id),
        }
