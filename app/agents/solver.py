"""Solver Agent - 漏洞探测与验证执行器"""

from __future__ import annotations

import asyncio
from pathlib import Path

from app.core.evidence_store import Evidence, EvidenceStore
from app.core.llm import LLMConfig, LLMManager
from app.core.poc_builder import PoCBuilder, PoCWriter
from app.core.verifier import PoCVerifier, VerificationReport
from app.execution.sanitizer import SanitizerRunner
from app.memory.idea_board import Idea, IdeaBoard
from app.memory.memory_board import MemoryBoard


class SolverAgent:
    """Solver Agent - 实际漏洞探测与验证"""

    def __init__(
        self,
        id: str,
        workspace: Path,
        idea_board: IdeaBoard,
        memory_board: MemoryBoard,
        evidence_store: EvidenceStore,
        config: dict | None = None,
    ):
        self.id = id
        self.workspace = workspace
        self.idea_board = idea_board
        self.memory_board = memory_board
        self.evidence_store = evidence_store

        # 配置
        self.config = config or {}
        self.max_iterations = self.config.get("max_iterations", 5)
        self.model = self.config.get("model") or LLMConfig().get_default_poc_model()

        # 组件
        self.llm_manager = LLMManager()
        self.poc_builder = PoCBuilder(model=self.model, llm_manager=self.llm_manager)
        self.poc_writer = PoCWriter(workspace)
        self.sanitizer_runner = SanitizerRunner()
        self.verifier = PoCVerifier(self.sanitizer_runner)

    async def work(self, task_id: str, pre_patch_binary: Path, post_patch_binary: Path) -> bool:
        """主工作循环

        Args:
            task_id: 任务ID
            pre_patch_binary: Pre-Patch二进制文件
            post_patch_binary: Post-Patch二进制文件

        Returns:
            是否找到有效PoC
        """
        print(f"[{self.id}] 开始工作，任务: {task_id}")

        while True:
            # 1. 从Idea Board认领任务
            idea = self.idea_board.claim(task_id, self.id)
            if not idea:
                print(f"[{self.id}] 没有待处理的Idea，退出")
                break

            print(f"[{self.id}] 认领Idea: {idea.id} - {idea.description}")

            # 2. 处理这个Idea
            success = await self._process_idea(idea, pre_patch_binary, post_patch_binary)

            if success:
                print(f"[{self.id}] ✅ Idea {idea.id} 验证成功")
                return True

        return False

    async def _process_idea(self, idea: Idea, pre_patch_binary: Path, post_patch_binary: Path) -> bool:
        """处理单个Idea

        Args:
            idea: 漏洞假设
            pre_patch_binary: Pre-Patch二进制
            post_patch_binary: Post-Patch二进制

        Returns:
            是否验证成功
        """
        previous_attempts = []

        for iteration in range(1, self.max_iterations + 1):
            print(f"[{self.id}] Idea {idea.id} - 第{iteration}次尝试")

            # 获取上下文（最近的Memory）
            context = self.memory_board.get_summary(idea.task_id, last_n=10)

            # 记录实验开始
            self.evidence_store.append(
                Evidence.create(
                    type="experiment",
                    agent_id=self.id,
                    task_id=idea.task_id,
                    content={
                        "idea_id": idea.id,
                        "iteration": iteration,
                        "action": "build_poc",
                    },
                )
            )

            # 构造PoC
            try:
                poc_result = await self.poc_builder.build(
                    idea=idea,
                    context=context,
                    iteration=iteration,
                    previous_attempts=previous_attempts,
                )

                # 写入PoC文件
                poc_path = self.poc_writer.write_poc(poc_result, idea.id)
                print(f"[{self.id}] PoC已生成: {poc_path}")

                # 记录PoC生成
                self.evidence_store.append(
                    Evidence.create(
                        type="poc",
                        agent_id=self.id,
                        task_id=idea.task_id,
                        content={
                            "idea_id": idea.id,
                            "poc_path": str(poc_path),
                            "poc_type": poc_result["poc_type"],
                            "expected_crash": poc_result["expected_crash"],
                        },
                    )
                )

                # 验证PoC
                verification_result = self.verifier.verify_poc(
                    poc_path=poc_path,
                    pre_patch_binary=pre_patch_binary,
                    post_patch_binary=post_patch_binary,
                    expected_crash_type=poc_result.get("expected_crash"),
                    poc_type=poc_result.get("poc_type", "input_file"),
                )

                if verification_result.verified:
                    stable, stability_reason = self.verifier.verify_stability(
                        poc_path,
                        pre_patch_binary,
                        runs=2,
                        poc_type=poc_result.get("poc_type", "input_file"),
                    )
                    if not stable:
                        verification_result.verified = False
                        verification_result.reason = stability_reason

                if verification_result.verified:
                    # 验证成功！
                    print(f"[{self.id}] 🎉 验证成功！{verification_result.reason}")

                    # 更新Idea状态
                    self.idea_board.update_status(idea.id, idea.task_id, "verified")

                    # 记录成功
                    self.memory_board.create_and_add(
                        task_id=idea.task_id,
                        type="poc_success",
                        content={
                            "idea_id": idea.id,
                            "poc_path": str(poc_path),
                            "crash_type": verification_result.crash_type,
                            "crash_location": verification_result.crash_location,
                            "iterations": iteration,
                        },
                        created_by=self.id,
                        related_idea=idea.id,
                    )

                    self.evidence_store.append(
                        Evidence.create(
                            type="verified",
                            agent_id=self.id,
                            task_id=idea.task_id,
                            content={
                                "idea_id": idea.id,
                                "poc_path": str(poc_path),
                                "verification": {
                                    "crash_type": verification_result.crash_type,
                                    "crash_location": verification_result.crash_location,
                                    "reason": verification_result.reason,
                                },
                            },
                        )
                    )

                    # 生成报告
                    report = VerificationReport.generate_report(verification_result, poc_path)
                    report_path = poc_path.with_suffix(".report.md")
                    report_path.write_text(report, encoding="utf-8")

                    return True

                else:
                    # 验证失败
                    print(f"[{self.id}] ❌ 验证失败: {verification_result.reason}")

                    # 记录失败
                    previous_attempts.append(
                        {
                            "iteration": iteration,
                            "reason": verification_result.reason,
                            "pre_crash": verification_result.pre_patch_crashed,
                            "post_crash": verification_result.post_patch_crashed,
                        }
                    )

                    self.memory_board.create_and_add(
                        task_id=idea.task_id,
                        type="poc_fail",
                        content={
                            "idea_id": idea.id,
                            "iteration": iteration,
                            "reason": verification_result.reason,
                        },
                        created_by=self.id,
                        related_idea=idea.id,
                    )

                    # 如果是最后一次尝试，记录负面证据
                    if iteration == self.max_iterations:
                        self.memory_board.create_and_add(
                            task_id=idea.task_id,
                            type="negative_evidence",
                            content={
                                "idea_id": idea.id,
                                "reason": f"经过{self.max_iterations}次尝试未能验证",
                                "attempts": previous_attempts,
                            },
                            created_by=self.id,
                            related_idea=idea.id,
                        )

            except Exception as e:
                print(f"[{self.id}] PoC构造/验证出错: {e}")
                previous_attempts.append(
                    {
                        "iteration": iteration,
                        "reason": f"异常: {str(e)}",
                    }
                )

            # 等待一小段时间再重试
            await asyncio.sleep(1)

        # 所有尝试都失败
        self.idea_board.update_status(idea.id, idea.task_id, "rejected")
        return False
