"""端到端测试 - 完整流程验证"""

import tempfile
from pathlib import Path

import pytest

from app.core.evidence_store import EvidenceStore
from app.core.hypothesis import HypothesisGenerator
from app.memory.idea_board import IdeaBoard
from app.memory.memory_board import MemoryBoard


@pytest.fixture
def temp_storage():
    """临时存储目录"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.mark.asyncio
async def test_hypothesis_generation(temp_storage):
    """测试假设生成流程"""
    # 创建假设生成器
    generator = HypothesisGenerator()

    # 简单的漏洞描述
    task_description = """
    parse_input函数在处理用户输入时，未检查输入长度就直接使用memcpy，
    可能导致堆缓冲区溢出。
    """

    # 生成假设
    ideas = await generator.generate(
        task_description=task_description,
        task_id="test-task-1",
        code_summary="简单的C程序，包含parse_input函数",
    )

    # 验证生成了假设
    assert len(ideas) > 0
    assert ideas[0].task_id == "test-task-1"
    assert ideas[0].type in ["memory_safety", "logic_bug", "injection", "other"]
    assert ideas[0].priority >= 1 and ideas[0].priority <= 10


@pytest.mark.asyncio
async def test_complete_workflow(temp_storage):
    """测试完整工作流程"""
    # 1. 创建存储组件
    evidence_store = EvidenceStore(temp_storage / "evidence")
    idea_board = IdeaBoard(temp_storage / "ideas")
    memory_board = MemoryBoard(temp_storage / "memories")

    task_id = "test-workflow-1"

    # 2. 生成假设
    generator = HypothesisGenerator()
    ideas = await generator.generate(
        task_description="堆缓冲区溢出漏洞",
        task_id=task_id,
    )

    # 3. 添加到Idea Board
    for idea in ideas:
        idea_board.add(idea)

    # 验证Ideas
    stats = idea_board.get_stats(task_id)
    assert stats["total"] == len(ideas)
    assert stats["pending"] == len(ideas)

    # 4. 模拟Solver认领
    claimed_idea = idea_board.claim(task_id, "solver-test")
    assert claimed_idea is not None
    assert claimed_idea.status == "in_progress"
    assert claimed_idea.assigned_to == "solver-test"

    # 5. 记录实验结果
    memory_board.create_and_add(
        task_id=task_id,
        type="poc_fail",
        content={"reason": "Pre-Patch未崩溃"},
        created_by="solver-test",
        related_idea=claimed_idea.id,
    )

    # 6. 更新Idea状态
    idea_board.update_status(claimed_idea.id, task_id, "rejected")

    # 验证状态
    updated_idea = idea_board.get(claimed_idea.id, task_id)
    assert updated_idea.status == "rejected"

    # 验证Memory
    memories = memory_board.get_all(task_id)
    assert len(memories) == 1
    assert memories[0].type == "poc_fail"

    # 7. 获取摘要
    summary = memory_board.get_summary(task_id)
    assert "PoC失败" in summary


def test_storage_persistence(temp_storage):
    """测试存储持久化"""
    # 创建Idea Board
    idea_board1 = IdeaBoard(temp_storage)

    # 添加Idea
    from app.memory.idea_board import Idea

    idea = Idea.create(
        task_id="persist-test",
        type="memory_safety",
        location="test.c:100",
        description="test",
        priority=5,
        created_by="test",
    )
    idea_board1.add(idea)

    # 创建新的Idea Board实例（模拟重启）
    idea_board2 = IdeaBoard(temp_storage)

    # 验证数据持久化
    loaded_idea = idea_board2.get(idea.id, "persist-test")
    assert loaded_idea is not None
    assert loaded_idea.id == idea.id
    assert loaded_idea.description == idea.description
