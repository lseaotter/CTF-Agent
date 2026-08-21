"""测试Idea看板系统"""

import tempfile
from pathlib import Path

import pytest

from app.memory.idea_board import Idea, IdeaBoard


@pytest.fixture
def temp_storage():
    """临时存储目录"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


def test_idea_creation():
    """测试Idea创建"""
    idea = Idea.create(
        task_id="task-1",
        type="memory_safety",
        location="src/parser.c:142",
        description="parse_input未检查长度直接memcpy",
        priority=9,
        created_by="hypothesis_generator",
    )
    assert idea.id.startswith("idea-")
    assert idea.status == "pending"
    assert idea.assigned_to is None
    assert idea.priority == 9


def test_idea_board_add(temp_storage):
    """测试添加Idea"""
    board = IdeaBoard(temp_storage)
    idea = Idea.create(
        task_id="task-1",
        type="memory_safety",
        location="src/main.c:100",
        description="test vulnerability",
        priority=5,
        created_by="test-agent",
    )
    board.add(idea)

    # 验证已添加
    loaded = board.get(idea.id, "task-1")
    assert loaded is not None
    assert loaded.id == idea.id


def test_idea_board_claim(temp_storage):
    """测试Solver认领Idea"""
    board = IdeaBoard(temp_storage)

    # 添加多个不同优先级的Idea
    for i in range(3):
        idea = Idea.create(
            task_id="task-1",
            type="memory_safety",
            location=f"src/file{i}.c:100",
            description=f"vulnerability {i}",
            priority=i + 1,
            created_by="test-agent",
        )
        board.add(idea)

    # Solver认领（应该获取优先级最高的）
    claimed = board.claim("task-1", "solver-1")
    assert claimed is not None
    assert claimed.priority == 3  # 最高优先级
    assert claimed.status == "in_progress"
    assert claimed.assigned_to == "solver-1"


def test_idea_board_update_status(temp_storage):
    """测试更新Idea状态"""
    board = IdeaBoard(temp_storage)
    idea = Idea.create(
        task_id="task-1",
        type="memory_safety",
        location="src/test.c:50",
        description="test",
        priority=5,
        created_by="test-agent",
    )
    board.add(idea)

    # 更新状态
    board.update_status(idea.id, "task-1", "verified")

    # 验证状态已更新
    loaded = board.get(idea.id, "task-1")
    assert loaded.status == "verified"


def test_idea_board_list_pending(temp_storage):
    """测试获取待处理Idea列表"""
    board = IdeaBoard(temp_storage)

    # 添加不同状态的Idea
    for i in range(3):
        idea = Idea.create(
            task_id="task-1",
            type="memory_safety",
            location=f"src/file{i}.c:100",
            description=f"vulnerability {i}",
            priority=i + 1,
            created_by="test-agent",
        )
        board.add(idea)

    # 更新一个为verified
    ideas = board.list_all("task-1")
    board.update_status(ideas[0].id, "task-1", "verified")

    # 获取pending列表
    pending = board.list_pending("task-1")
    assert len(pending) == 2
    # 验证按优先级排序（降序）
    assert pending[0].priority > pending[1].priority


def test_idea_board_stats(temp_storage):
    """测试统计信息"""
    board = IdeaBoard(temp_storage)

    # 添加不同状态的Idea
    statuses = ["pending", "in_progress", "verified", "rejected"]
    for i, status in enumerate(statuses):
        idea = Idea.create(
            task_id="task-1",
            type="memory_safety",
            location=f"src/file{i}.c:100",
            description=f"vulnerability {i}",
            priority=5,
            created_by="test-agent",
        )
        idea.status = status
        board.add(idea)

    stats = board.get_stats("task-1")
    assert stats["total"] == 4
    assert stats["pending"] == 1
    assert stats["in_progress"] == 1
    assert stats["verified"] == 1
    assert stats["rejected"] == 1
