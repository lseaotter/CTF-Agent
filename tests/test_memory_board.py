"""测试Memory看板系统"""

import tempfile
from pathlib import Path

import pytest

from app.memory.memory_board import Memory, MemoryBoard


@pytest.fixture
def temp_storage():
    """临时存储目录"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


def test_memory_board_add(temp_storage):
    """测试添加Memory"""
    board = MemoryBoard(temp_storage)
    memory_id = board.create_and_add(
        task_id="task-1",
        type="poc_success",
        content={"vulnerability_type": "heap-buffer-overflow", "poc_path": "/tmp/poc.bin"},
        created_by="solver-1",
        related_idea="idea-123",
    )
    assert memory_id.startswith("mem-")


def test_memory_board_get_all(temp_storage):
    """测试获取所有Memory"""
    board = MemoryBoard(temp_storage)

    # 添加多条记忆
    for i in range(3):
        board.create_and_add(
            task_id="task-1",
            type="experiment",
            content={"index": i},
            created_by="solver-1",
        )

    memories = board.get_all("task-1")
    assert len(memories) == 3


def test_memory_board_get_latest(temp_storage):
    """测试获取最近的Memory"""
    board = MemoryBoard(temp_storage)

    # 添加5条记忆
    for i in range(5):
        board.create_and_add(
            task_id="task-1",
            type="experiment",
            content={"index": i},
            created_by="solver-1",
        )

    latest = board.get_latest("task-1", limit=3)
    assert len(latest) == 3
    assert latest[-1].content["index"] == 4


def test_memory_board_search(temp_storage):
    """测试搜索Memory"""
    board = MemoryBoard(temp_storage)

    # 添加不同类型的记忆
    types = ["poc_success", "poc_fail", "negative_evidence"]
    for t in types:
        board.create_and_add(
            task_id="task-1",
            type=t,
            content={},
            created_by="solver-1",
        )

    # 搜索特定类型
    success_memories = board.search("task-1", type="poc_success")
    assert len(success_memories) == 1


def test_memory_board_get_summary(temp_storage):
    """测试获取摘要"""
    board = MemoryBoard(temp_storage)

    # 添加不同类型的记忆
    board.create_and_add(
        task_id="task-1",
        type="poc_success",
        content={"vulnerability_type": "heap-overflow"},
        created_by="solver-1",
    )
    board.create_and_add(
        task_id="task-1",
        type="poc_fail",
        content={"reason": "timeout"},
        created_by="solver-1",
    )
    board.create_and_add(
        task_id="task-1",
        type="insight",
        content={"summary": "发现新模式"},
        created_by="observer",
    )

    summary = board.get_summary("task-1")
    assert "✓ PoC成功" in summary
    assert "✗ PoC失败" in summary
    assert "💡 发现" in summary


def test_memory_board_stats(temp_storage):
    """测试统计信息"""
    board = MemoryBoard(temp_storage)

    # 添加不同类型的记忆
    types = ["poc_success", "poc_success", "poc_fail", "negative_evidence"]
    for t in types:
        board.create_and_add(
            task_id="task-1",
            type=t,
            content={},
            created_by="solver-1",
        )

    stats = board.get_stats("task-1")
    assert stats["total"] == 4
    assert stats["poc_success"] == 2
    assert stats["poc_fail"] == 1
    assert stats["negative_evidence"] == 1


def test_memory_board_has_success(temp_storage):
    """测试检查是否有成功PoC"""
    board = MemoryBoard(temp_storage)

    # 初始应该没有成功
    assert board.has_success("task-1") is False

    # 添加失败记录
    board.create_and_add(
        task_id="task-1",
        type="poc_fail",
        content={},
        created_by="solver-1",
    )
    assert board.has_success("task-1") is False

    # 添加成功记录
    board.create_and_add(
        task_id="task-1",
        type="poc_success",
        content={},
        created_by="solver-1",
    )
    assert board.has_success("task-1") is True


def test_memory_board_compress(temp_storage):
    """测试上下文压缩"""
    board = MemoryBoard(temp_storage)

    # 添加20条记忆
    for i in range(20):
        board.create_and_add(
            task_id="task-1",
            type="experiment",
            content={"index": i},
            created_by="solver-1",
        )

    # 压缩，只保留最近5条
    board.compress("task-1", keep_recent=5)

    # 验证压缩后的数量（5条 + 1条压缩摘要）
    memories = board.get_all("task-1")
    assert len(memories) == 6

    # 验证第一条是压缩摘要
    assert memories[0].type == "insight"
    assert "压缩了15条旧记忆" in memories[0].content["summary"]
