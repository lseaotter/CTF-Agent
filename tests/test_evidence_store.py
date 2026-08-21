"""测试证据存储系统"""

import tempfile
from pathlib import Path

import pytest

from app.core.evidence_store import Evidence, EvidenceStore


@pytest.fixture
def temp_storage():
    """临时存储目录"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


def test_evidence_creation():
    """测试证据创建"""
    evidence = Evidence.create(
        type="hypothesis",
        agent_id="test-agent",
        task_id="test-task",
        content={"description": "test hypothesis"},
    )
    assert evidence.id.startswith("ev-")
    assert evidence.type == "hypothesis"
    assert evidence.agent_id == "test-agent"
    assert evidence.task_id == "test-task"


def test_evidence_store_append(temp_storage):
    """测试证据追加"""
    store = EvidenceStore(temp_storage)
    evidence = Evidence.create(
        type="hypothesis",
        agent_id="agent-1",
        task_id="task-1",
        content={"test": "data"},
    )
    evidence_id = store.append(evidence)
    assert evidence_id == evidence.id


def test_evidence_store_query(temp_storage):
    """测试证据查询"""
    store = EvidenceStore(temp_storage)

    # 添加多条证据
    for i in range(3):
        evidence = Evidence.create(
            type="hypothesis" if i % 2 == 0 else "experiment",
            agent_id=f"agent-{i}",
            task_id="task-1",
            content={"index": i},
        )
        store.append(evidence)

    # 查询所有
    all_evidence = store.query(task_id="task-1")
    assert len(all_evidence) == 3

    # 按类型查询
    hypotheses = store.query(task_id="task-1", type="hypothesis")
    assert len(hypotheses) == 2


def test_evidence_store_get_latest(temp_storage):
    """测试获取最新证据"""
    store = EvidenceStore(temp_storage)

    # 添加5条证据
    for i in range(5):
        evidence = Evidence.create(
            type="experiment",
            agent_id="agent-1",
            task_id="task-1",
            content={"index": i},
        )
        store.append(evidence)

    # 获取最近3条
    latest = store.get_latest("task-1", limit=3)
    assert len(latest) == 3
    assert latest[-1].content["index"] == 4


def test_evidence_store_summary(temp_storage):
    """测试证据摘要"""
    store = EvidenceStore(temp_storage)

    # 添加不同类型的证据
    types = ["hypothesis", "experiment", "poc", "verified", "negative"]
    for t in types:
        evidence = Evidence.create(
            type=t,
            agent_id="agent-1",
            task_id="task-1",
            content={},
        )
        store.append(evidence)

    summary = store.get_summary("task-1")
    assert summary["total"] == 5
    assert summary["by_type"]["hypothesis"] == 1
    assert summary["by_type"]["verified"] == 1
