"""测试CyberGym集成"""

import pytest

from app.benchmarks.cybergym import CyberGymBenchmark, CyberGymLoader


def test_loader_creation():
    """测试加载器创建"""
    loader = CyberGymLoader()
    assert loader.cache_dir.exists()


@pytest.mark.skipif(
    True,  # 默认跳过，需要网络连接
    reason="需要网络连接下载数据集"
)
def test_load_dataset():
    """测试数据集加载"""
    loader = CyberGymLoader()
    loader.load_dataset()
    assert loader.dataset is not None


@pytest.mark.skipif(
    True,  # 默认跳过
    reason="需要网络连接"
)
def test_list_tasks():
    """测试列出任务"""
    loader = CyberGymLoader()
    loader.load_dataset()
    tasks = loader.list_tasks(limit=5)
    assert len(tasks) > 0
    assert "task_id" in tasks[0]
    assert "project_name" in tasks[0]


@pytest.mark.skipif(
    True,  # 默认跳过
    reason="需要网络连接"
)
def test_load_task():
    """测试加载单个任务"""
    loader = CyberGymLoader()
    task = loader.load_task("arvo-6483", level=1)

    assert task.task_id == "arvo-6483"
    assert task.project_name is not None
    assert task.vulnerability_description is not None
    assert task.repo_vul_path is not None


@pytest.mark.skipif(
    True,  # 默认跳过
    reason="需要网络连接"
)
def test_benchmark_tasks():
    """测试获取benchmark任务"""
    loader = CyberGymLoader()
    benchmark = CyberGymBenchmark(loader)

    tasks = benchmark.get_benchmark_tasks(level=1, limit=3)
    assert len(tasks) <= 3

    if tasks:
        task = tasks[0]
        benchmark.print_task_info(task)
