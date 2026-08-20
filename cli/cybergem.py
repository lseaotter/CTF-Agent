"""CyberGem CLI - 命令行工具"""

import asyncio
import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from app.core.orchestrator import Orchestrator
from app.core.openharmony import OpenHarmonyPatchAnalyzer, evaluate_paths

app = typer.Typer(help="CyberGem - 智能漏洞挖掘框架")
console = Console()


@app.command("oh-analyze")
def oh_analyze(
    repo: Path = typer.Argument(..., exists=True, file_okay=False, help="OpenHarmony Git repository"),
    repair_commit: str = typer.Argument(..., help="Repair commit to inspect"),
    module: str = typer.Option(None, "--module", help="Competition module name"),
    file_path: str = typer.Option(None, "--file", help="Limit analysis to one source file"),
    cwe: str = typer.Option(None, "--cwe", help="Optional CWE hint from the task"),
    output: Path = typer.Option(None, "--output", help="Write the JSON candidate report"),
):
    """Analyze one OpenHarmony repair commit into an L1/L2/L3 submission."""
    try:
        result = OpenHarmonyPatchAnalyzer().analyze(
            repo,
            repair_commit,
            module=module,
            file_path=file_path,
            cwe_hint=cwe,
        )
    except Exception as exc:
        console.print(f"OpenHarmony analysis failed: {exc}", style="bold red")
        raise typer.Exit(1) from exc

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        console.print(f"Candidate report written to {output}")
    primary = result.get("primary")
    if primary:
        console.print(f"Primary candidate: {primary['location']}")
        console.print(f"L2: {primary['intro_commit']}")
        console.print(f"L3: {primary['cwe']}")
        console.print(f"trackId: {primary['track_id']}")
        for warning in result.get("warnings", []):
            console.print(f"Warning: {warning}", style="yellow")
    else:
        console.print("No relevant patch candidate found.", style="bold yellow")
        raise typer.Exit(2)


@app.command("oh-score")
def oh_score(
    prediction: Path = typer.Argument(..., exists=True, dir_okay=False, help="JSON prediction report"),
    truth: Path = typer.Option(
        Path("results/communication_netmanager_base_CORRECT_ANSWER.md"),
        "--truth",
        exists=True,
        dir_okay=False,
        help="Local ground-truth answer; no contest submission is performed",
    ),
):
    """Score an OpenHarmony answer locally using 5/4/1 points."""
    try:
        result = evaluate_paths(prediction, truth)
    except Exception as exc:
        console.print(f"OpenHarmony scoring failed: {exc}", style="bold red")
        raise typer.Exit(1) from exc

    best = result.get("best") or {}
    console.print(f"Score: {result['score']}/{result['max_score']} ({result['accuracy']:.1%})")
    console.print(
        f"L1 {'hit' if best.get('l1') else 'miss'} | "
        f"L2 {'hit' if best.get('l2') else 'miss'} | "
        f"L3 {'hit' if best.get('l3') else 'miss'}"
    )
    if best:
        console.print(json.dumps(best["submission"], ensure_ascii=False, indent=2))


@app.command()
def config(
    check: bool = typer.Option(False, "--check", help="检查配置"),
):
    """配置管理"""
    if check:
        console.print("[check] 检查配置...\n", style="bold blue")

        # 检查环境变量
        import os

        env_vars = {
            "DEEPSEEK_API_KEY": os.getenv("DEEPSEEK_API_KEY"),
            "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY"),
            "ANTHROPIC_API_KEY": os.getenv("ANTHROPIC_API_KEY"),
        }

        table = Table(title="环境变量")
        table.add_column("变量名", style="cyan")
        table.add_column("状态", style="green")

        for name, value in env_vars.items():
            status = "[OK] 已配置" if value else "[MISSING] 未配置"
            style = "green" if value else "red"
            table.add_row(name, f"[{style}]{status}[/{style}]")

        console.print(table)

        # 检查存储路径
        storage_root = Path("./storage")
        console.print(f"\n存储路径: {storage_root.absolute()}")
        console.print(f"   存在: {'[OK]' if storage_root.exists() else '[MISSING]'}")

        # 检查Docker
        import subprocess

        try:
            result = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
            docker_status = "[OK] 运行中" if result.returncode == 0 else "[MISSING] 未运行"
        except Exception:
            docker_status = "[MISSING] 未安装"

        console.print(f"\nDocker: {docker_status}")


@app.command()
def solve(
    task_id: str = typer.Argument(..., help="任务ID，如 arvo-6483"),
    description: str = typer.Option(None, "--description", "-d", help="漏洞描述"),
    repo: Path = typer.Option(None, "--repo", "-r", help="代码仓库路径"),
    pre_binary: Path = typer.Option(None, "--pre-binary", help="Pre-Patch二进制"),
    post_binary: Path = typer.Option(None, "--post-binary", help="Post-Patch二进制"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="详细输出"),
):
    """运行单个任务"""
    console.print(f"🎯 开始任务: {task_id}\n", style="bold green")

    if not all([description, repo, pre_binary, post_binary]):
        console.print("❌ 缺少必需参数", style="bold red")
        console.print("请提供: --description, --repo, --pre-binary, --post-binary")
        raise typer.Exit(1)

    # 创建编排器
    storage_root = Path("./storage")
    orchestrator = Orchestrator(storage_root)

    # 运行任务
    async def run():
        result = await orchestrator.run_task(
            task_id=task_id,
            task_description=description,
            repo_path=repo,
            pre_patch_binary=pre_binary,
            post_patch_binary=post_binary,
        )
        return result

    result = asyncio.run(run())

    # 显示结果
    console.print("\n" + "=" * 60)
    if result["success"]:
        console.print("✅ 任务成功！", style="bold green")
    else:
        console.print("❌ 任务失败", style="bold red")

    console.print(f"\n统计信息:")
    stats = result["stats"]
    console.print(f"  Ideas: {stats['ideas']['verified']}/{stats['ideas']['total']} 验证")
    console.print(f"  Memories: {stats['memories']['total']} 条")
    console.print(f"  Evidence: {stats['evidence']['total']} 条")
    console.print(f"  Tokens: {stats['tokens_used']:,}")


@app.command()
def benchmark(
    level: int = typer.Option(1, "--level", "-l", help="难度等级 (1-3)"),
    limit: int = typer.Option(10, "--limit", "-n", help="任务数量限制"),
    language: str = typer.Option(None, "--language", help="过滤语言 (c, cpp, rust)"),
):
    """运行benchmark评测"""
    console.print(f"🏆 开始Benchmark (Level {level}, 限制 {limit} 个任务)\n", style="bold blue")

    try:
        from app.benchmarks.cybergym import CyberGymBenchmark, CyberGymLoader
        from app.core.orchestrator import Orchestrator

        # 加载数据集
        loader = CyberGymLoader()
        benchmark_runner = CyberGymBenchmark(loader)

        console.print("📥 加载CyberGym数据集...")
        tasks = benchmark_runner.get_benchmark_tasks(
            level=level,
            limit=limit,
            filter_language=language,
        )

        if not tasks:
            console.print("❌ 没有找到符合条件的任务", style="bold red")
            raise typer.Exit(1)

        console.print(f"✓ 加载了 {len(tasks)} 个任务\n")

        # 创建编排器
        storage_root = Path("./storage")
        orchestrator = Orchestrator(storage_root)

        # 转换为编排器格式
        benchmark_tasks = []
        for task in tasks:
            pre_binary = Path(task.binary_path) if task.binary_path else None
            post_binary_value = CyberGymLoader.find_binary(task.repo_fix_path)
            post_binary = Path(post_binary_value) if post_binary_value else None
            if pre_binary is None or post_binary is None:
                console.print(
                    f"Skipping {task.task_id}: both pre/post binaries are required for verification.",
                    style="yellow",
                )
                continue
            benchmark_tasks.append({
                "task_id": task.task_id,
                "description": task.vulnerability_description,
                "repo_path": task.repo_vul_path,
                # 注意：这里需要实际的二进制路径，目前使用占位符
                "pre_patch_binary": pre_binary,
                "post_patch_binary": post_binary,
            })

        if not benchmark_tasks:
            console.print("No runnable tasks with both binaries were found.", style="bold red")
            raise typer.Exit(1)

        # 运行benchmark
        async def run():
            return await orchestrator.run_benchmark(benchmark_tasks)

        result = asyncio.run(run())

        # 显示结果
        console.print(f"\n{'='*60}")
        console.print(f"Benchmark结果", style="bold green")
        console.print(f"{'='*60}")
        console.print(f"总任务数: {result['total']}")
        console.print(f"成功数: {result['success']}")
        console.print(f"成功率: {result['success_rate']:.1%}")
        console.print(f"{'='*60}\n")

    except ImportError as e:
        console.print(f"❌ 导入失败: {e}", style="bold red")
        console.print("提示: 运行 pip install datasets")
    except Exception as e:
        console.print(f"❌ Benchmark运行失败: {e}", style="bold red")


@app.command()
def results(
    task_id: str = typer.Argument(..., help="任务ID"),
):
    """查看任务结果"""
    console.print(f"📊 任务结果: {task_id}\n", style="bold blue")

    storage_root = Path("./storage")
    orchestrator = Orchestrator(storage_root)

    report = orchestrator.get_task_report(task_id)

    # 显示报告
    console.print(f"任务ID: {report['task_id']}")
    console.print(f"状态: {'✅ 成功' if report['success'] else '❌ 失败'}")

    console.print("\nIdeas:")
    for key, value in report["ideas"].items():
        console.print(f"  {key}: {value}")

    console.print("\nMemories:")
    for key, value in report["memories"].items():
        console.print(f"  {key}: {value}")

    console.print("\nEvidence:")
    for key, value in report["evidence"].items():
        console.print(f"  {key}: {value}")


@app.command()
def tasks(
    list_tasks: bool = typer.Option(False, "--list", "-l", help="列出所有任务"),
    limit: int = typer.Option(20, "--limit", "-n", help="显示数量"),
    info: str = typer.Option(None, "--info", "-i", help="查看任务详情"),
):
    """任务管理"""
    try:
        from app.benchmarks.cybergym import CyberGymBenchmark, CyberGymLoader

        loader = CyberGymLoader()

        if info:
            # 显示任务详情
            console.print(f"📊 任务详情: {info}\n", style="bold blue")
            task = loader.load_task(info, level=1)

            console.print(f"任务ID: {task.task_id}")
            console.print(f"项目: {task.project_name}")
            console.print(f"语言: {task.project_language}")
            console.print(f"Docker: {task.docker_image}")
            console.print(f"\n漏洞描述:")
            console.print(task.vulnerability_description)

        elif list_tasks:
            # 列出任务
            console.print(f"📋 CyberGym任务列表 (前{limit}个):\n", style="bold blue")

            task_list = loader.list_tasks(limit=limit)

            table = Table(title=f"CyberGym Tasks")
            table.add_column("任务ID", style="cyan")
            table.add_column("项目", style="green")
            table.add_column("语言", style="yellow")
            table.add_column("描述", style="white")

            for task in task_list:
                table.add_row(
                    task["task_id"],
                    task["project_name"],
                    task["language"],
                    task["description"][:50] + "...",
                )

            console.print(table)

    except ImportError:
        console.print("❌ 需要安装 datasets: pip install datasets", style="bold red")
    except Exception as e:
        console.print(f"❌ 错误: {e}", style="bold red")


if __name__ == "__main__":
    app()
