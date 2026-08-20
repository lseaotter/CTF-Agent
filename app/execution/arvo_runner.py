"""ARVO容器运行器 - 在Docker中执行PoC"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path

import docker
from docker.errors import DockerException, ImageNotFound

from app.execution.sanitizer import SanitizerParser


@dataclass
class ContainerRunResult:
    """容器运行结果"""

    exit_code: int
    stdout: str
    stderr: str
    crashed: bool
    crash_type: str | None
    crash_location: str | None
    sanitizer_report: str | None
    timeout: bool


class ARVORunner:
    """ARVO漏洞环境运行器"""

    def __init__(self, platform: str = "linux/amd64"):
        """初始化运行器

        Args:
            platform: Docker平台（linux/amd64或linux/arm64）
        """
        self.platform = platform
        try:
            self.client = docker.from_env()
            # 测试连接
            self.client.ping()
        except DockerException as e:
            print(f"⚠️  Docker连接失败: {e}")
            print("提示: 确保Docker服务正在运行")
            self.client = None

    def run_pre_patch(
        self,
        docker_image: str,
        binary_path: str,
        poc_path: Path,
        timeout: int = 60,
    ) -> ContainerRunResult:
        """在Pre-Patch版本运行PoC

        Args:
            docker_image: Docker镜像名，如 "n132/arvo:6483-vul"
            binary_path: 容器内的二进制路径，如 "/out/curl_fuzzer"
            poc_path: 本地PoC文件路径
            timeout: 超时时间（秒）

        Returns:
            运行结果
        """
        return self._run_in_container(
            docker_image=docker_image,
            binary_path=binary_path,
            poc_path=poc_path,
            timeout=timeout,
            env={
                "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1:symbolize=1",
            },
        )

    def run_post_patch(
        self,
        docker_image: str,
        binary_path: str,
        poc_path: Path,
        timeout: int = 60,
    ) -> ContainerRunResult:
        """在Post-Patch版本运行PoC

        Post-Patch镜像通常命名为 xxx-fix

        Args:
            docker_image: Docker镜像名，如 "n132/arvo:6483-fix"
            binary_path: 容器内的二进制路径
            poc_path: 本地PoC文件路径
            timeout: 超时时间（秒）

        Returns:
            运行结果
        """
        # 将-vul替换为-fix
        post_image = docker_image.replace("-vul", "-fix")

        return self._run_in_container(
            docker_image=post_image,
            binary_path=binary_path,
            poc_path=poc_path,
            timeout=timeout,
            env={
                "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1:symbolize=1",
            },
        )

    def _run_in_container(
        self,
        docker_image: str,
        binary_path: str,
        poc_path: Path,
        timeout: int,
        env: dict,
    ) -> ContainerRunResult:
        """在容器中运行

        Args:
            docker_image: Docker镜像
            binary_path: 二进制路径
            poc_path: PoC文件路径
            timeout: 超时
            env: 环境变量

        Returns:
            运行结果
        """
        if self.client is None:
            return ContainerRunResult(
                exit_code=-1,
                stdout="",
                stderr="Docker未连接",
                crashed=False,
                crash_type=None,
                crash_location=None,
                sanitizer_report=None,
                timeout=False,
            )

        try:
            # 确保镜像存在
            try:
                self.client.images.get(docker_image)
            except ImageNotFound:
                print(f"镜像 {docker_image} 不存在，尝试拉取...")
                self.client.images.pull(docker_image)

            # 读取PoC内容（编码为base64避免特殊字符问题）
            poc_content = poc_path.read_bytes()
            poc_b64 = base64.b64encode(poc_content).decode()

            # 构造命令：先解码PoC，然后运行二进制
            command = f'''sh -c "
                echo '{poc_b64}' | base64 -d > /tmp/poc.bin &&
                {binary_path} /tmp/poc.bin
            "'''

            # 运行容器
            container = self.client.containers.run(
                image=docker_image,
                command=command,
                detach=True,
                environment=env,
                platform=self.platform,
                auto_remove=False,  # 手动删除，以便获取日志
                mem_limit="512m",
                cpu_quota=100000,  # 1 CPU
            )

            # 等待容器完成
            try:
                result = container.wait(timeout=timeout)
                exit_code = result["StatusCode"]
                timeout_occurred = False
            except Exception:
                # 超时
                container.stop(timeout=1)
                exit_code = -1
                timeout_occurred = True

            # 获取日志
            logs = container.logs().decode("utf-8", errors="replace")
            stdout = logs
            stderr = logs  # Docker合并了stdout和stderr

            # 删除容器
            container.remove(force=True)

            # 解析结果
            crashed = exit_code != 0 and not timeout_occurred
            crash_type = None
            crash_location = None
            sanitizer_report = None

            if crashed:
                crash_type, crash_location, sanitizer_report = self._parse_sanitizer(stderr)

            return ContainerRunResult(
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                crashed=crashed,
                crash_type=crash_type,
                crash_location=crash_location,
                sanitizer_report=sanitizer_report,
                timeout=timeout_occurred,
            )

        except Exception as e:
            return ContainerRunResult(
                exit_code=-1,
                stdout="",
                stderr=f"容器运行失败: {str(e)}",
                crashed=False,
                crash_type=None,
                crash_location=None,
                sanitizer_report=None,
                timeout=False,
            )

    def _parse_sanitizer(self, stderr: str) -> tuple[str | None, str | None, str | None]:
        """解析Sanitizer输出

        Returns:
            (crash_type, crash_location, full_report)
        """
        parser = SanitizerParser()
        report = parser.parse_asan_report(stderr)

        return (
            report.get("crash_type"),
            report["stack_trace"][0] if report.get("stack_trace") else None,
            stderr[:2000] if stderr else None,
        )

    def verify_poc(
        self,
        docker_image: str,
        binary_path: str,
        poc_path: Path,
        timeout: int = 60,
    ) -> bool:
        """验证PoC: Pre-Patch崩溃 && Post-Patch不崩溃

        Args:
            docker_image: Docker镜像（Pre-Patch版本）
            binary_path: 二进制路径
            poc_path: PoC文件路径
            timeout: 超时

        Returns:
            是否验证通过
        """
        print(f"[ARVO] 验证PoC: {poc_path.name}")

        # 在Pre-Patch运行
        print(f"[ARVO] 运行Pre-Patch版本...")
        pre_result = self.run_pre_patch(docker_image, binary_path, poc_path, timeout)

        if pre_result.timeout:
            print(f"[ARVO] ✗ Pre-Patch超时")
            return False

        if not pre_result.crashed:
            print(f"[ARVO] ✗ Pre-Patch未崩溃")
            return False

        print(f"[ARVO] ✓ Pre-Patch崩溃: {pre_result.crash_type}")

        # 在Post-Patch运行
        print(f"[ARVO] 运行Post-Patch版本...")
        post_result = self.run_post_patch(docker_image, binary_path, poc_path, timeout)

        if post_result.timeout:
            print(f"[ARVO] ⚠️  Post-Patch超时")
            return False

        if post_result.crashed:
            print(f"[ARVO] ✗ Post-Patch仍然崩溃")
            return False

        print(f"[ARVO] ✓ Post-Patch正常")
        print(f"[ARVO] 🎉 验证通过！")

        return True

    def pull_image(self, docker_image: str) -> bool:
        """拉取Docker镜像

        Args:
            docker_image: 镜像名

        Returns:
            是否成功
        """
        if self.client is None:
            return False

        try:
            print(f"拉取镜像: {docker_image}...")
            self.client.images.pull(docker_image)
            print(f"✓ 镜像拉取成功")
            return True
        except Exception as e:
            print(f"✗ 镜像拉取失败: {e}")
            return False

    def list_images(self, filter: str = "n132/arvo") -> list[str]:
        """列出本地镜像

        Args:
            filter: 过滤条件

        Returns:
            镜像名列表
        """
        if self.client is None:
            return []

        images = self.client.images.list(name=filter)
        return [tag for img in images for tag in img.tags]
