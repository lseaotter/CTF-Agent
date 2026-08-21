"""PoC验证器 - 确定性验收"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.execution.sanitizer import PocType, SanitizerParser, SanitizerResult, SanitizerRunner


@dataclass
class VerificationResult:
    """验证结果"""

    verified: bool
    pre_patch_crashed: bool
    post_patch_crashed: bool
    crash_type: str | None
    crash_location: str | None
    pre_patch_report: str | None
    post_patch_report: str | None
    reason: str  # 验证通过/失败的原因


class PoCVerifier:
    """PoC验证器"""

    def __init__(self, sanitizer_runner: SanitizerRunner | None = None):
        self.sanitizer_runner = sanitizer_runner or SanitizerRunner()

    def verify_poc(
        self,
        poc_path: Path,
        pre_patch_binary: Path,
        post_patch_binary: Path,
        expected_crash_type: str | None = None,
        poc_type: PocType = "input_file",
    ) -> VerificationResult:
        """验证PoC

        标准：
        1. Pre-Patch版本必须崩溃
        2. Post-Patch版本必须不崩溃
        3. （可选）崩溃类型匹配预期

        Args:
            poc_path: PoC文件路径
            pre_patch_binary: Pre-Patch二进制文件
            post_patch_binary: Post-Patch二进制文件
            expected_crash_type: 预期的崩溃类型

        Returns:
            验证结果
        """
        # 在Pre-Patch版本运行
        pre_result = self.sanitizer_runner.run_with_asan(
            pre_patch_binary,
            poc_path,
            poc_type=poc_type,
        )

        # 在Post-Patch版本运行
        post_result = self.sanitizer_runner.run_with_asan(
            post_patch_binary,
            poc_path,
            poc_type=poc_type,
        )

        # 判断验证是否通过
        verified = False
        reason = ""

        if not pre_result.crashed:
            reason = "Pre-Patch版本未崩溃"
        elif post_result.crashed:
            reason = "Post-Patch版本仍然崩溃"
        elif expected_crash_type and pre_result.crash_type != expected_crash_type:
            reason = f"崩溃类型不匹配：预期{expected_crash_type}，实际{pre_result.crash_type}"
        else:
            verified = True
            reason = f"验证通过：Pre-Patch崩溃（{pre_result.crash_type}），Post-Patch正常"

        return VerificationResult(
            verified=verified,
            pre_patch_crashed=pre_result.crashed,
            post_patch_crashed=post_result.crashed,
            crash_type=pre_result.crash_type,
            crash_location=pre_result.crash_location,
            pre_patch_report=pre_result.sanitizer_report,
            post_patch_report=post_result.sanitizer_report,
            reason=reason,
        )

    def verify_stability(
        self,
        poc_path: Path,
        binary: Path,
        runs: int = 3,
        poc_type: PocType = "input_file",
    ) -> tuple[bool, str]:
        """验证PoC稳定性

        运行多次，检查是否每次都能稳定触发相同的崩溃

        Args:
            poc_path: PoC路径
            binary: 二进制文件
            runs: 运行次数

        Returns:
            (is_stable, reason)
        """
        results = []
        for _ in range(runs):
            result = self.sanitizer_runner.run_with_asan(binary, poc_path, poc_type=poc_type)
            results.append(result)

        # 检查所有运行是否都崩溃
        all_crashed = all(r.crashed for r in results)
        if not all_crashed:
            return False, f"不稳定：{runs}次运行中只有{sum(r.crashed for r in results)}次崩溃"

        # 检查崩溃类型是否一致
        crash_types = [r.crash_type for r in results]
        if len(set(crash_types)) > 1:
            return False, f"不稳定：崩溃类型不一致 {crash_types}"

        # 检查崩溃位置是否一致（使用报告相似度）
        first_report = results[0].sanitizer_report
        for i, result in enumerate(results[1:], 2):
            if not SanitizerParser.is_same_crash(first_report, result.sanitizer_report):
                return False, f"不稳定：第{i}次运行的崩溃位置不同"

        return True, f"稳定：{runs}次运行都触发了相同的崩溃"

    def independent_verification(self, poc_path: Path, binary: Path) -> SanitizerResult:
        """独立验证

        在独立上下文中重新执行，避免依赖之前的运行状态

        Args:
            poc_path: PoC路径
            binary: 二进制文件

        Returns:
            运行结果
        """
        # 简单实现：直接运行
        # 生产环境可以考虑：
        # 1. 在新的Docker容器中运行
        # 2. 清理环境变量
        # 3. 使用临时目录
        return self.sanitizer_runner.run_with_asan(binary, poc_path)


class VerificationReport:
    """验证报告生成器"""

    @staticmethod
    def generate_report(verification_result: VerificationResult, poc_path: Path) -> str:
        """生成验证报告

        Args:
            verification_result: 验证结果
            poc_path: PoC路径

        Returns:
            Markdown格式的报告
        """
        status = "✅ 验证通过" if verification_result.verified else "❌ 验证失败"

        report = f"""# PoC验证报告

## 状态
{status}

## PoC信息
- 文件: {poc_path.name}
- 大小: {poc_path.stat().st_size} bytes

## 验证结果
- Pre-Patch崩溃: {"是" if verification_result.pre_patch_crashed else "否"}
- Post-Patch崩溃: {"是" if verification_result.post_patch_crashed else "否"}
- 崩溃类型: {verification_result.crash_type or "N/A"}
- 崩溃位置: {verification_result.crash_location or "N/A"}

## 原因
{verification_result.reason}

"""

        if verification_result.pre_patch_report:
            report += f"""## Pre-Patch Sanitizer报告
```
{verification_result.pre_patch_report}
```

"""

        if verification_result.post_patch_report:
            report += f"""## Post-Patch Sanitizer报告
```
{verification_result.post_patch_report}
```
"""

        return report
