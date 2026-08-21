"""PoC构造器 - Stage 2（使用强模型）"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from app.core.llm import LLMConfig, LLMManager
from app.memory.idea_board import Idea


class PoCBuilder:
    """PoC构造器"""

    def __init__(self, model: str | None = None, llm_manager: LLMManager | None = None):
        self.llm_manager = llm_manager or LLMManager()
        self.model = model or LLMConfig().get_default_poc_model()

    async def build(
        self,
        idea: Idea,
        context: str,
        iteration: int = 1,
        previous_attempts: list[dict] | None = None,
    ) -> dict:
        """构造PoC

        Args:
            idea: 漏洞假设
            context: 上下文（Memory摘要）
            iteration: 当前迭代次数
            previous_attempts: 之前的尝试记录

        Returns:
            PoC结果，包含：
            - poc_type: 类型（input_file/command_args/stdin）
            - content: PoC内容
            - expected_crash: 预期崩溃类型
            - reasoning: 构造reasoning
        """
        system_prompt = """你是一个专业的安全研究员，擅长构造PoC来触发C/C++程序中的内存安全漏洞。

你的任务是基于漏洞假设，构造最小化的触发输入。

要求：
1. PoC必须最小化，只触发目标漏洞
2. 不要破坏程序的正常解析流程
3. 针对内存安全漏洞（堆/栈溢出、UAF等）
4. 输出具体的二进制/文本内容

常见策略：
- 堆溢出：构造超长输入
- UAF：触发特定的对象释放和重用序列
- 整数溢出：提供导致溢出的大数值
- 格式化字符串：注入%s/%n等格式符"""

        attempts_text = ""
        if previous_attempts:
            attempts_text = "\n之前的尝试:\n"
            for i, attempt in enumerate(previous_attempts[-3:], 1):  # 只显示最近3次
                attempts_text += f"{i}. {attempt.get('reason', 'unknown')}\n"

        user_prompt = f"""任务：为以下漏洞构造PoC

漏洞假设：
位置：{idea.location}
类型：{idea.type}
描述：{idea.description}

上下文信息：
{context}

{attempts_text}

当前是第 {iteration} 次尝试。

请输出JSON格式：
```json
{{
  "poc_type": "input_file",
  "content": "PoC内容（如果是二进制，使用base64编码）",
  "content_encoding": "text",
  "expected_crash": "heap-buffer-overflow",
  "reasoning": "为什么这个输入会触发漏洞",
  "filename": "poc.txt"
}}
```

poc_type可选值：
- input_file: 作为文件输入
- command_args: 作为命令行参数
- stdin: 通过标准输入

只输出JSON，不要其他内容。"""

        try:
            response = await self.llm_manager.generate(
                prompt=user_prompt,
                system_prompt=system_prompt,
                model=self.model,
                temperature=0.2,  # 稍高的温度增加创造性
                max_tokens=4096,
            )

            # 提取JSON
            response = response.strip()
            if "```json" in response:
                start = response.find("```json") + 7
                end = response.find("```", start)
                response = response[start:end].strip()
            elif "```" in response:
                start = response.find("```") + 3
                end = response.find("```", start)
                response = response[start:end].strip()

            poc_result = json.loads(response)

            # 验证必需字段
            required_fields = ["poc_type", "content", "expected_crash"]
            for field in required_fields:
                if field not in poc_result:
                    raise ValueError(f"缺少必需字段: {field}")

            return poc_result

        except Exception as e:
            print(f"PoC构造失败: {e}")
            # 返回一个简单的fallback PoC
            return {
                "poc_type": "input_file",
                "content": "A" * 1024,  # 简单的长字符串
                "content_encoding": "text",
                "expected_crash": "heap-buffer-overflow",
                "reasoning": f"生成失败，使用fallback PoC: {str(e)}",
                "filename": "poc.txt",
            }

    async def refine_from_crash(self, poc_result: dict, crash_info: dict) -> dict:
        """根据崩溃信息优化PoC

        Args:
            poc_result: 原始PoC
            crash_info: 崩溃信息（包含sanitizer报告）

        Returns:
            优化后的PoC
        """
        system_prompt = "你是安全研究员，根据崩溃信息优化PoC。"

        user_prompt = f"""原始PoC：
类型：{poc_result['poc_type']}
内容：{poc_result['content'][:200]}...
预期崩溃：{poc_result['expected_crash']}

实际崩溃信息：
{json.dumps(crash_info, indent=2, ensure_ascii=False)}

请优化PoC使其更精确地触发目标漏洞。输出JSON格式：
```json
{{
  "poc_type": "类型",
  "content": "优化后的内容",
  "expected_crash": "崩溃类型",
  "reasoning": "优化reasoning"
}}
```"""

        try:
            response = await self.llm_manager.generate(
                prompt=user_prompt,
                system_prompt=system_prompt,
                model=self.model,
                temperature=0.1,
            )

            # 提取JSON
            if "```json" in response:
                start = response.find("```json") + 7
                end = response.find("```", start)
                response = response[start:end].strip()

            refined = json.loads(response)
            return refined

        except Exception as e:
            print(f"PoC优化失败: {e}")
            return poc_result  # 返回原PoC


class PoCWriter:
    """PoC文件写入器"""

    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.poc_dir = workspace / "pocs"
        self.poc_dir.mkdir(parents=True, exist_ok=True)

    def write_poc(self, poc_result: dict, idea_id: str) -> Path:
        """写入PoC文件

        Args:
            poc_result: PoC结果
            idea_id: 关联的Idea ID

        Returns:
            PoC文件路径
        """
        import base64

        # 确定文件名
        filename = Path(str(poc_result.get("filename", f"poc_{idea_id}.bin"))).name
        if not filename or filename in {".", ".."}:
            filename = f"poc_{idea_id}.bin"
        poc_type = poc_result.get("poc_type", "input_file")
        if poc_type not in {"input_file", "command_args", "stdin"}:
            raise ValueError(f"Unsupported poc_type: {poc_type}")
        poc_path = self.poc_dir / filename

        # 写入内容
        content = poc_result["content"]
        encoding = poc_result.get("content_encoding", "text")

        if encoding == "base64":
            # Base64解码
            content_bytes = base64.b64decode(content)
            poc_path.write_bytes(content_bytes)
        else:
            # 文本内容
            poc_path.write_text(content, encoding="utf-8")

        # 写入元数据
        metadata_path = poc_path.with_suffix(poc_path.suffix + ".json")
        metadata = {
            "idea_id": idea_id,
            "poc_type": poc_type,
            "expected_crash": poc_result["expected_crash"],
            "reasoning": poc_result.get("reasoning", ""),
        }
        metadata_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")

        return poc_path

    def list_pocs(self) -> list[Path]:
        """列出所有PoC文件"""
        return [p for p in self.poc_dir.iterdir() if not p.suffix == ".json"]
