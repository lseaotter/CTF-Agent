"""漏洞假设生成器 - Stage 1（使用便宜模型）"""

from __future__ import annotations

import json
from pathlib import Path

from app.core.llm import LLMConfig, LLMManager
from app.memory.idea_board import Idea


def _canonical_idea_type(value: object) -> str:
    """Map model-specific vulnerability names to the board's stable categories."""
    normalized = str(value or "").strip().lower().replace("_", "-")
    if any(token in normalized for token in ("buffer", "overflow", "use-after-free", "double-free", "memory", "uaf")):
        return "memory_safety"
    if any(token in normalized for token in ("inject", "command", "sql", "path-traversal")):
        return "injection"
    if any(token in normalized for token in ("logic", "race", "deadlock", "concurr")):
        return "logic_bug"
    return normalized if normalized in {"memory-safety", "logic-bug", "injection", "other"} else "other"


class HypothesisGenerator:
    """漏洞假设生成器"""

    def __init__(self, model: str | None = None, llm_manager: LLMManager | None = None):
        self.llm_manager = llm_manager or LLMManager()
        self.model = model or LLMConfig().get_default_hypothesis_model()

    async def generate(self, task_description: str, task_id: str, code_summary: str | None = None) -> list[Idea]:
        """生成漏洞假设

        Args:
            task_description: 漏洞描述
            task_id: 任务ID
            code_summary: 代码摘要（可选）

        Returns:
            漏洞假设列表
        """
        system_prompt = """你是一个专业的安全研究员，擅长发现C/C++代码中的内存安全漏洞。

你的任务是根据漏洞描述和代码库，提出可能的漏洞假设。

关注以下漏洞类型：
1. 堆缓冲区溢出（heap-buffer-overflow）
2. 栈缓冲区溢出（stack-buffer-overflow）
3. Use-After-Free（UAF）
4. Double-Free
5. 越界读写
6. 整数溢出
7. 未初始化内存使用

要求：
- 每个假设必须包含具体的代码位置
- 优先级1-10，10最高
- 最多提出5个假设
- 按优先级降序排列"""

        user_prompt = f"""任务：分析以下漏洞并提出假设

漏洞描述：
{task_description}

{f'代码摘要：\\n{code_summary}\\n' if code_summary else ''}

请输出JSON数组格式：
```json
[
  {{
    "type": "memory_safety",
    "location": "src/parser.c:142",
    "description": "parse_input函数未检查输入长度，直接使用memcpy可能导致堆溢出",
    "priority": 9,
    "reasoning": "该函数处理用户输入，缺少边界检查"
  }},
  ...
]
```

只输出JSON数组，不要其他内容。"""

        try:
            response = await self.llm_manager.generate(
                prompt=user_prompt,
                system_prompt=system_prompt,
                model=self.model,
                temperature=0.1,
                max_tokens=2048,
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

            hypotheses = json.loads(response)

            # 转换为Idea对象
            ideas = []
            for i, h in enumerate(hypotheses):
                idea = Idea.create(
                    task_id=task_id,
                    type=_canonical_idea_type(h.get("type", "memory_safety")),
                    location=h["location"],
                    description=h["description"],
                    priority=h.get("priority", 5),
                    created_by="hypothesis_generator",
                )
                ideas.append(idea)

            return ideas

        except Exception as e:
            # 如果生成失败，返回一个通用假设
            print(f"假设生成失败: {e}")
            return [
                Idea.create(
                    task_id=task_id,
                    type="memory_safety",
                    location="unknown",
                    description=f"基于描述的通用假设: {task_description[:100]}",
                    priority=5,
                    created_by="hypothesis_generator",
                )
            ]

    async def refine_hypothesis(self, idea: Idea, feedback: str) -> Idea:
        """根据反馈优化假设

        Args:
            idea: 原始假设
            feedback: 反馈信息（如验证失败原因）

        Returns:
            优化后的假设
        """
        system_prompt = "你是一个安全研究员，根据反馈优化漏洞假设。"

        user_prompt = f"""原始假设：
位置：{idea.location}
描述：{idea.description}

反馈：
{feedback}

请基于反馈优化假设，输出JSON格式：
```json
{{
  "location": "更精确的位置",
  "description": "优化后的描述",
  "priority": 优先级(1-10)
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

            # 创建新的Idea
            return Idea.create(
                task_id=idea.task_id,
                type=idea.type,
                location=refined["location"],
                description=refined["description"],
                priority=refined.get("priority", idea.priority),
                created_by="hypothesis_generator",
            )

        except Exception as e:
            print(f"假设优化失败: {e}")
            return idea  # 返回原假设


class CodeAnalyzer:
    """代码分析器 - 提取代码摘要供假设生成使用"""

    def __init__(self):
        pass

    def analyze_repository(self, repo_path: Path) -> str:
        """分析代码仓库，生成摘要

        Args:
            repo_path: 代码仓库路径

        Returns:
            代码摘要
        """
        # TODO: 实现代码分析
        # 1. 找到可疑的函数（处理输入、内存操作等）
        # 2. 提取函数签名和关键逻辑
        # 3. 生成结构化摘要

        # 目前返回简单的文件列表
        c_files = list(repo_path.rglob("*.c")) + list(repo_path.rglob("*.cpp"))
        h_files = list(repo_path.rglob("*.h")) + list(repo_path.rglob("*.hpp"))

        summary = f"C/C++源文件数量: {len(c_files)}\n"
        summary += f"头文件数量: {len(h_files)}\n"

        if c_files:
            summary += "\n主要源文件:\n"
            for f in c_files[:10]:
                summary += f"  - {f.name}\n"

        return summary

    def find_suspicious_functions(self, repo_path: Path) -> list[dict]:
        """查找可疑函数

        Returns:
            可疑函数列表，每个包含：
            - file: 文件路径
            - function: 函数名
            - line: 行号
            - reason: 可疑原因
        """
        # TODO: 实现函数分析
        # 使用静态分析工具（如tree-sitter）识别：
        # - 使用memcpy/strcpy等不安全函数
        # - 处理用户输入
        # - 进行内存分配和释放

        return []
