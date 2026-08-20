# CTF-Agent / CyberGem

> 基于多 Agent 编排的自动化漏洞发现与验证系统，面向合法 CTF、CyberGym 和明确授权的研究环境。
>
> An AI agent framework for solving CTF challenges in authorized environments.

[![Tests](https://github.com/lseaotter/CTF-Agent/actions/workflows/ci.yml/badge.svg)](https://github.com/lseaotter/CTF-Agent/actions/workflows/ci.yml)

本仓库是一个研究型工具，不是面向互联网的扫描器。默认配置只允许在本地或显式授权的目标上运行。

## 特性

- ✅ **多Agent协作** - Manager/Observer/Solver三角色架构
- ✅ **证据驱动** - Append-only事件存储，可追溯验证过程
- ✅ **成本优化** - 两阶段检测（便宜模型假设 + 强模型验证）
- ✅ **CyberGym集成** - 原生支持CyberGym benchmark
- ✅ **Sanitizer验证** - ASan/UBSan/MSan确定性验收
- ✅ **上下文治理** - 看板系统 + 轨迹压缩

## 架构

```
┌─────────────────────────────────────────────────┐
│              Orchestrator                       │
│    (确定性任务调度 + 状态机管理)                 │
└─────────────────────────────────────────────────┘
          │              │              │
    ┌─────▼─────┐  ┌────▼────┐  ┌──────▼──────┐
    │  Manager  │  │Observer │  │   Solver    │
    │  (调度器) │  │(监督器) │  │  (执行器)   │
    └─────┬─────┘  └────┬────┘  └──────┬──────┘
          │              │              │
    ┌─────▼──────────────▼──────────────▼─────┐
    │         Evidence Store + 看板系统        │
    │   Idea Board | Memory Board | Events     │
    └──────────────────────────────────────────┘
                     │
    ┌────────────────▼────────────────┐
    │   Execution Backend             │
    │  Docker + Sanitizer + ARVO      │
    └─────────────────────────────────┘
```

## 快速开始

### 安装

```bash
# 克隆仓库
git clone https://github.com/lseaotter/CTF-Agent.git CTF-Agent
cd CTF-Agent

# 创建虚拟环境
python -m venv .venv
.venv\Scripts\Activate.ps1  # Windows
# source .venv/bin/activate  # Linux

# 安装
pip install -e ".[dev]"
```

### 配置

复制配置模板：

```bash
cp configs/models.yaml.example configs/models.yaml
cp .env.example .env
```

编辑 `.env`：

```bash
DEEPSEEK_API_KEY=sk-your-key-here
OPENAI_API_KEY=sk-your-key-here
ANTHROPIC_API_KEY=sk-your-key-here
```

### 运行单个任务

```bash
cybergem solve --task-id arvo-6483
```

### 运行benchmark

```bash
cybergem benchmark --level 1 --limit 10
```

## 使用示例

### 1. 配置检查

```bash
cybergem config --check
```

输出：
```
✓ DeepSeek API: 已配置
✓ Storage路径: .\storage
✓ Docker: 运行中
✓ CyberGym数据集: 已缓存
```

### 2. 查看可用任务

```bash
cybergem tasks --list
```

### 3. 运行特定任务

```bash
cybergem solve --task-id arvo-6483 --verbose
```

工作流程：
1. 加载CyberGym任务描述
2. 生成漏洞假设（DeepSeek）
3. 分配给Solver
4. 构造PoC（GPT-5/Opus）
5. Sanitizer验证
6. 生成报告

### 4. 查看结果

```bash
cybergem results --task-id arvo-6483
```

输出：
```json
{
  "task_id": "arvo-6483",
  "status": "verified",
  "poc_path": "storage/tasks/arvo-6483/poc.bin",
  "vulnerability_type": "heap-buffer-overflow",
  "cost_usd": 1.52,
  "time_seconds": 127
}
```

## 项目结构

```
cybergem/
├── app/
│   ├── agents/              # Agent实现
│   │   ├── manager.py       # 任务调度器
│   │   ├── observer.py      # 策略监督器
│   │   └── solver.py        # 漏洞探测器
│   ├── core/                # 核心组件
│   │   ├── orchestrator.py  # 编排器
│   │   ├── evidence_store.py # 证据存储
│   │   ├── hypothesis.py    # 假设生成
│   │   ├── poc_builder.py   # PoC构造
│   │   └── verifier.py      # 验证器
│   ├── execution/           # 执行后端
│   │   ├── container.py     # 容器管理
│   │   ├── sanitizer.py     # Sanitizer运行器
│   │   └── arvo_runner.py   # ARVO环境
│   ├── memory/              # 状态管理
│   │   ├── idea_board.py    # Idea看板
│   │   └── memory_board.py  # Memory看板
│   ├── benchmarks/          # Benchmark适配
│   │   └── cybergym.py      # CyberGym加载器
│   └── api/                 # API服务
│       └── main.py          # FastAPI入口
├── cli/                     # 命令行工具
│   └── cybergem.py          # CLI入口
├── configs/                 # 配置文件
│   ├── models.yaml          # LLM配置
│   ├── agents.yaml          # Agent配置
│   └── sanitizers.yaml      # Sanitizer配置
├── storage/                 # 数据存储
│   ├── tasks/               # 任务工作空间
│   ├── evidence/            # 证据数据库
│   └── results/             # 评测结果
└── tests/                   # 测试
```

## 配置说明

### models.yaml

```yaml
providers:
  deepseek_cheap:
    provider: deepseek
    model: deepseek-v4-pro
    api_key_env: DEEPSEEK_API_KEY
    use_for: hypothesis_generation

  openai_strong:
    provider: openai
    model: gpt-5
    api_key_env: OPENAI_API_KEY
    use_for: poc_construction
```

### agents.yaml

```yaml
manager:
  max_solvers: 3
  budget_tokens: 200000
  timeout_seconds: 600

solver:
  max_iterations: 5
  poc_timeout: 60
  model: openai_strong
```

## API使用

启动本地研究控制台（Windows）：

```bash
\.venv\Scripts\python.exe web_interface.py --port 8765
```

健康检查：

```powershell
Invoke-RestMethod http://127.0.0.1:8765/api/v1/health
```

兼容的 ASGI 入口仍然是 `app.api.main:app`，但默认应绑定到本机：

```powershell
\.venv\Scripts\python.exe -m uvicorn app.api.main:app --host 127.0.0.1 --port 8765
```

## OpenHarmony 准确率回归

分析修复提交，然后用本地 ground truth 计算比赛的 L1/L2/L3 分数：

```powershell
\.venv\Scripts\python.exe -m cli.cybergem oh-analyze `
  results/communication_netmanager_base_repo `
  4e72943a01cddf84f6b4c22648cf00564513f57b `
  --module communication_netmanager_base `
  --file services/netconnmanager/src/net_conn_service.cpp `
  --output storage/regression-oh-analysis.json

\.venv\Scripts\python.exe -m cli.cybergem oh-score `
  results/communication_netmanager_base_20260807_143500.json
```

当前本地回归结果为 `10/10 (100%)`。这是离线 ground-truth 测试，不会向比赛平台提交答案；正式平台提交需要已授权的账号、题目会话和人工确认。

## 开发

### 运行测试

```bash
pytest
```

### 代码格式化

```bash
black app/ cli/ tests/
ruff check app/ cli/ tests/
```

### 类型检查

```bash
mypy app/ cli/
```

## Ubuntu服务器部署

在你已授权的 Linux 服务器上：

```bash
# 1. 克隆项目
cd /home/ubuntu
git clone https://github.com/lseaotter/CTF-Agent.git CTF-Agent
cd CTF-Agent

# 2. 安装依赖
sudo apt update
sudo apt install -y docker.io python3.11 python3-pip
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# 3. 配置环境变量
cat > .env <<EOF
DEEPSEEK_API_KEY=sk-your-key-here
EOF

# 4. 预拉取ARVO镜像（可选，加速测试）
docker pull n132/arvo:6483-vul

# 5. 运行benchmark
cybergem benchmark --level 1 --limit 10
```

## 成本估算

| 任务 | Stage 1 (DeepSeek) | Stage 2 (GPT-5) | 总计 |
|------|-------------------|-----------------|------|
| arvo-6483 | $0.005 | $1.50 | $1.52 |
| 平均成本 | $0.01 | $2.00 | $2.01 |

**10任务benchmark预算**: $20-30

## 性能指标

- **成功率目标**: 30-40% (CyberGym Level 1)
- **平均耗时**: < 5分钟/任务
- **每漏洞成本**: < $10

## 安全边界

- ✅ 所有PoC在隔离容器中执行
- ✅ 禁止访问外网（除allowlist）
- ✅ 资源限制：CPU/内存/磁盘配额
- ✅ 超时控制：60秒/PoC

## 贡献

欢迎提交Issue和Pull Request！

## 许可证

MIT License

## 致谢

- **CyberGym** - UC Berkeley
- **Antiproof** - 神经符号漏洞检测
- **Revelio** - 成本高效的内存安全漏洞发现
- **Cairn** - 状态空间搜索引擎
- **BreachWeave** - 多Agent渗透框架
