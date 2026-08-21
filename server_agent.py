#!/usr/bin/env python3
"""
CyberGem Server Agent - 服务器端挖掘代理
用于在远程服务器上执行计算密集型的漏洞挖掘任务
"""

import json
import argparse
import sys
from pathlib import Path
from datetime import datetime
import subprocess
import time

class ServerAgent:
    """服务器端挖掘代理"""

    def __init__(self, output_dir="./results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    def log(self, message):
        """记录日志"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        try:
            print(f"[{timestamp}] {message}", flush=True)
        except UnicodeEncodeError:
            print(f"[{timestamp}] {message.encode('utf-8', errors='ignore').decode('utf-8')}", flush=True)

    def clone_openharmony(self, module="sensors"):
        """克隆OpenHarmony仓库"""
        self.log(f"克隆OpenHarmony {module} 模块...")

        repo_urls = {
            "sensors": "https://gitee.com/openharmony/sensors_sensor.git",
            "medical_sensor": "https://gitee.com/openharmony/sensors_medical_sensor.git",
            "arkui": "https://gitee.com/openharmony/arkui_ace_engine.git",
            "communication": "https://gitee.com/openharmony/communication_ipc.git"
        }

        repo_url = repo_urls.get(module, repo_urls["sensors"])
        repo_path = self.output_dir / f"{module}_repo"

        if repo_path.exists():
            self.log(f"仓库已存在: {repo_path}")
            return str(repo_path)

        try:
            subprocess.run([
                "git", "clone",
                "--depth", "1000",
                repo_url,
                str(repo_path)
            ], check=True, capture_output=True, text=True, encoding='utf-8', errors='ignore')

            self.log(f"[OK] 克隆完成: {repo_path}")
            return str(repo_path)
        except subprocess.CalledProcessError as e:
            self.log(f"[ERROR] 克隆失败")
            return None

    def analyze_repository(self, repo_path):
        """分析仓库"""
        self.log("分析git历史...")

        vulnerabilities = []

        # 关键词列表
        keywords = [
            "security", "vulnerability", "CVE", "fix", "crash",
            "overflow", "null", "leak", "sanitize", "bound"
        ]

        all_commits = []

        # 搜索包含关键词的提交
        for keyword in keywords:
            try:
                result = subprocess.run([
                    "git", "-C", repo_path, "log",
                    "--all", "--oneline",
                    f"--grep={keyword}",
                    "-i",
                    "--format=%H|%s|%ad|%an",
                    "--date=short"
                ], capture_output=True, text=True, encoding='utf-8', errors='ignore', check=True)

                for line in result.stdout.strip().split('\n'):
                    if '|' in line and line.strip():
                        parts = line.split('|', 3)
                        if len(parts) >= 3:
                            commit_hash, subject, date = parts[0], parts[1], parts[2]
                            if commit_hash not in [c['hash'] for c in all_commits]:
                                all_commits.append({
                                    'hash': commit_hash,
                                    'subject': subject,
                                    'date': date
                                })
            except:
                continue

        self.log(f"找到 {len(all_commits)} 个可疑提交")

        # 分析每个提交
        for i, commit in enumerate(all_commits[:50], 1):  # 分析前50个
            self.log(f"[{i}/{min(50, len(all_commits))}] 分析: {commit['hash'][:8]}")

            vuln = self.analyze_commit(repo_path, commit)
            if vuln:
                vulnerabilities.extend(vuln)

        return vulnerabilities

    def analyze_commit(self, repo_path, commit):
        """分析单个提交"""
        try:
            # 获取修改的文件
            diff_result = subprocess.run([
                "git", "-C", repo_path, "diff-tree",
                "--no-commit-id",
                "--name-status",
                "-r",
                commit['hash']
            ], capture_output=True, text=True, encoding='utf-8', errors='ignore', check=True)

            modified_files = []
            for line in diff_result.stdout.strip().split('\n'):
                if line and '\t' in line:
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        modified_files.append(parts[1])

            # 获取diff详情
            diff_detail = subprocess.run([
                "git", "-C", repo_path, "show",
                commit['hash'],
                "--format=",
                "--unified=5"
            ], capture_output=True, text=True, encoding='utf-8', errors='ignore', check=True)

            # 检测漏洞类型
            vuln_type = self.detect_vulnerability_type(commit['subject'], diff_detail.stdout)
            cwe = self.map_to_cwe(vuln_type)

            # 提取漏洞位置
            locations = self.extract_locations(diff_detail.stdout, modified_files)

            vulnerabilities = []
            for loc in locations:
                vulnerabilities.append({
                    'location': f"{loc['file']}:{loc['line']}",
                    'file': loc['file'],
                    'line': loc['line'],
                    'type': vuln_type,
                    'description': commit['subject'],
                    'commit': commit['hash'],
                    'commit_short': commit['hash'][:8],
                    'cwe': cwe,
                    'date': commit['date'],
                    'fixed_code': loc.get('code', '')
                })

            return vulnerabilities

        except Exception as e:
            return []

    def detect_vulnerability_type(self, subject, diff):
        """检测漏洞类型"""
        text = (subject + " " + diff).lower()

        if any(kw in text for kw in ['buffer overflow', 'overflow', 'memcpy', 'strcpy']):
            return "buffer overflow"
        elif any(kw in text for kw in ['null pointer', 'nullptr', 'null check']):
            return "null pointer dereference"
        elif any(kw in text for kw in ['use after free', 'uaf', 'dangling']):
            return "use after free"
        elif any(kw in text for kw in ['integer overflow', 'int overflow']):
            return "integer overflow"
        elif any(kw in text for kw in ['memory leak', 'leak']):
            return "memory leak"
        elif any(kw in text for kw in ['permission', 'authorization', 'privilege']):
            return "permission bypass"
        elif any(kw in text for kw in ['race condition', 'thread', 'lock']):
            return "race condition"
        else:
            return "security fix"

    def map_to_cwe(self, vuln_type):
        """映射到CWE"""
        mapping = {
            "buffer overflow": "CWE-120",
            "null pointer dereference": "CWE-476",
            "use after free": "CWE-416",
            "integer overflow": "CWE-190",
            "memory leak": "CWE-401",
            "permission bypass": "CWE-862",
            "race condition": "CWE-362",
            "security fix": "CWE-Unknown"
        }
        return mapping.get(vuln_type, "CWE-Unknown")

    def extract_locations(self, diff, files):
        """提取漏洞位置"""
        locations = []
        current_file = None
        current_line = 0

        for line in diff.split('\n'):
            if line.startswith('+++ b/'):
                current_file = line[6:]
            elif line.startswith('@@ '):
                import re
                match = re.search(r'\+(\d+)', line)
                if match:
                    current_line = int(match.group(1))
            elif line.startswith('+') and not line.startswith('+++'):
                if current_file and any(kw in line.lower() for kw in
                    ['check', 'null', 'validate', 'sanitize', 'if', 'return']):
                    locations.append({
                        'file': current_file,
                        'line': current_line,
                        'code': line[1:].strip()
                    })
                current_line += 1
            elif not line.startswith('-'):
                current_line += 1

        return locations[:10]  # 最多返回10个位置

    def save_results(self, vulnerabilities, module):
        """保存结果"""
        output_file = self.output_dir / f"{module}_{self.session_id}.json"

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({
                'session_id': self.session_id,
                'module': module,
                'timestamp': datetime.now().isoformat(),
                'total': len(vulnerabilities),
                'vulnerabilities': vulnerabilities
            }, f, indent=2, ensure_ascii=False)

        self.log(f"[OK] 结果已保存: {output_file}")
        return str(output_file)

    def generate_ctf_submissions(self, vulnerabilities):
        """生成CTF提交格式"""
        submissions = []

        for vuln in vulnerabilities:
            submissions.append({
                'level1': vuln['location'],
                'level2': vuln['commit'],
                'level3': vuln['cwe'],
                'description': f"{vuln['type']} - {vuln['description']}"
            })

        return submissions

    def run(self, module="sensors"):
        """执行完整流程"""
        self.log("="*60)
        self.log("CyberGem Server Agent - 启动")
        self.log("="*60)

        start_time = time.time()

        # 1. 克隆仓库
        repo_path = self.clone_openharmony(module)
        if not repo_path:
            self.log("✗ 无法克隆仓库")
            return None

        # 2. 分析仓库
        vulnerabilities = self.analyze_repository(repo_path)

        # 3. 保存结果
        result_file = self.save_results(vulnerabilities, module)

        # 4. 生成CTF提交格式
        submissions = self.generate_ctf_submissions(vulnerabilities)

        elapsed = time.time() - start_time

        self.log("="*60)
        self.log(f"[OK] 完成！耗时: {elapsed:.1f}秒")
        self.log(f"[OK] 发现漏洞: {len(vulnerabilities)} 个")
        self.log(f"[OK] 结果文件: {result_file}")
        self.log("="*60)

        # 显示前5个答案
        self.log("\n前5个CTF答案:")
        for i, sub in enumerate(submissions[:5], 1):
            self.log(f"\n答案 {i}:")
            self.log(f"  Level 1: {sub['level1']}")
            self.log(f"  Level 2: {sub['level2']}")
            self.log(f"  Level 3: {sub['level3']}")

        return result_file


def main():
    parser = argparse.ArgumentParser(description='CyberGem Server Agent')
    parser.add_argument('--module', default='sensors',
                       choices=['sensors', 'medical_sensor', 'arkui', 'communication'],
                       help='目标模块')
    parser.add_argument('--output', default='./results', help='输出目录')

    args = parser.parse_args()

    agent = ServerAgent(output_dir=args.output)
    agent.run(module=args.module)


if __name__ == "__main__":
    main()
