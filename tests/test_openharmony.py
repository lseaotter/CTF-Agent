import json
import subprocess
from pathlib import Path

import pytest

from app.core.openharmony import OpenHarmonyPatchAnalyzer, load_ground_truth, score_submission


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def test_openharmony_analyzer_recovers_patch_chain(tmp_path: Path):
    repo = tmp_path / "sample_repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "CyberGem Test")
    source = repo / "src" / "service.cpp"
    source.parent.mkdir()
    source.write_text(
        "int service() {\n"
        "    std::lock_guard<std::mutex> lock(mu);\n"
        "    return network_->GetNetLinkInfo().mtu_;\n"
        "}\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "introduce race")
    intro = _git(repo, "rev-parse", "HEAD")
    source.write_text(
        "int service() {\n"
        "    return handler_->PostSyncTask([this] { return network_->GetNetLinkInfo().mtu_; });\n"
        "}\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "fix race")
    repair = _git(repo, "rev-parse", "HEAD")

    result = OpenHarmonyPatchAnalyzer().analyze(repo, repair, module="sample")
    assert result["primary"] is not None
    primary = result["primary"]
    assert primary["location"] == "src/service.cpp:3"
    assert primary["intro_commit"] == intro
    assert primary["cwe"] == "CWE-362"

    scored = score_submission(
        result,
        {"L1": primary["location"], "L2": intro, "L3": "CWE-362"},
    )
    assert scored["score"] == 10


def test_openharmony_scoring_accepts_short_commit():
    result = score_submission(
        {"submission": {"L1": "src/a.cpp:10", "L2": "abcdef123456", "L3": "CWE-476"}},
        {"L1": "src/a.cpp:10", "L2": "abcdef1", "L3": "CWE-476"},
    )
    assert result["score"] == 10


def test_communication_regression_scores_full_chain_when_fixture_is_present():
    repo = Path("results/communication_netmanager_base_repo")
    truth_path = Path("results/communication_netmanager_base_CORRECT_ANSWER.md")
    if not repo.is_dir() or not truth_path.is_file():
        pytest.skip("local OpenHarmony regression fixture is not present")

    result = OpenHarmonyPatchAnalyzer().analyze(
        repo,
        "4e72943a01cddf84f6b4c22648cf00564513f57b",
        module="communication_netmanager_base",
    )
    scored = score_submission(result, load_ground_truth(truth_path))
    assert scored["score"] == 10
    assert result["primary"]["location"] == "services/netconnmanager/src/net_conn_service.cpp:1501"
