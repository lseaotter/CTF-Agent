import json
from pathlib import Path

from app.core.results import ResultStore


def test_result_store_normalizes_chain_artifacts(tmp_path: Path):
    results = tmp_path / "results"
    results.mkdir()
    (results / "sample_chains.json").write_text(
        json.dumps(
            {
                "module": "sample",
                "chains": [
                    {
                        "file": "src/a.cpp",
                        "line": 10,
                        "intro_commit": "abcdef1234567890",
                        "fix_commit": "1234567890abcdef",
                        "cwe": "CWE-362",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    store = ResultStore(tmp_path)
    run = store.get_run("sample_chains")
    assert run["grouped_total"] == 1
    finding = run["findings"][0]
    assert finding["location"] == "src/a.cpp:10"
    assert finding["level2_commit"] == "abcdef1234567890"
    assert finding["commit"] == "1234567890abcdef"
    assert finding["submission"]["L3"] == "CWE-362"


def test_result_store_normalizes_answer_artifacts(tmp_path: Path):
    results = tmp_path / "results"
    results.mkdir()
    (results / "sample_answer.json").write_text(
        json.dumps(
            {
                "module": "sample",
                "answer": {
                    "L1": "src/a.cpp:10",
                    "L2": "abcdef1234567890",
                    "L3": "CWE-476",
                },
            }
        ),
        encoding="utf-8",
    )
    finding = ResultStore(tmp_path).get_run("sample_answer")["findings"][0]
    assert finding["submission"]["L1"] == "src/a.cpp:10"
    assert finding["submission"]["L2"] == "abcdef1234567890"
    assert finding["submission"]["L3"] == "CWE-476"
