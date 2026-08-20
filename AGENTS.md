# CyberGem Agent Notes

## Active entry points

- Use `\.venv\Scripts\python.exe` for every Python command on Windows.
- Local research console: `\.venv\Scripts\python.exe web_interface.py --port 8765`.
- OpenHarmony patch analysis: `\.venv\Scripts\python.exe -m cli.cybergem oh-analyze ...`.
- Local scoring only: `\.venv\Scripts\python.exe -m cli.cybergem oh-score ...`.
- The OpenHarmony console and scoring commands never submit to the contest service.

## Accuracy workflow

1. Analyze a security repair commit, not the earlier commit that introduced the bug.
2. Keep the high-recall candidate list and inspect Git blame evidence.
3. Use `--file` when the task identifies a source file; otherwise rank all candidates and review the evidence.
4. Score against a checked-in ground truth with the 5/4/1 L1/L2/L3 weights.
5. Record negative results and do not treat a historical N-day repair as a new 0-day.

The analyzer's `trackId` is a deterministic local candidate key. It is not a
platform-issued contest track token; obtain the real token from an authorized
contest session before any submission.

The current regression fixture is `communication_netmanager_base`. Its local result is
`results/communication_netmanager_base_20260807_143500.json` and its score is 10/10.

## Verification

```powershell
& .\.venv\Scripts\python.exe -m pytest -q
& .\.venv\Scripts\python.exe -m cli.cybergem oh-score results/communication_netmanager_base_20260807_143500.json
```

Do not print, commit, or copy `.env`. API status endpoints expose configuration state,
never credentials. Keep `results/*_repo` Git repositories intact because they provide
the source and blame evidence used by the scorer.

## Repository layout

The maintained implementation is in `app/`, `cli/`, `web/`, `configs/`, `tests/`,
`results/`, `server_agent.py`, and `web_interface.py`. Historical experiments and
old GUI bundles live under `archive/legacy/`.
