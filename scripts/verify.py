"""Execute local release checks and preserve exact commands, outputs and exits."""
import json
from pathlib import Path
import platform
import subprocess
import sys
from ledger import ROOT, canonical, now
from storage import safe_path


def main():
    reports = safe_path(ROOT, "reports")
    reports.mkdir(exist_ok=True)
    commands = [
        [sys.executable, "-B", "-W", "error::ResourceWarning", "-m", "unittest", "discover", "-s", "tests", "-v"],
        [sys.executable, "-B", "scripts/shadow.py", "init"],
        [sys.executable, "-B", "scripts/shadow.py", "validate"],
        [sys.executable, "-B", "scripts/shadow.py", "summary"],
        [sys.executable, "-B", "scripts/shadow.py", "status"],
        ["git", "diff", "--check"],
        ["git", "diff", "--cached", "--check"],
    ]
    results = []
    for command in commands:
        completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=180)
        results.append({"argv": command, "exit_code": completed.returncode,
                        "stdout": completed.stdout, "stderr": completed.stderr})
        print(json.dumps({"argv":command, "exit_code":completed.returncode}), flush=True)
    git = {}
    for name, args in {"base_head":["rev-parse","HEAD"], "branch":["branch","--show-current"],
                       "changed_files":["diff","--cached","--name-only"],
                       "status":["status","--short"]}.items():
        result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=10)
        git[name] = result.stdout.strip()
    receipt = {"generated_at":now(), "root":str(ROOT), "python":sys.version, "platform":platform.platform(),
               "git":git, "checks":results, "passed":all(r["exit_code"] == 0 for r in results),
               "limits":["Live GitHub CI not run; remote publication pending approval.",
                         "Other OS/Python versions and long-duration operation not tested here.",
                         "Model correctness and outcome truth are not certified."]}
    safe_path(ROOT, "reports/build-verification.json").write_bytes(canonical(receipt) + b"\n")
    text = "# Local build verification\n\nGenerated: " + receipt["generated_at"] + "\n\n"
    text += "Root: " + str(ROOT) + "\n\nBase Git head: " + git["base_head"] + "\n\nBranch: " + git["branch"] + "\n\n"
    text += "| Exact command | Exit |\n|---|---|\n"
    for result in results:
        text += "| `" + subprocess.list2cmdline(result["argv"]) + "` | " + str(result["exit_code"]) + " |\n"
    text += "\nFull outputs and runtime details: `build-verification.json`.\n\n"
    text += "## Staged source files\n\n" + "".join("- `" + path + "`\n" for path in git["changed_files"].splitlines())
    text += "\n## Limits\n\n" + "".join("- " + limit + "\n" for limit in receipt["limits"])
    safe_path(ROOT, "reports/build-verification.md").write_text(text, encoding="utf-8", newline="\n")
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
