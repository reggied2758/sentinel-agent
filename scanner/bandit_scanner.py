import json
import subprocess  # nosec B404
from pathlib import Path

from scanner.finding import SecurityFinding


DEFAULT_EXCLUDES = {
    ".venv",
    ".git",
    "__pycache__",
    ".pytest_cache",
}


def build_exclude_paths(target, exclude_paths=None):
    """
    Build absolute exclusion paths for Bandit.
    """

    target_path = Path(target).resolve()

    paths = set(DEFAULT_EXCLUDES)

    for path in exclude_paths or []:
        paths.add(path)

    resolved = []

    for path in paths:
        path_obj = Path(path)

        if path_obj.is_absolute():
            resolved.append(str(path_obj))
        else:
            resolved.append(
                str(
                    (target_path / path_obj).resolve()
                )
            )

    return resolved


def run_bandit(target, exclude_paths=None):
    exclude_paths = build_exclude_paths(
        target,
        exclude_paths,
    )

    target_path = str(
        Path(target).resolve()
    )

    command = [
        "bandit",
        "-r",
        target_path,
        "--exclude",
        ",".join(exclude_paths),
        "-f",
        "json",
    ]

    result = subprocess.run(  # nosec B603
        command,
        capture_output=True,
        text=True,
    )

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()

    if not stdout:
        return {
            "results": [],
            "errors": [
                stderr
                or "Bandit returned no JSON output."
            ],
        }

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return {
            "results": [],
            "errors": [
                "Bandit returned invalid JSON.",
                stderr,
            ],
        }

    # Bandit returns exit code 1 when findings are present.
    # That is a successful scan, not a scanner failure.
    if result.returncode not in (0, 1):
        return {
            "results": data.get(
                "results",
                [],
            ),
            "errors": [
                stderr
                or (
                    "Bandit exited with "
                    f"code {result.returncode}."
                )
            ],
        }

    return data


def normalize_findings(data):
    findings = []

    for result in data.get(
        "results",
        [],
    ):
        issue_cwe = (
            result.get("issue_cwe")
            or {}
        )

        findings.append(
            SecurityFinding(
                tool="bandit",
                rule=result.get(
                    "test_id",
                    "UNKNOWN",
                ),
                severity=result.get(
                    "issue_severity",
                    "LOW",
                ),
                file=result.get(
                    "filename",
                    "unknown",
                ),
                line=result.get(
                    "line_number",
                    0,
                ),
                message=result.get(
                    "issue_text",
                    "",
                ),
                cwe=issue_cwe.get("id"),
                code=result.get("code"),
            )
        )

    return findings


if __name__ == "__main__":
    data = run_bandit(
        "vulnerable_app/"
    )

    if data.get("errors"):
        print("Bandit errors:")

        for error in data["errors"]:
            print(f"- {error}")

    findings = normalize_findings(data)

    for finding in findings:
        print(finding)