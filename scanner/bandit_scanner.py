import json
import subprocess

from scanner.finding import SecurityFinding


def run_bandit(target, exclude_paths=None):
    exclude_paths = exclude_paths or []

    command = [
        "bandit",
        "-r",
        target,
    ]

    if exclude_paths:
        command.extend(
            [
                "--exclude",
                ",".join(exclude_paths),
            ]
        )

    command.extend(["-f", "json"])

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    if not result.stdout.strip():
        return {
            "results": [],
            "errors": [
                result.stderr.strip()
                or "Bandit returned no JSON output."
            ],
        }

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "results": [],
            "errors": [
                "Bandit returned invalid JSON.",
                result.stderr.strip(),
            ],
        }


def normalize_findings(data):
    findings = []

    for result in data.get("results", []):
        issue_cwe = result.get("issue_cwe") or {}

        finding = SecurityFinding(
            tool="bandit",
            rule=result.get("test_id", "UNKNOWN"),
            severity=result.get("issue_severity", "LOW"),
            file=result.get("filename", "unknown"),
            line=result.get("line_number", 0),
            message=result.get("issue_text", ""),
            cwe=issue_cwe.get("id"),
            code=result.get("code"),
        )

        findings.append(finding)

    return findings


if __name__ == "__main__":
    data = run_bandit("vulnerable_app/")
    findings = normalize_findings(data)

    for finding in findings:
        print(finding)