import subprocess
import json

from scanner.finding import SecurityFinding


def run_bandit(target):
    result = subprocess.run(
        ["bandit", "-r", target, "-f", "json"],
        capture_output=True,
        text=True
    )

    return json.loads(result.stdout)


def normalize_findings(data):
    findings = []

    for result in data["results"]:
        finding = SecurityFinding(
            tool="bandit",
            rule=result["test_id"],
            severity=result["issue_severity"],
            file=result["filename"],
            line=result["line_number"],
            message=result["issue_text"],
            cwe=result["issue_cwe"]["id"]
        )

        findings.append(finding)

    return findings


if __name__ == "__main__":
    data = run_bandit("vulnerable_app/")
    findings = normalize_findings(data)

    for finding in findings:
        print(finding)