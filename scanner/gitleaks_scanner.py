import subprocess
import json
import tempfile
import os

from scanner.finding import SecurityFinding


def run_gitleaks(target):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as report:
        report_path = report.name

    try:
        subprocess.run(
            [
                "gitleaks",
                "detect",
                "--source",
                target,
                "--no-git",
                "--report-format",
                "json",
                "--report-path",
                report_path
            ],
            capture_output=True,
            text=True
        )

        if not os.path.exists(report_path):
            return []

        with open(report_path, "r") as file:
            content = file.read()

        if not content.strip():
            return []

        return json.loads(content)

    finally:
        if os.path.exists(report_path):
            os.remove(report_path)


def normalize_findings(data):
    findings = []

    for result in data:
        finding = SecurityFinding(
            tool="gitleaks",
            rule=result["RuleID"],
            severity="HIGH",
            file=result["File"],
            line=result["StartLine"],
            message=result["Description"]
        )

        findings.append(finding)

    return findings


if __name__ == "__main__":
    data = run_gitleaks("vulnerable_app/")
    findings = normalize_findings(data)

    for finding in findings:
        print(finding)