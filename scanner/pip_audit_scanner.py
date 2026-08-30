import json
import subprocess
from pathlib import Path

from scanner.finding import SecurityFinding


def run_pip_audit(target):
    requirements = Path(target) / "requirements.txt"

    if not requirements.exists():
        return {
            "dependencies": [],
            "vulnerabilities": [],
            "error": None,
        }

    result = subprocess.run(
        [
            "pip-audit",
            "-r",
            str(requirements),
            "-f",
            "json",
        ],
        capture_output=True,
        text=True,
    )

    if not result.stdout.strip():
        return {
            "dependencies": [],
            "vulnerabilities": [],
            "error": result.stderr.strip(),
        }

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "dependencies": [],
            "vulnerabilities": [],
            "error": "pip-audit returned invalid JSON.",
        }


def normalize_findings(data, target):
    findings = []

    requirements = Path(target) / "requirements.txt"

    for package in data.get("dependencies", []):
        package_name = package.get("name", "unknown")
        package_version = package.get("version", "unknown")

        for vulnerability in package.get("vulns", []):
            fix_versions = vulnerability.get("fix_versions", [])

            if fix_versions:
                fixes = ", ".join(fix_versions)
            else:
                fixes = "No fixed version specified"

            findings.append(
                SecurityFinding(
                    tool="pip-audit",
                    rule=vulnerability.get("id", "UNKNOWN"),
                    severity="HIGH",
                    file=str(requirements),
                    line=1,
                    message=(
                        f"{package_name} {package_version} has a known "
                        f"vulnerability. Fix versions: {fixes}"
                    ),
                    cwe=None,
                )
            )

    return findings


def scan(target):
    data = run_pip_audit(target)

    if data.get("error"):
        print(f"pip-audit warning: {data['error']}")

    return normalize_findings(data, target)


if __name__ == "__main__":
    findings = scan("vulnerable_app/")

    for finding in findings:
        print(finding)