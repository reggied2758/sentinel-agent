import json
import subprocess  # nosec B404
import sys
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

    pip_audit = Path(sys.executable).parent / "pip-audit"

    if not pip_audit.exists():
        return {
            "dependencies": [],
            "vulnerabilities": [],
            "error": (
                f"pip-audit executable not found: {pip_audit}"
            ),
        }

    result = subprocess.run(  # nosec B603
        [
            str(pip_audit),
            "-r",
            str(requirements),
            "-f",
            "json",
        ],
        capture_output=True,
        text=True,
    )

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()

    if not stdout:
        return {
            "dependencies": [],
            "vulnerabilities": [],
            "error": (
                stderr
                or "pip-audit returned no JSON output."
            ),
        }

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return {
            "dependencies": [],
            "vulnerabilities": [],
            "error": (
                "pip-audit returned invalid JSON."
            ),
        }

    if result.returncode not in (0, 1):
        return {
            "dependencies": data.get(
                "dependencies",
                [],
            ),
            "vulnerabilities": data.get(
                "vulnerabilities",
                [],
            ),
            "error": (
                stderr
                or (
                    "pip-audit exited with "
                    f"code {result.returncode}."
                )
            ),
        }

    return data


def normalize_findings(data, target):
    findings = []

    requirements = (
        Path(target) / "requirements.txt"
    )

    for package in data.get(
        "dependencies",
        [],
    ):
        package_name = package.get(
            "name",
            "unknown",
        )

        package_version = package.get(
            "version",
            "unknown",
        )

        for vulnerability in package.get(
            "vulns",
            [],
        ):
            fix_versions = vulnerability.get(
                "fix_versions",
                [],
            )

            if fix_versions:
                fixes = ", ".join(fix_versions)
            else:
                fixes = "No fixed version specified"

            findings.append(
                SecurityFinding(
                    tool="pip-audit",
                    rule=vulnerability.get(
                        "id",
                        "UNKNOWN",
                    ),
                    severity="HIGH",
                    file=str(requirements),
                    line=1,
                    message=(
                        f"{package_name} "
                        f"{package_version} has a known "
                        f"vulnerability. Fix versions: "
                        f"{fixes}"
                    ),
                    cwe=None,
                )
            )

    return findings


def scan(target):
    data = run_pip_audit(target)

    if data.get("error"):
        print(
            f"pip-audit warning: "
            f"{data['error']}"
        )

    return normalize_findings(
        data,
        target,
    )


if __name__ == "__main__":
    findings = scan(
        "vulnerable_app/"
    )

    for finding in findings:
        print(finding)