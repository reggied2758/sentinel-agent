import json
import os
import subprocess  # nosec B404
import tempfile

from scanner.finding import SecurityFinding


def run_gitleaks(target, exclude_paths=None):
    exclude_paths = exclude_paths or []

    with tempfile.NamedTemporaryFile(
        suffix=".json",
        delete=False,
    ) as report:
        report_path = report.name

    try:
        command = [
            "gitleaks",
            "detect",
            "--source",
            target,
            "--no-git",
            "--report-format",
            "json",
            "--report-path",
            report_path,
        ]

        result = subprocess.run(  # nosec B603
            command,
            capture_output=True,
            text=True,
        )

        if not os.path.exists(report_path):
            return {
                "results": [],
                "error": (
                    result.stderr.strip()
                    or "Gitleaks did not produce a report."
                ),
            }

        with open(report_path, "r") as file:
            content = file.read()

        if not content.strip():
            if result.returncode not in (0, 1):
                return {
                    "results": [],
                    "error": (
                        result.stderr.strip()
                        or (
                            "Gitleaks exited with "
                            f"code {result.returncode}."
                        )
                    ),
                }

            return {
                "results": [],
                "error": None,
            }

        try:
            results = json.loads(content)
        except json.JSONDecodeError:
            return {
                "results": [],
                "error": "Gitleaks returned invalid JSON.",
            }

        if result.returncode not in (0, 1):
            return {
                "results": results,
                "error": (
                    result.stderr.strip()
                    or (
                        "Gitleaks exited with "
                        f"code {result.returncode}."
                    )
                ),
            }

        return {
            "results": results,
            "error": None,
        }

    except OSError as exc:
        return {
            "results": [],
            "error": str(exc),
        }

    finally:
        if os.path.exists(report_path):
            os.remove(report_path)


def normalize_findings(data):
    findings = []

    for result in data.get("results", []):
        findings.append(
            SecurityFinding(
                tool="gitleaks",
                rule=result.get(
                    "RuleID",
                    "UNKNOWN",
                ),
                severity="HIGH",
                file=result.get(
                    "File",
                    "unknown",
                ),
                line=result.get(
                    "StartLine",
                    0,
                ),
                message=result.get(
                    "Description",
                    "",
                ),
            )
        )

    return findings


if __name__ == "__main__":
    data = run_gitleaks(
        "vulnerable_app/"
    )

    if data.get("error"):
        print(
            f"Gitleaks error: "
            f"{data['error']}"
        )

    findings = normalize_findings(data)

    for finding in findings:
        print(finding)