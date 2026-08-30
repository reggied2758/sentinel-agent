import sys
from pathlib import Path

from scanner.__main__ import run_security_scan
from agent.prioritizer import prioritize
from agent.ai_analyzer import analyze_finding
from agent.report import generate_report


def run_agent(target):
    target_path = Path(target)

    if not target_path.exists():
        print(f"Error: target does not exist: {target}")
        return []

    if not target_path.is_dir():
        print(f"Error: target is not a directory: {target}")
        return []

    findings = run_security_scan(target)
    findings = prioritize(findings)

    print("\n=== Security Agent ===\n")

    analyses = []

    for finding in findings:
        print(
            f"\n[{finding.severity}] "
            f"{finding.tool} - "
            f"{finding.rule}"
        )

        analysis = analyze_finding(finding)
        analyses.append(analysis)

        print(f"Risk: {analysis['risk']}")
        print(f"Explanation: {analysis['explanation']}")
        print(f"Impact: {analysis['impact']}")
        print(f"Recommendation: {analysis['recommendation']}")

    generate_report(findings, analyses)

    return findings


def main():
    if len(sys.argv) == 2 and sys.argv[1] in ("--help", "-h"):
        print("Sentinel Security Agent")
        print()
        print("Usage:")
        print("  sentinel scan <target>")
        print()
        print("Commands:")
        print("  scan    Scan a project for security vulnerabilities")
        print()
        print("Examples:")
        print("  sentinel scan vulnerable_app/")
        print("  sentinel scan clean_app/")
        return

    if len(sys.argv) != 3 or sys.argv[1] != "scan":
        print("Usage: sentinel scan <target>")
        print("Run 'sentinel --help' for more information.")
        sys.exit(1)

    target = sys.argv[2]
    run_agent(target)


if __name__ == "__main__":
    main()