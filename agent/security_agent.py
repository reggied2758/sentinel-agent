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
    if len(sys.argv) != 2:
        print("Usage: sentinel <target>")
        sys.exit(1)

    target = sys.argv[1]
    run_agent(target)


if __name__ == "__main__":
    main()