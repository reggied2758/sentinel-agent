import sys
from pathlib import Path

from scanner.__main__ import run_security_scan
from agent.prioritizer import prioritize
from agent.ai_analyzer import analyze_finding
from agent.report import generate_report


VALID_FORMATS = {"json", "markdown", "html", "all"}


def run_agent(target, use_ai=True, output_format="all"):
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

        if use_ai:
            analysis = analyze_finding(finding)
        else:
            analysis = {
                "risk": finding.rule,
                "explanation": "AI analysis disabled.",
                "impact": (
                    "See the scanner finding "
                    "for technical details."
                ),
                "recommendation": (
                    "Review and remediate the "
                    "finding manually."
                ),
            }

        analyses.append(analysis)

        print(f"Risk: {analysis['risk']}")
        print(f"Explanation: {analysis['explanation']}")
        print(f"Impact: {analysis['impact']}")
        print(
            f"Recommendation: "
            f"{analysis['recommendation']}"
        )

    generate_report(
        findings,
        analyses,
        output_format=output_format,
    )

    return findings


def print_help():
    print("Sentinel Security Agent")
    print()
    print("Usage:")
    print("  sentinel scan <target>")
    print("  sentinel scan <target> --no-ai")
    print("  sentinel scan <target> --format <format>")
    print()
    print("Commands:")
    print(
        "  scan    Scan a project for security vulnerabilities"
    )
    print()
    print("Options:")
    print(
        "  --no-ai             Run scanners without AI analysis"
    )
    print(
        "  --format <format>   Output format: "
        "json, markdown, html, all"
    )
    print()
    print("Examples:")
    print("  sentinel scan vulnerable_app/")
    print("  sentinel scan vulnerable_app/ --no-ai")
    print(
        "  sentinel scan vulnerable_app/ "
        "--format html"
    )
    print(
        "  sentinel scan vulnerable_app/ "
        "--format json"
    )


def main():
    if len(sys.argv) == 2 and sys.argv[1] in (
        "--help",
        "-h",
    ):
        print_help()
        return

    if len(sys.argv) < 3 or sys.argv[1] != "scan":
        print("Usage: sentinel scan <target> [options]")
        print(
            "Run 'sentinel --help' "
            "for more information."
        )
        sys.exit(1)

    target = sys.argv[2]
    use_ai = True
    output_format = "all"

    args = sys.argv[3:]
    index = 0

    while index < len(args):
        argument = args[index]

        if argument == "--no-ai":
            use_ai = False
            index += 1

        elif argument == "--format":
            if index + 1 >= len(args):
                print("Error: --format requires a value.")
                sys.exit(1)

            output_format = args[index + 1]

            if output_format not in VALID_FORMATS:
                print(
                    f"Error: unsupported format: "
                    f"{output_format}"
                )
                print(
                    "Valid formats: "
                    "json, markdown, html, all"
                )
                sys.exit(1)

            index += 2

        else:
            print(f"Unknown option: {argument}")
            print(
                "Run 'sentinel --help' "
                "for more information."
            )
            sys.exit(1)

    run_agent(
        target,
        use_ai=use_ai,
        output_format=output_format,
    )


if __name__ == "__main__":
    main()