import sys
from pathlib import Path

from scanner.__main__ import run_security_scan
from agent.prioritizer import prioritize
from agent.ai_analyzer import analyze_finding
from agent.report import generate_report


VALID_FORMATS = {"json", "markdown", "html", "all"}
BLOCKING_SEVERITIES = {"HIGH", "CRITICAL"}


def run_agent(
    target,
    use_ai=True,
    output_format="all",
    exclude_paths=None,
):
    target_path = Path(target)

    if not target_path.exists():
        print(f"Error: target does not exist: {target}")
        return []

    if not target_path.is_dir():
        print(f"Error: target is not a directory: {target}")
        return []

    findings = run_security_scan(
        target,
        exclude_paths=exclude_paths,
    )
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


def get_exit_code(findings):
    """
    Return a non-zero exit code when HIGH or CRITICAL
    security findings are present.
    """
    for finding in findings:
        if finding.severity in BLOCKING_SEVERITIES:
            return 1

    return 0


def print_help():
    print("Sentinel Security Agent")
    print()
    print("Usage:")
    print("  sentinel scan <target>")
    print("  sentinel scan <target> --no-ai")
    print("  sentinel scan <target> --format <format>")
    print("  sentinel scan <target> --exclude <path>")
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
    print(
        "  --exclude <path>    Exclude a path from scanning"
    )
    print()
    print("Security gate:")
    print(
        "  HIGH and CRITICAL findings cause a non-zero exit."
    )
    print()
    print("Examples:")
    print("  sentinel scan vulnerable_app/")
    print("  sentinel scan vulnerable_app/ --no-ai")
    print(
        "  sentinel scan . --no-ai "
        "--format json --exclude vulnerable_app"
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
    exclude_paths = []

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

        elif argument == "--exclude":
            if index + 1 >= len(args):
                print("Error: --exclude requires a path.")
                sys.exit(1)

            exclude_paths.append(args[index + 1])
            index += 2

        else:
            print(f"Unknown option: {argument}")
            print(
                "Run 'sentinel --help' "
                "for more information."
            )
            sys.exit(1)

    findings = run_agent(
        target,
        use_ai=use_ai,
        output_format=output_format,
        exclude_paths=exclude_paths,
    )

    sys.exit(get_exit_code(findings))


if __name__ == "__main__":
    main()