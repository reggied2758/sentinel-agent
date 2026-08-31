import sys
from pathlib import Path

from scanner.__main__ import run_security_scan
from agent.prioritizer import prioritize
from agent.ai_analyzer import analyze_finding
from agent.report import generate_report


VALID_FORMATS = {
    "json",
    "markdown",
    "html",
    "all",
}

BLOCKING_SEVERITIES = {
    "HIGH",
    "CRITICAL",
}


def run_agent(
    target,
    use_ai=True,
    output_format="all",
    exclude_paths=None,
):
    target_path = Path(target)

    if not target_path.exists():
        print(
            f"Error: target does not exist: {target}"
        )
        return []

    if not target_path.is_dir():
        print(
            f"Error: target is not a directory: {target}"
        )
        return []

    scan_result = run_security_scan(
        target,
        exclude_paths=exclude_paths,
    )

    findings = prioritize(
        scan_result["findings"]
    )

    scanner_errors = scan_result["errors"]

    print(
        "\n=== Security Agent ===\n"
    )

    if scanner_errors:
        print(
            "=== Scanner Errors ===\n"
        )

        for error in scanner_errors:
            print(
                f"[ERROR] "
                f"{error['tool']}: "
                f"{error['message']}"
            )

        print()

    analyses = []

    for finding in findings:
        print(
            f"\n[{finding.severity}] "
            f"{finding.tool} - "
            f"{finding.rule}"
        )

        print(
            f"File: {finding.file}"
        )

        print(
            f"Line: {finding.line}"
        )

        print(
            f"Message: {finding.message}"
        )

        if finding.cwe is not None:
            print(
                f"CWE: {finding.cwe}"
            )

        if use_ai:
            analysis = analyze_finding(
                finding
            )
        else:
            analysis = {
                "risk": finding.severity,
                "explanation": finding.message,
                "impact": (
                    f"{finding.tool} reported "
                    f"rule {finding.rule} at "
                    f"{finding.file}:"
                    f"{finding.line}."
                ),
                "recommendation": (
                    "Review the finding and "
                    "remediate the underlying "
                    "security issue."
                ),
            }

        analyses.append(analysis)

        print(
            f"Risk: {analysis['risk']}"
        )

        print(
            f"Explanation: "
            f"{analysis['explanation']}"
        )

        print(
            f"Impact: "
            f"{analysis['impact']}"
        )

        print(
            "Recommendation: "
            f"{analysis['recommendation']}"
        )

    generate_report(
        findings,
        analyses,
        output_format=output_format,
    )

    # Preserve the existing run_agent() API:
    # callers receive the findings list.
    #
    # Scanner errors are attached separately so
    # main() can determine the correct CI exit code.
    run_agent.last_errors = scanner_errors

    return findings


run_agent.last_errors = []


def get_exit_code(findings):
    """
    Return a non-zero exit code when HIGH
    or CRITICAL security findings are present.
    """

    for finding in findings:
        if (
            finding.severity
            in BLOCKING_SEVERITIES
        ):
            return 1

    return 0


def print_help():
    print(
        "Sentinel Security Agent"
    )

    print()

    print("Usage:")

    print(
        "  sentinel scan <target>"
    )

    print(
        "  sentinel scan <target> --no-ai"
    )

    print(
        "  sentinel scan <target> "
        "--format <format>"
    )

    print(
        "  sentinel scan <target> "
        "--exclude <path>"
    )

    print()

    print("Commands:")

    print(
        "  scan    Scan a project for "
        "security vulnerabilities"
    )

    print()

    print("Options:")

    print(
        "  --no-ai             Run scanners "
        "without AI analysis"
    )

    print(
        "  --format <format>   Output format: "
        "json, markdown, html, all"
    )

    print(
        "  --exclude <path>    Exclude a path "
        "from scanning"
    )

    print()

    print("Security gate:")

    print(
        "  HIGH and CRITICAL findings cause "
        "a non-zero exit."
    )

    print(
        "  Scanner errors also cause a "
        "non-zero exit."
    )

    print()

    print("Examples:")

    print(
        "  sentinel scan vulnerable_app/"
    )

    print(
        "  sentinel scan vulnerable_app/ "
        "--no-ai"
    )

    print(
        "  sentinel scan . --no-ai "
        "--format json "
        "--exclude vulnerable_app"
    )


def main():
    if len(sys.argv) == 2 and sys.argv[1] in (
        "--help",
        "-h",
    ):
        print_help()
        return

    if (
        len(sys.argv) < 3
        or sys.argv[1] != "scan"
    ):
        print(
            "Usage: sentinel scan "
            "<target> [options]"
        )

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
                print(
                    "Error: --format "
                    "requires a value."
                )
                sys.exit(1)

            output_format = (
                args[index + 1]
            )

            if (
                output_format
                not in VALID_FORMATS
            ):
                print(
                    "Error: unsupported "
                    f"format: "
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
                print(
                    "Error: --exclude "
                    "requires a path."
                )
                sys.exit(1)

            exclude_paths.append(
                args[index + 1]
            )

            index += 2

        else:
            print(
                f"Unknown option: "
                f"{argument}"
            )

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

    # Scanner errors are failures because a clean
    # security result cannot be trusted if a scanner
    # failed to run.
    if run_agent.last_errors:
        sys.exit(1)

    sys.exit(
        get_exit_code(findings)
    )


if __name__ == "__main__":
    main()