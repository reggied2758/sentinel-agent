import sys
from pathlib import Path

from scanner.__main__ import run_security_scan
from agent.prioritizer import prioritize
from agent.ai_analyzer import analyze_finding
from agent.remediation import generate_remediation
from agent.patch_validator import validate_patch
from agent.patch_applier import apply_patch
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
    remediations = []

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

        if (
            use_ai
            and finding.severity
            in BLOCKING_SEVERITIES
        ):
            remediation = generate_remediation(
                finding
            )
        else:
            remediation = {
                "summary": "",
                "explanation": "",
                "fixed_code": "",
                "patch": "",
                "changes": [],
                "testing": "",
            }

        if remediation.get("patch"):
            validation = validate_patch(
                remediation["patch"],
                target,
            )

            remediation["patch_validation"] = (
                validation
            )
        else:
            remediation["patch_validation"] = {
                "valid": False,
                "errors": [
                    "No patch was generated."
                ],
            }

        remediations.append(
            remediation
        )

        if remediation["summary"]:
            print(
                "\nRemediation:"
            )

            print(
                f"Summary: "
                f"{remediation['summary']}"
            )

            print(
                f"Explanation: "
                f"{remediation['explanation']}"
            )

            if remediation["fixed_code"]:
                print(
                    "Proposed Code:"
                )
                print(
                    remediation["fixed_code"]
                )

            if remediation.get("patch"):
                print(
                    "Proposed Patch:"
                )
                print(
                    remediation["patch"]
                )

            if remediation["changes"]:
                print(
                    "Changes:"
                )

                for change in remediation[
                    "changes"
                ]:
                    print(
                        f"- {change}"
                    )

            print(
                f"Testing: "
                f"{remediation['testing']}"
            )

            validation = remediation[
                "patch_validation"
            ]

            print(
                "\nPatch Validation:"
            )

            if validation["valid"]:
                print(
                    "Status: VALID"
                )
            else:
                print(
                    "Status: INVALID"
                )

                for error in validation[
                    "errors"
                ]:
                    print(
                        f"- {error}"
                    )

    generate_report(
        findings,
        analyses,
        remediations=remediations,
        output_format=output_format,
    )

    run_agent.last_errors = scanner_errors

    return findings


run_agent.last_errors = []


def get_exit_code(findings):
    """
    Return a non-zero exit code when HIGH
    or CRITICAL findings are present.
    """

    for finding in findings:
        if finding.severity in BLOCKING_SEVERITIES:
            return 1

    return 0


def remediate_agent(
    target,
    output_format="all",
    exclude_paths=None,
):
    """
    Generate validated remediation patches
    and optionally apply them after explicit
    user confirmation.
    """

    target_path = Path(target)

    if not target_path.exists():
        print(
            f"Error: target does not exist: {target}"
        )
        return 1

    if not target_path.is_dir():
        print(
            f"Error: target is not a directory: {target}"
        )
        return 1

    scan_result = run_security_scan(
        target,
        exclude_paths=exclude_paths,
    )

    findings = prioritize(
        scan_result["findings"]
    )

    scanner_errors = scan_result["errors"]

    if scanner_errors:
        print(
            "\n=== Scanner Errors ===\n"
        )

        for error in scanner_errors:
            print(
                f"[ERROR] "
                f"{error['tool']}: "
                f"{error['message']}"
            )

        return 1

    blocking_findings = [
        finding
        for finding in findings
        if finding.severity in BLOCKING_SEVERITIES
    ]

    if not blocking_findings:
        print(
            "\nNo HIGH or CRITICAL findings "
            "require remediation."
        )
        return 0

    print(
        "\n=== Sentinel Remediation ===\n"
    )

    proposed_patches = []

    for finding in blocking_findings:
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

        remediation = generate_remediation(
            finding
        )

        patch = remediation.get(
            "patch",
            "",
        )

        if not patch:
            print(
                "\nNo patch was generated."
            )
            continue

        validation = validate_patch(
            patch,
            target,
        )

        if not validation["valid"]:
            print(
                "\nPatch Validation: INVALID"
            )

            for error in validation[
                "errors"
            ]:
                print(
                    f"- {error}"
                )

            continue

        print(
            "\nPatch Validation: VALID"
        )

        print(
            "\nProposed Patch:"
        )

        print(
            patch
        )

        proposed_patches.append(
            {
                "finding": finding,
                "remediation": remediation,
            }
        )

    if not proposed_patches:
        print(
            "\nNo valid remediation patches "
            "are available."
        )
        return 1

    print(
        "\n=== Review Required ==="
    )

    print(
        "\nSentinel has generated "
        f"{len(proposed_patches)} "
        "validated patch(es)."
    )

    print(
        "No files have been modified."
    )

    try:
        answer = input(
            "\nApply these patches? "
            "[y/N]: "
        )
    except EOFError:
        answer = ""

    if answer.strip().lower() not in {
        "y",
        "yes",
    }:
        print(
            "\nRemediation cancelled."
        )
        return 0

    print(
        "\n=== Applying Patches ==="
    )

    applied_count = 0

    for proposal in proposed_patches:
        finding = proposal["finding"]
        remediation = proposal[
            "remediation"
        ]

        print(
            f"\nApplying patch for "
            f"{finding.tool} "
            f"{finding.rule}..."
        )

        result = apply_patch(
            remediation["patch"],
            target,
        )

        if result["applied"]:
            print(
                "Patch applied successfully."
            )
            applied_count += 1
        else:
            print(
                "Patch application failed."
            )

            for error in result[
                "errors"
            ]:
                print(
                    f"- {error}"
                )

    print(
        "\n=== Remediation Summary ==="
    )

    print(
        f"Patches applied: "
        f"{applied_count}/"
        f"{len(proposed_patches)}"
    )

    if applied_count == 0:
        return 1

    print(
        "\n=== Rescanning ===\n"
    )

    verification_result = run_security_scan(
        target,
        exclude_paths=exclude_paths,
    )

    remaining_findings = prioritize(
        verification_result["findings"]
    )

    remaining_blocking = [
        finding
        for finding in remaining_findings
        if finding.severity in BLOCKING_SEVERITIES
    ]

    if verification_result["errors"]:
        print(
            "Verification scan encountered "
            "errors."
        )

        for error in verification_result[
            "errors"
        ]:
            print(
                f"[ERROR] "
                f"{error['tool']}: "
                f"{error['message']}"
            )

        return 1

    if remaining_blocking:
        print(
            "Remediation verification: "
            "FAILED"
        )

        print(
            f"Remaining HIGH/CRITICAL findings: "
            f"{len(remaining_blocking)}"
        )

        for finding in remaining_blocking:
            print(
                f"- {finding.tool} "
                f"{finding.rule}: "
                f"{finding.file}:"
                f"{finding.line}"
            )

        return 1

    print(
        "Remediation verification: "
        "PASSED"
    )

    print(
        "No HIGH or CRITICAL findings "
        "remain."
    )

    return 0


def print_help():
    print(
        """
Sentinel Security Agent

Usage:
    sentinel scan <target> [options]
    sentinel remediate <target> [options]

Commands:
    scan
        Scan a target for security findings.

    remediate
        Generate validated remediation patches,
        ask for confirmation, apply approved patches,
        and rescan the target.

Options:
    --no-ai
        Disable AI analysis and remediation.

    --format <format>
        Report format:
        json
        markdown
        html
        all

    --exclude <path>
        Exclude a path from scanning.

    --help
        Show this help message.
"""
    )


def main():
    args = sys.argv[1:]

    if not args:
        print_help()
        sys.exit(0)

    if args[0] in {
        "--help",
        "-h",
        "help",
    }:
        print_help()
        sys.exit(0)

    command = args[0]

    if command not in {
        "scan",
        "remediate",
    }:
        print(
            f"Unknown command: {command}"
        )
        print_help()
        sys.exit(2)

    if len(args) < 2:
        print(
            f"Error: {command} requires "
            "a target directory."
        )
        print_help()
        sys.exit(2)

    target = args[1]

    use_ai = True
    output_format = "all"
    exclude_paths = []

    index = 2

    while index < len(args):
        argument = args[index]

        if argument == "--no-ai":
            use_ai = False
            index += 1
            continue

        if argument == "--format":
            if index + 1 >= len(args):
                print(
                    "Error: --format requires "
                    "a value."
                )
                sys.exit(2)

            output_format = args[
                index + 1
            ]

            if output_format not in VALID_FORMATS:
                print(
                    f"Error: invalid format "
                    f"'{output_format}'."
                )

                print(
                    "Valid formats: "
                    + ", ".join(
                        sorted(VALID_FORMATS)
                    )
                )

                sys.exit(2)

            index += 2
            continue

        if argument == "--exclude":
            if index + 1 >= len(args):
                print(
                    "Error: --exclude requires "
                    "a path."
                )
                sys.exit(2)

            exclude_paths.append(
                args[index + 1]
            )

            index += 2
            continue

        print(
            f"Unknown option: {argument}"
        )

        print_help()
        sys.exit(2)

    if command == "scan":
        findings = run_agent(
            target,
            use_ai=use_ai,
            output_format=output_format,
            exclude_paths=exclude_paths,
        )

        scanner_errors = getattr(
            run_agent,
            "last_errors",
            [],
        )

        if scanner_errors:
            sys.exit(1)

        sys.exit(
            get_exit_code(findings)
        )

    if command == "remediate":
        if not use_ai:
            print(
                "Error: remediate requires "
                "AI to generate patches."
            )
            sys.exit(2)

        exit_code = remediate_agent(
            target,
            output_format=output_format,
            exclude_paths=exclude_paths,
        )

        sys.exit(exit_code)


if __name__ == "__main__":
    main()