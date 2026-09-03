import sys
from pathlib import Path

from scanner.__main__ import run_security_scan
from agent.prioritizer import prioritize
from agent.ai_analyzer import analyze_finding
from agent.remediation import generate_remediation
from agent.patch_validator import validate_patch
from agent.patch_applier import apply_patch, dry_run_patch
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
    dry_run=False,
):
    """
    Generate validated remediation patches.

    Normal mode:
        Ask for confirmation, apply approved patches,
        and rescan the target.

    Dry-run mode:
        Test whether the patches can be applied without
        modifying any files.
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

    if dry_run:
        print(
            "\n=== Dry Run ==="
        )

        print(
            "\nTesting whether the proposed "
            "patches can be applied."
        )

        print(
            "No files will be modified.\n"
        )

        dry_run_failed = False

        for proposal in proposed_patches:
            finding = proposal["finding"]
            remediation = proposal["remediation"]

            print(
                f"Testing patch for "
                f"{finding.tool} "
                f"{finding.rule}..."
            )

            result = dry_run_patch(
                remediation["patch"],
                target,
            )

            if result["valid"]:
                print(
                    "Dry-run application check: PASSED"
                )

                if result.get("output"):
                    print(
                        result["output"]
                    )
            else:
                dry_run_failed = True

                print(
                    "Dry-run application check: FAILED"
                )

                for error in result[
                    "errors"
                ]:
                    print(
                        f"- {error}"
                    )

        print(
            "\nNo files have been modified."
        )

        if dry_run_failed:
            print(
                "Dry run failed."
            )
            return 1

        print(
            "Dry run completed successfully."
        )

        return 0

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
            "Verification scan encountered errors."
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
            "Remediation verification: FAILED"
        )

        print(
            "\nRemaining HIGH or CRITICAL findings:"
        )

        for finding in remaining_blocking:
            print(
                f"- {finding.tool} "
                f"{finding.rule} "
                f"{finding.file}:"
                f"{finding.line}"
            )

        return 1

    print(
        "Remediation verification: PASSED"
    )

    print(
        "No HIGH or CRITICAL findings remain."
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

    --dry-run
        Generate and validate remediation patches
        without modifying any files.

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
    arguments = sys.argv[1:]

    if not arguments:
        print_help()
        return 1

    if "--help" in arguments:
        print_help()
        return 0

    command = arguments[0]

    if command not in {
        "scan",
        "remediate",
    }:
        print(
            f"Unknown command: {command}"
        )
        print_help()
        return 1

    if len(arguments) < 2:
        print(
            f"Error: {command} requires a target."
        )
        print_help()
        return 1

    target = arguments[1]

    use_ai = True
    dry_run = False
    output_format = "all"
    exclude_paths = []

    index = 2

    while index < len(arguments):
        argument = arguments[index]

        if argument == "--no-ai":
            use_ai = False

        elif argument == "--dry-run":
            dry_run = True

        elif argument == "--format":
            index += 1

            if index >= len(arguments):
                print(
                    "Error: --format requires a value."
                )
                return 1

            output_format = arguments[index]

            if output_format not in VALID_FORMATS:
                print(
                    f"Unknown format: "
                    f"{output_format}"
                )
                print(
                    "Valid formats: "
                    "json, markdown, html, all"
                )
                return 1

        elif argument == "--exclude":
            index += 1

            if index >= len(arguments):
                print(
                    "Error: --exclude requires a path."
                )
                return 1

            exclude_paths.append(
                arguments[index]
            )

        else:
            print(
                f"Unknown option: {argument}"
            )
            print_help()
            return 1

        index += 1

    if command == "scan":
        if dry_run:
            print(
                "Error: --dry-run is only "
                "available with remediate."
            )
            return 1

        findings = run_agent(
            target,
            use_ai=use_ai,
            output_format=output_format,
            exclude_paths=exclude_paths,
        )

        return get_exit_code(findings)

    if command == "remediate":
        if not use_ai:
            print(
                "Error: --no-ai cannot be used "
                "with remediate."
            )
            return 1

        return remediate_agent(
            target,
            output_format=output_format,
            exclude_paths=exclude_paths,
            dry_run=dry_run,
        )

    return 1


if __name__ == "__main__":
    sys.exit(main())