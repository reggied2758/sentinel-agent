from scanner.bandit_scanner import (
    run_bandit,
    normalize_findings as normalize_bandit,
)

from scanner.gitleaks_scanner import (
    run_gitleaks,
    normalize_findings as normalize_gitleaks,
)

from scanner.pip_audit_scanner import (
    run_pip_audit,
    normalize_findings as normalize_pip_audit,
)


def run_security_scan(
    target,
    exclude_paths=None,
):
    findings = []
    errors = []

    exclude_paths = exclude_paths or []

    # Bandit
    bandit_data = run_bandit(
        target,
        exclude_paths=exclude_paths,
    )

    findings.extend(
        normalize_bandit(
            bandit_data
        )
    )

    for error in bandit_data.get(
        "errors",
        [],
    ):
        if error:
            errors.append(
                {
                    "tool": "bandit",
                    "message": error,
                }
            )

    # Gitleaks
    gitleaks_data = run_gitleaks(
        target,
        exclude_paths=exclude_paths,
    )

    findings.extend(
        normalize_gitleaks(
            gitleaks_data
        )
    )

    if gitleaks_data.get("error"):
        errors.append(
            {
                "tool": "gitleaks",
                "message": gitleaks_data["error"],
            }
        )

    # pip-audit
    pip_audit_data = run_pip_audit(target)

    findings.extend(
        normalize_pip_audit(
            pip_audit_data,
            target,
        )
    )

    if pip_audit_data.get("error"):
        errors.append(
            {
                "tool": "pip-audit",
                "message": pip_audit_data["error"],
            }
        )

    return {
        "findings": findings,
        "errors": errors,
    }


if __name__ == "__main__":
    result = run_security_scan(
        "vulnerable_app/"
    )

    print(
        "\n=== Sentinel Agent Security Scan ===\n"
    )

    for finding in result["findings"]:
        print(finding)

    if result["errors"]:
        print("\n=== Scanner Errors ===\n")

        for error in result["errors"]:
            print(
                f"[ERROR] "
                f"{error['tool']}: "
                f"{error['message']}"
            )

    print(
        f"\nTotal findings: "
        f"{len(result['findings'])}"
    )