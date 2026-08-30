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


def run_security_scan(target):
    findings = []

    # Bandit
    bandit_data = run_bandit(target)
    findings.extend(normalize_bandit(bandit_data))

    # Gitleaks
    gitleaks_data = run_gitleaks(target)
    findings.extend(normalize_gitleaks(gitleaks_data))

    # pip-audit
    pip_audit_data = run_pip_audit(target)
    findings.extend(normalize_pip_audit(pip_audit_data, target))

    return findings


if __name__ == "__main__":
    findings = run_security_scan("vulnerable_app/")

    print("\n=== Sentinel Agent Security Scan ===\n")

    for finding in findings:
        print(finding)

    print(f"\nTotal findings: {len(findings)}")