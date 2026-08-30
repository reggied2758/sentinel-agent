def prioritize(findings):
    priority = {
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3
    }

    return sorted(
        findings,
        key=lambda finding: priority.get(finding.severity, 4)
    )