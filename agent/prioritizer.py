def deduplicate(findings):
    seen = set()
    unique_findings = []

    for finding in findings:
        if finding.finding_id in seen:
            continue

        seen.add(finding.finding_id)
        unique_findings.append(finding)

    return unique_findings


def prioritize(findings):
    priority = {
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
    }

    unique_findings = deduplicate(findings)

    return sorted(
        unique_findings,
        key=lambda finding: priority.get(
            finding.severity,
            4,
        ),
    )