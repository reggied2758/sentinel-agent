import json


def get_overall_risk(findings):
    high = sum(1 for f in findings if f.severity == "HIGH")
    medium = sum(1 for f in findings if f.severity == "MEDIUM")

    if high >= 1:
        return "CRITICAL"
    elif medium >= 1:
        return "HIGH"
    else:
        return "LOW"


def generate_report(findings, analyses):
    high = sum(1 for f in findings if f.severity == "HIGH")
    medium = sum(1 for f in findings if f.severity == "MEDIUM")
    low = sum(1 for f in findings if f.severity == "LOW")

    overall_risk = get_overall_risk(findings)

    report = {
        "summary": {
            "overall_risk": overall_risk,
            "high": high,
            "medium": medium,
            "low": low,
            "total": len(findings),
        },
        "findings": [],
    }

    for finding, analysis in zip(findings, analyses):
        report["findings"].append(
            {
                "tool": finding.tool,
                "rule": finding.rule,
                "severity": finding.severity,
                "file": finding.file,
                "line": finding.line,
                "message": finding.message,
                "cwe": finding.cwe,
                "ai_analysis": {
                    "risk": analysis.get("risk", ""),
                    "explanation": analysis.get("explanation", ""),
                    "impact": analysis.get("impact", ""),
                    "recommendation": analysis.get(
                        "recommendation", ""
                    ),
                },
            }
        )

    # JSON report
    with open("sentinel_report.json", "w") as file:
        json.dump(report, file, indent=2)

    # Markdown report
    with open("sentinel_report.md", "w") as file:
        file.write("# Sentinel Security Report\n\n")

        file.write(f"## Overall Risk\n\n")
        file.write(f"**{overall_risk}**\n\n")

        file.write("## Risk Summary\n\n")
        file.write("| Severity | Count |\n")
        file.write("|---|---:|\n")
        file.write(f"| HIGH | {high} |\n")
        file.write(f"| MEDIUM | {medium} |\n")
        file.write(f"| LOW | {low} |\n")
        file.write(f"| **TOTAL** | **{len(findings)}** |\n\n")

        file.write("## Findings\n\n")

        for index, (finding, analysis) in enumerate(
            zip(findings, analyses), start=1
        ):
            file.write(
                f"### {index}. [{finding.severity}] "
                f"{finding.tool} - {finding.rule}\n\n"
            )

            file.write(
                f"**Location:** `{finding.file}:{finding.line}`\n\n"
            )

            file.write(
                f"**Message:** {finding.message}\n\n"
            )

            if finding.cwe:
                file.write(f"**CWE:** {finding.cwe}\n\n")

            file.write(
                f"**Risk:** {analysis.get('risk', '')}\n\n"
            )

            file.write(
                f"**Explanation:** "
                f"{analysis.get('explanation', '')}\n\n"
            )

            file.write(
                f"**Impact:** "
                f"{analysis.get('impact', '')}\n\n"
            )

            file.write(
                f"**Recommendation:** "
                f"{analysis.get('recommendation', '')}\n\n"
            )

            file.write("---\n\n")

    print("\n=== SENTINEL SECURITY REPORT ===\n")

    print("Overall Risk")
    print("------------")
    print(overall_risk)

    print("\nRisk Summary")
    print("------------")
    print(f"HIGH     {high}")
    print(f"MEDIUM   {medium}")
    print(f"LOW      {low}")
    print(f"TOTAL    {len(findings)}")

    print("\nReports saved:")
    print("- sentinel_report.json")
    print("- sentinel_report.md")