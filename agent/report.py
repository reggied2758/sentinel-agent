import html
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

        file.write("## Overall Risk\n\n")
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
            zip(findings, analyses),
            start=1,
        ):
            file.write(
                f"### {index}. [{finding.severity}] "
                f"{finding.tool} - {finding.rule}\n\n"
            )

            file.write(
                f"**Location:** "
                f"`{finding.file}:{finding.line}`\n\n"
            )

            file.write(
                f"**Message:** {finding.message}\n\n"
            )

            if finding.cwe:
                file.write(
                    f"**CWE:** {finding.cwe}\n\n"
                )

            file.write(
                f"**Risk:** "
                f"{analysis.get('risk', '')}\n\n"
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

    # HTML report
    with open("sentinel_report.html", "w") as file:
        file.write(
            """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport"
      content="width=device-width, initial-scale=1.0">
<title>Sentinel Security Report</title>

<style>
* {
    box-sizing: border-box;
}

body {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont,
                 "Segoe UI", sans-serif;
    background: #f4f6f8;
    color: #1f2937;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 40px 24px;
}

header {
    margin-bottom: 32px;
}

h1 {
    margin: 0 0 8px;
    font-size: 32px;
}

.subtitle {
    color: #6b7280;
}

.risk {
    padding: 24px;
    border-radius: 12px;
    background: #111827;
    color: white;
    margin-bottom: 24px;
}

.risk-label {
    font-size: 14px;
    text-transform: uppercase;
    letter-spacing: 1px;
    opacity: 0.75;
}

.risk-value {
    font-size: 36px;
    font-weight: 700;
    margin-top: 6px;
}

.cards {
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
}

.card {
    background: white;
    padding: 20px;
    border-radius: 12px;
    border: 1px solid #e5e7eb;
}

.card-label {
    color: #6b7280;
    font-size: 14px;
}

.card-value {
    font-size: 30px;
    font-weight: 700;
    margin-top: 6px;
}

.finding {
    background: white;
    border: 1px solid #e5e7eb;
    border-radius: 12px;
    margin-bottom: 16px;
    overflow: hidden;
}

.finding-header {
    padding: 18px 20px;
    border-bottom: 1px solid #e5e7eb;
}

.finding-body {
    padding: 20px;
}

.severity {
    font-weight: 700;
    margin-right: 8px;
}

.high {
    color: #b91c1c;
}

.medium {
    color: #b45309;
}

.low {
    color: #047857;
}

.meta {
    color: #6b7280;
    font-size: 14px;
    margin-top: 6px;
}

.section {
    margin-top: 18px;
}

.section strong {
    display: block;
    margin-bottom: 5px;
}

code {
    background: #f3f4f6;
    padding: 2px 5px;
    border-radius: 4px;
}

.empty {
    background: white;
    padding: 32px;
    border-radius: 12px;
    text-align: center;
    color: #047857;
    font-weight: 600;
}

footer {
    margin-top: 32px;
    color: #6b7280;
    font-size: 13px;
}
</style>
</head>

<body>
<div class="container">

<header>
    <h1>Sentinel Security Report</h1>
    <div class="subtitle">
        Automated DevSecOps vulnerability analysis
    </div>
</header>
"""
        )

        file.write(
            f"""
<section class="risk">
    <div class="risk-label">Overall Risk</div>
    <div class="risk-value">
        {html.escape(overall_risk)}
    </div>
</section>

<section class="cards">
    <div class="card">
        <div class="card-label">High</div>
        <div class="card-value">{high}</div>
    </div>

    <div class="card">
        <div class="card-label">Medium</div>
        <div class="card-value">{medium}</div>
    </div>

    <div class="card">
        <div class="card-label">Low</div>
        <div class="card-value">{low}</div>
    </div>

    <div class="card">
        <div class="card-label">Total</div>
        <div class="card-value">{len(findings)}</div>
    </div>
</section>

<h2>Findings</h2>
"""
        )

        if not findings:
            file.write(
                """
<div class="empty">
    No security findings detected.
</div>
"""
            )

        for index, (finding, analysis) in enumerate(
            zip(findings, analyses),
            start=1,
        ):
            severity_class = finding.severity.lower()

            file.write(
                f"""
<article class="finding">

<div class="finding-header">
    <span class="severity {severity_class}">
        [{html.escape(finding.severity)}]
    </span>

    <strong>
        {html.escape(finding.tool)}
        - {html.escape(finding.rule)}
    </strong>

    <div class="meta">
        {html.escape(str(finding.file))}
        :{html.escape(str(finding.line))}
    </div>
</div>

<div class="finding-body">

<div class="section">
    <strong>Message</strong>
    {html.escape(str(finding.message))}
</div>
"""
            )

            if finding.cwe:
                file.write(
                    f"""
<div class="section">
    <strong>CWE</strong>
    {html.escape(str(finding.cwe))}
</div>
"""
                )

            file.write(
                f"""
<div class="section">
    <strong>Risk</strong>
    {html.escape(
        str(analysis.get("risk", ""))
    )}
</div>

<div class="section">
    <strong>Explanation</strong>
    {html.escape(
        str(analysis.get("explanation", ""))
    )}
</div>

<div class="section">
    <strong>Impact</strong>
    {html.escape(
        str(analysis.get("impact", ""))
    )}
</div>

<div class="section">
    <strong>Recommendation</strong>
    {html.escape(
        str(analysis.get("recommendation", ""))
    )}
</div>

</div>
</article>
"""
            )

        file.write(
            """
<footer>
    Generated by Sentinel Security Agent.
</footer>

</div>
</body>
</html>
"""
        )

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
    print("- sentinel_report.html")