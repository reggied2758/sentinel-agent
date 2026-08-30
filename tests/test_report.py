import json

from scanner.finding import SecurityFinding
from agent.report import generate_report


def test_generate_report(tmp_path, monkeypatch):
    findings = [
        SecurityFinding(
            "bandit",
            "B602",
            "HIGH",
            "app.py",
            10,
            "shell=True",
        ),
        SecurityFinding(
            "bandit",
            "B608",
            "MEDIUM",
            "app.py",
            20,
            "SQL injection",
        ),
        SecurityFinding(
            "bandit",
            "B404",
            "LOW",
            "app.py",
            2,
            "subprocess module",
        ),
    ]

    analyses = [
        {
            "risk": "Command injection",
            "explanation": "Unsafe shell execution.",
            "impact": "Arbitrary command execution.",
            "recommendation": "Avoid shell=True.",
        },
        {
            "risk": "SQL injection",
            "explanation": "Unsafe SQL construction.",
            "impact": "Unauthorized database access.",
            "recommendation": "Use parameterized queries.",
        },
        {
            "risk": "Subprocess risk",
            "explanation": "Subprocess requires review.",
            "impact": "Potential command execution.",
            "recommendation": "Use safe subprocess arguments.",
        },
    ]

    monkeypatch.chdir(tmp_path)

    generate_report(findings, analyses)

    report_file = tmp_path / "sentinel_report.json"

    assert report_file.exists()

    with open(report_file) as file:
        report = json.load(file)

    assert report["summary"]["overall_risk"] == "CRITICAL"
    assert report["summary"]["high"] == 1
    assert report["summary"]["medium"] == 1
    assert report["summary"]["low"] == 1
    assert report["summary"]["total"] == 3

    assert len(report["findings"]) == 3

    assert report["findings"][0]["rule"] == "B602"
    assert (
        report["findings"][0]["ai_analysis"]["risk"]
        == "Command injection"
    )