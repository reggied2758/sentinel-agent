from scanner.finding import SecurityFinding
from agent.prioritizer import prioritize


def test_prioritize_orders_severity():
    findings = [
        SecurityFinding(
            "test",
            "LOW",
            "LOW",
            "test.py",
            1,
            "low finding",
        ),
        SecurityFinding(
            "test",
            "HIGH",
            "HIGH",
            "test.py",
            2,
            "high finding",
        ),
        SecurityFinding(
            "test",
            "MEDIUM",
            "MEDIUM",
            "test.py",
            3,
            "medium finding",
        ),
    ]

    result = prioritize(findings)

    assert result[0].severity == "HIGH"
    assert result[1].severity == "MEDIUM"
    assert result[2].severity == "LOW"


def test_prioritize_empty_list():
    result = prioritize([])

    assert result == []


def test_deduplicates_identical_findings():
    finding = SecurityFinding(
        "bandit",
        "B602",
        "HIGH",
        "app.py",
        19,
        "shell=True",
    )

    result = prioritize([finding, finding])

    assert len(result) == 1
    assert result[0].finding_id == finding.finding_id


def test_finding_id_is_stable():
    finding_one = SecurityFinding(
        "bandit",
        "B602",
        "HIGH",
        "app.py",
        19,
        "shell=True",
    )

    finding_two = SecurityFinding(
        "bandit",
        "B602",
        "HIGH",
        "app.py",
        19,
        "shell=True",
    )

    assert finding_one.finding_id == finding_two.finding_id


def test_different_findings_have_different_ids():
    finding_one = SecurityFinding(
        "bandit",
        "B602",
        "HIGH",
        "app.py",
        19,
        "shell=True",
    )

    finding_two = SecurityFinding(
        "bandit",
        "B608",
        "MEDIUM",
        "app.py",
        10,
        "SQL injection",
    )

    assert finding_one.finding_id != finding_two.finding_id