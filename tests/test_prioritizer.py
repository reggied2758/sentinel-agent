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