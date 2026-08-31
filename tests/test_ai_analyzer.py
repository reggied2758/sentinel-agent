from unittest.mock import patch

from openai import APIError

from agent.ai_analyzer import analyze_finding
from scanner.finding import SecurityFinding


def test_ai_api_error():
    finding = SecurityFinding(
        "bandit",
        "B602",
        "HIGH",
        "test.py",
        19,
        "subprocess call with shell=True identified, security issue.",
        78,
    )

    mock_client = patch(
        "agent.ai_analyzer.get_client"
    )

    with mock_client as get_client:
        get_client.return_value.responses.create.side_effect = APIError(
            "Test API failure",
            request=None,
            body=None,
        )

        result = analyze_finding(finding)

    assert result["risk"] == "B602"
    assert "AI analysis failed" in result["explanation"]
    assert result["recommendation"] != ""