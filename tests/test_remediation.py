from scanner.finding import SecurityFinding
from agent.remediation import generate_remediation


def test_generate_remediation_returns_expected_structure(
    monkeypatch,
):
    finding = SecurityFinding(
        tool="bandit",
        rule="B602",
        severity="HIGH",
        file="vulnerable_app/app.py",
        line=19,
        message=(
            "subprocess call with shell=True "
            "identified, security issue."
        ),
        cwe=78,
        code=(
            "result = subprocess.run("
            "user_input, shell=True)"
        ),
    )

    class FakeResponse:
        output_text = """
{
    "summary": "Disable shell execution.",
    "explanation": "shell=True can enable command injection.",
    "fixed_code": "subprocess.run(args, shell=False)",
    "changes": [
        "Use an argument list.",
        "Disable shell execution."
    ],
    "testing": "Run Bandit and application tests."
}
"""

    class FakeResponses:
        def create(self, **kwargs):
            return FakeResponse()

    class FakeClient:
        responses = FakeResponses()

    monkeypatch.setattr(
        "agent.remediation.get_client",
        lambda: FakeClient(),
    )

    result = generate_remediation(
        finding
    )

    assert result["summary"] == (
        "Disable shell execution."
    )

    assert result["explanation"] == (
        "shell=True can enable command injection."
    )

    assert result["fixed_code"] == (
        "subprocess.run(args, shell=False)"
    )

    assert result["changes"] == [
        "Use an argument list.",
        "Disable shell execution.",
    ]

    assert result["testing"] == (
        "Run Bandit and application tests."
    )