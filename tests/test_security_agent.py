from agent.security_agent import get_exit_code, run_agent
from scanner.finding import SecurityFinding


def test_invalid_target(capsys):
    result = run_agent("does_not_exist/")

    captured = capsys.readouterr()

    assert result == []

    assert (
        "Error: target does not exist: does_not_exist/"
        in captured.out
    )


def test_invalid_file_target(tmp_path, capsys):
    target = tmp_path / "file.txt"
    target.write_text("test")

    result = run_agent(str(target))

    captured = capsys.readouterr()

    assert result == []

    assert (
        f"Error: target is not a directory: {target}"
        in captured.out
    )


def test_security_gate_allows_low():
    finding = SecurityFinding(
        "bandit",
        "B404",
        "LOW",
        "test.py",
        1,
        "Test low severity finding.",
        None,
    )

    assert get_exit_code([finding]) == 0


def test_security_gate_allows_medium():
    finding = SecurityFinding(
        "bandit",
        "B608",
        "MEDIUM",
        "test.py",
        1,
        "Test medium severity finding.",
        None,
    )

    assert get_exit_code([finding]) == 0


def test_security_gate_blocks_high():
    finding = SecurityFinding(
        "bandit",
        "B602",
        "HIGH",
        "test.py",
        1,
        "Test high severity finding.",
        None,
    )

    assert get_exit_code([finding]) == 1


def test_security_gate_blocks_critical():
    finding = SecurityFinding(
        "sentinel",
        "TEST",
        "CRITICAL",
        "test.py",
        1,
        "Test critical severity finding.",
        None,
    )

    assert get_exit_code([finding]) == 1