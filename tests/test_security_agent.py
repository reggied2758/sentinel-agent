from agent.security_agent import run_agent


def test_invalid_target(capsys):
    result = run_agent("does_not_exist/")

    captured = capsys.readouterr()

    assert result == []

    assert (
        "Error: target does not exist: does_not_exist/"
        in captured.out
    )