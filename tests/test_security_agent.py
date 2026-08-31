from pathlib import Path

from agent.security_agent import run_agent


def test_invalid_target(capsys):
    result = run_agent("does_not_exist/")

    captured = capsys.readouterr()

    assert result == []

    assert (
        "Error: target does not exist: does_not_exist/"
        in captured.out
    )


def test_run_agent_clean_project(tmp_path, monkeypatch):
    target = tmp_path / "clean_project"
    target.mkdir()

    monkeypatch.chdir(tmp_path)

    result = run_agent(
        str(target),
        use_ai=False,
        output_format="json",
    )

    assert result == []
    assert Path("sentinel_report.json").exists()


def test_json_format(tmp_path, monkeypatch):
    target = tmp_path / "clean_project"
    target.mkdir()

    monkeypatch.chdir(tmp_path)

    run_agent(
        str(target),
        use_ai=False,
        output_format="json",
    )

    assert Path("sentinel_report.json").exists()
    assert not Path("sentinel_report.md").exists()
    assert not Path("sentinel_report.html").exists()


def test_markdown_format(tmp_path, monkeypatch):
    target = tmp_path / "clean_project"
    target.mkdir()

    monkeypatch.chdir(tmp_path)

    run_agent(
        str(target),
        use_ai=False,
        output_format="markdown",
    )

    assert Path("sentinel_report.md").exists()
    assert not Path("sentinel_report.json").exists()
    assert not Path("sentinel_report.html").exists()


def test_html_format(tmp_path, monkeypatch):
    target = tmp_path / "clean_project"
    target.mkdir()

    monkeypatch.chdir(tmp_path)

    run_agent(
        str(target),
        use_ai=False,
        output_format="html",
    )

    assert Path("sentinel_report.html").exists()
    assert not Path("sentinel_report.json").exists()
    assert not Path("sentinel_report.md").exists()


def test_all_formats(tmp_path, monkeypatch):
    target = tmp_path / "clean_project"
    target.mkdir()

    monkeypatch.chdir(tmp_path)

    run_agent(
        str(target),
        use_ai=False,
        output_format="all",
    )

    assert Path("sentinel_report.json").exists()
    assert Path("sentinel_report.md").exists()
    assert Path("sentinel_report.html").exists()