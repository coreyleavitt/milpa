"""CLI surface tests.

In-process via milpa.cli.main(argv) — no subprocess spawn. argparse's
SystemExit on --version / --help is caught with pytest.raises.
"""

import pytest

from milpa.cli import main


def test_version_prints_milpa_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "milpa" in captured.out
    assert "0.0.1" in captured.out


def test_help_lists_all_subcommands(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for cmd in ["fetch", "lock", "show", "clean"]:
        assert cmd in out, f"{cmd!r} missing from --help output"


def test_fetch_dispatches_to_cmd_fetch(monkeypatch, tmp_path):
    """`milpa fetch -C <dir>` should call cmd_fetch with the resolved dir."""
    called: dict[str, object] = {}

    def fake_cmd_fetch(project_dir):
        called["project_dir"] = project_dir
        return 0

    monkeypatch.setattr("milpa.cli.cmd_fetch", fake_cmd_fetch)
    rc = main(["-C", str(tmp_path), "fetch"])
    assert rc == 0
    assert called["project_dir"] == tmp_path.resolve()


def test_lock_dispatches_to_cmd_lock(monkeypatch, tmp_path):
    called: dict[str, object] = {}

    def fake(project_dir):
        called["project_dir"] = project_dir
        return 0

    monkeypatch.setattr("milpa.cli.cmd_lock", fake)
    rc = main(["-C", str(tmp_path), "lock"])
    assert rc == 0
    assert called["project_dir"] == tmp_path.resolve()


def test_show_dispatches_to_cmd_show(monkeypatch, tmp_path):
    called: dict[str, object] = {}

    def fake(project_dir):
        called["project_dir"] = project_dir
        return 0

    monkeypatch.setattr("milpa.cli.cmd_show", fake)
    rc = main(["-C", str(tmp_path), "show"])
    assert rc == 0


def test_clean_dispatches_to_cmd_clean(monkeypatch, tmp_path):
    called: dict[str, object] = {}

    def fake(project_dir):
        called["project_dir"] = project_dir
        return 0

    monkeypatch.setattr("milpa.cli.cmd_clean", fake)
    rc = main(["-C", str(tmp_path), "clean"])
    assert rc == 0


@pytest.mark.parametrize("cmd", ["fetch", "lock", "show", "clean"])
def test_subcommand_help_works(capsys, cmd):
    with pytest.raises(SystemExit) as exc:
        main([cmd, "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    # argparse's subparser help mentions the program name + subcommand
    assert "milpa" in out
    assert cmd in out


def test_bare_invocation_prints_help_and_exits_zero(capsys):
    rc = main([])
    assert rc == 0
    out = capsys.readouterr().out
    # Help output should mention the available subcommands so a user
    # who typed just `milpa` learns what's available.
    for cmd in ["fetch", "lock", "show", "clean"]:
        assert cmd in out
