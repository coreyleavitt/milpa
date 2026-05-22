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
    for cmd in ["fetch", "lock", "show", "verify", "clean"]:
        assert cmd in out, f"{cmd!r} missing from --help output"


def test_fetch_dispatches_to_cmd_fetch(monkeypatch, tmp_path):
    """`milpa fetch -C <dir>` should call cmd_fetch with the resolved dir."""
    called: dict[str, object] = {}

    def fake_cmd_fetch(project_dir, **kw):
        called["project_dir"] = project_dir
        return 0

    monkeypatch.setattr("milpa.cli.cmd_fetch", fake_cmd_fetch)
    rc = main(["-C", str(tmp_path), "fetch"])
    assert rc == 0
    assert called["project_dir"] == tmp_path.resolve()


def test_lock_dispatches_to_cmd_lock(monkeypatch, tmp_path):
    called: dict[str, object] = {}

    def fake(project_dir, **kw):
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


def test_verify_dispatches_to_cmd_verify(monkeypatch, tmp_path):
    called: dict[str, object] = {}

    def fake(project_dir):
        called["project_dir"] = project_dir
        return 0

    monkeypatch.setattr("milpa.cli.cmd_verify", fake)
    rc = main(["-C", str(tmp_path), "verify"])
    assert rc == 0
    assert called["project_dir"] == tmp_path.resolve()


def test_parallel_flag_passed_to_cmd_fetch(monkeypatch, tmp_path):
    called: dict[str, object] = {}

    def fake(project_dir, **kw):
        called["project_dir"] = project_dir
        called["max_parallel"] = kw["max_parallel"]
        return 0

    monkeypatch.setattr("milpa.cli.cmd_fetch", fake)
    rc = main(["-C", str(tmp_path), "-j", "4", "fetch"])
    assert rc == 0
    assert called["max_parallel"] == 4


def test_parallel_long_flag(monkeypatch, tmp_path):
    called: dict[str, object] = {}

    def fake(project_dir, **kw):
        called["max_parallel"] = kw["max_parallel"]
        return 0

    monkeypatch.setattr("milpa.cli.cmd_fetch", fake)
    rc = main(["-C", str(tmp_path), "--parallel", "2", "fetch"])
    assert rc == 0
    assert called["max_parallel"] == 2


def test_strategy_flag_passed_to_cmd_fetch(monkeypatch, tmp_path):
    """`milpa fetch --strategy=minver` should reach cmd_fetch as
    Strategy.MINVER."""
    from milpa.solver import Strategy
    called: dict[str, object] = {}

    def fake(project_dir, **kw):
        called["strategy"] = kw["strategy"]
        return 0

    monkeypatch.setattr("milpa.cli.cmd_fetch", fake)
    rc = main(["-C", str(tmp_path), "--strategy", "minver", "fetch"])
    assert rc == 0
    assert called["strategy"] == Strategy.MINVER


def test_strategy_default_is_maxver(monkeypatch, tmp_path):
    """Default strategy is maxver — no behavior change for existing users."""
    from milpa.solver import Strategy
    called: dict[str, object] = {}

    def fake(project_dir, **kw):
        called["strategy"] = kw["strategy"]
        return 0

    monkeypatch.setattr("milpa.cli.cmd_fetch", fake)
    rc = main(["-C", str(tmp_path), "fetch"])
    assert rc == 0
    assert called["strategy"] == Strategy.MAXVER


def test_parallel_default_is_nontrivial(monkeypatch, tmp_path):
    """When -j isn't passed, max_parallel should default > 1 so we
    don't accidentally serialize."""
    called: dict[str, object] = {}

    def fake(project_dir, **kw):
        called["max_parallel"] = kw["max_parallel"]
        return 0

    monkeypatch.setattr("milpa.cli.cmd_fetch", fake)
    rc = main(["-C", str(tmp_path), "fetch"])
    assert rc == 0
    assert called["max_parallel"] > 1


@pytest.mark.parametrize("cmd", ["fetch", "lock", "show", "verify", "clean"])
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
    for cmd in ["fetch", "lock", "show", "verify", "clean"]:
        assert cmd in out
