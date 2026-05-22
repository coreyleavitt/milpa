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


@pytest.mark.parametrize("cmd", ["fetch", "lock", "show", "clean"])
def test_subcommand_stub_exits_nonzero_with_message(capsys, cmd):
    rc = main([cmd])
    assert rc != 0, f"{cmd!r} should exit non-zero while unimplemented"
    err = capsys.readouterr().err
    assert "not yet implemented" in err
    assert cmd in err


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
