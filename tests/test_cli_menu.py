"""`python -m usbkey_guard` with no arguments must open the menu."""
from usbkey_guard import cli, tui


def test_no_arguments_opens_the_menu(monkeypatch):
    monkeypatch.setattr(tui, "main", lambda: 7)
    assert cli.main([]) == 7


def test_a_subcommand_still_dispatches():
    args = cli.build_parser().parse_args(["status"])
    assert callable(args.func)


def test_no_subcommand_has_no_dispatch():
    assert getattr(cli.build_parser().parse_args([]), "func", None) is None
