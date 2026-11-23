"""S-10: exit 1 means "something exposed". A run that fails in a way nobody foresaw tears the
copy down and exits 2, like any other run that could not finish."""

from conftest import FIXTURES, residue
from rlsentry import cli
from rlsentry.sandbox import Sandbox


def test_unexpected_error_after_the_build_tears_down_and_exits_2(state_dir, monkeypatch, capsys):
    monkeypatch.setenv("RLSENTRY_STATE_DIR", str(state_dir))

    def broken_restore(self):
        raise RuntimeError("injected failure in restore")

    monkeypatch.setattr(Sandbox, "restore", broken_restore)
    before = residue()

    code = cli.main(["attack", "--migrations", str(FIXTURES / "clean")])

    assert code == 2
    assert "injected failure in restore" in capsys.readouterr().err
    assert residue() == before
    assert list(state_dir.glob("*.json")) == []
