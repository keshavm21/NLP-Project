from vulntriage.cli import main


def test_status_runs(capsys):
    assert main(["status"]) == 0
    assert "eval-e2e" in capsys.readouterr().out


def test_unimplemented_command_names_owner(capsys):
    assert main(["train-cwe"]) == 2
    assert "Owner: P4" in capsys.readouterr().err
