import io
import json

import pytest

from pii_scrub.cli import main

TEXT = "Contact jo@example.com from 203.0.113.42, ticket TCK-9912.\n"


@pytest.fixture
def ticket(tmp_path):
    path = tmp_path / "ticket.txt"
    path.write_text(TEXT, encoding="utf-8")
    return path


def test_scrub_then_restore(ticket, tmp_path, capsys):
    vault = tmp_path / "vault.json"
    assert main(["scrub", str(ticket), "--vault", str(vault)]) == 0
    out, err = capsys.readouterr()
    assert out == "Contact <EMAIL_1> from <IP_1>, ticket TCK-9912.\n"
    assert "replaced 2 value(s): EMAIL 1, IP 1" in err

    reply = tmp_path / "reply.txt"
    reply.write_text("Wrote to <EMAIL_1>.", encoding="utf-8")
    assert main(["restore", str(reply), "--vault", str(vault)]) == 0
    assert capsys.readouterr().out == "Wrote to jo@example.com."


def test_scrub_reads_stdin_and_writes_output_file(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(TEXT))
    out_path = tmp_path / "safe.txt"
    assert main(["scrub", "-o", str(out_path)]) == 0
    assert out_path.read_text() == "Contact <EMAIL_1> from <IP_1>, ticket TCK-9912.\n"
    assert "cannot be restored" in capsys.readouterr().err


def test_existing_vault_is_extended(ticket, tmp_path, capsys):
    vault = tmp_path / "vault.json"
    main(["scrub", str(ticket), "--vault", str(vault)])
    other = tmp_path / "other.txt"
    other.write_text("sam@example.com, jo@example.com", encoding="utf-8")
    capsys.readouterr()
    main(["scrub", str(other), "--vault", str(vault)])
    assert capsys.readouterr().out == "<EMAIL_2>, <EMAIL_1>"


def test_only_and_pattern_options(ticket, capsys):
    assert main(["scrub", str(ticket), "--only", "email", "--pattern", r"TICKET=TCK-\d+"]) == 0
    assert capsys.readouterr().out == "Contact <EMAIL_1> from 203.0.113.42, ticket <TICKET_1>.\n"


def test_unknown_detector_name(ticket):
    with pytest.raises(SystemExit) as excinfo:
        main(["scrub", str(ticket), "--only", "EMAIL,NOPE"])
    assert "NOPE" in str(excinfo.value)


def test_bad_pattern(ticket):
    with pytest.raises(SystemExit):
        main(["scrub", str(ticket), "--pattern", "X=("])
    with pytest.raises(SystemExit):
        main(["scrub", str(ticket), "--pattern", "no-equals"])


def test_detect_masks_by_default(ticket, capsys):
    assert main(["detect", str(ticket)]) == 0
    out = capsys.readouterr().out
    assert "jo@example.com" not in out
    assert out.splitlines()[0].startswith("1:9\tEMAIL\t")


def test_detect_json_show_and_fail_on_find(ticket, capsys):
    assert main(["detect", str(ticket), "--json", "--show", "--fail-on-find"]) == 1
    rows = json.loads(capsys.readouterr().out)
    assert rows == [
        {"label": "EMAIL", "line": 1, "column": 9, "value": "jo@example.com"},
        {"label": "IP", "line": 1, "column": 29, "value": "203.0.113.42"},
    ]


def test_missing_vault_file_is_reported(ticket, tmp_path, capsys):
    assert main(["restore", str(ticket), "--vault", str(tmp_path / "nope.json")]) == 2
    assert "pii-scrub:" in capsys.readouterr().err
