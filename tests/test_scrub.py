import json
import os
import stat

import pytest

from pii_scrub import Scrubber, Vault, regex_detector, scrub

TEXT = "Mail jo@example.com or sam@example.com, card 4111 1111 1111 1111. Again: jo@example.com"


def test_scrub_replaces_and_numbers_per_label():
    safe, vault = scrub(TEXT)
    assert safe == "Mail <EMAIL_1> or <EMAIL_2>, card <CREDIT_CARD_1>. Again: <EMAIL_1>"
    assert vault.items() == [
        ("<EMAIL_1>", "jo@example.com"),
        ("<EMAIL_2>", "sam@example.com"),
        ("<CREDIT_CARD_1>", "4111 1111 1111 1111"),
    ]
    assert vault.counts() == {"EMAIL": 2, "CREDIT_CARD": 1}


def test_roundtrip_is_exact():
    safe, vault = scrub(TEXT)
    assert vault.restore(safe) == TEXT


def test_restore_in_model_output():
    _, vault = scrub(TEXT)
    reply = "I emailed <EMAIL_2> and <EMAIL_1> about <CREDIT_CARD_1>."
    assert vault.restore(reply) == (
        "I emailed sam@example.com and jo@example.com about 4111 1111 1111 1111."
    )


def test_unknown_placeholders_are_left_alone():
    _, vault = scrub(TEXT)
    assert vault.restore("<EMAIL_9> <PHONE_1> <b>") == "<EMAIL_9> <PHONE_1> <b>"


def test_clean_text_is_unchanged():
    text = "Nothing sensitive here, just 42 apples."
    safe, vault = scrub(text)
    assert safe == text
    assert len(vault) == 0


def test_empty_text():
    assert scrub("")[0] == ""


def test_vault_is_shared_across_calls():
    first, vault = scrub("from jo@example.com")
    second, same = scrub("cc sam@example.com and jo@example.com", vault)
    assert same is vault
    assert first == "from <EMAIL_1>"
    assert second == "cc <EMAIL_2> and <EMAIL_1>"


def test_extra_detector_and_restore():
    order = regex_detector("ORDER", r"ORD-\d+")
    safe, vault = scrub("ORD-123 for jo@example.com", extra=[order])
    assert safe == "<ORDER_1> for <EMAIL_1>"
    assert vault.restore("done: <ORDER_1>") == "done: ORD-123"


def test_extra_detector_wins_a_tie_with_a_builtin():
    internal = regex_detector("STAFF_EMAIL", r"[\w.]+@corp\.example")
    safe, _ = scrub("ping kim@corp.example", extra=[internal])
    assert safe == "ping <STAFF_EMAIL_1>"


def test_detectors_argument_replaces_builtins():
    only_orders = [regex_detector("ORDER", r"ORD-\d+")]
    safe, _ = scrub("ORD-1 jo@example.com", detectors=only_orders)
    assert safe == "<ORDER_1> jo@example.com"


def test_multiline_and_unicode_are_preserved():
    text = "Zoë → zoe@example.com\n電話 +14155552671\n"
    safe, vault = Scrubber().scrub(text)
    assert safe == "Zoë → <EMAIL_1>\n電話 <PHONE_1>\n"
    assert vault.restore(safe) == text


def test_vault_save_and_load(tmp_path):
    safe, vault = scrub(TEXT)
    path = tmp_path / "vault.json"
    vault.save(path)
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text())["version"] == 1

    loaded = Vault.load(path)
    assert loaded.restore(safe) == TEXT
    # numbering continues after a reload and known values keep their placeholder
    again, _ = scrub("new@example.com and jo@example.com", loaded)
    assert again == "<EMAIL_3> and <EMAIL_1>"


def test_vault_mapping_protocol():
    _, vault = scrub(TEXT)
    assert "<EMAIL_1>" in vault
    assert vault["<EMAIL_2>"] == "sam@example.com"
    assert list(vault) == ["<EMAIL_1>", "<EMAIL_2>", "<CREDIT_CARD_1>"]


@pytest.mark.parametrize("bad", [{}, {"entries": []}, {"entries": {"EMAIL_1": "x"}}, []])
def test_vault_rejects_malformed_data(bad):
    with pytest.raises(ValueError):
        Vault.from_dict(bad)
