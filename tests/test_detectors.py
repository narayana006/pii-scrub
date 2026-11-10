import pytest

from pii_scrub import Scrubber, callable_detector, luhn_valid, regex_detector


def found(text, label=None):
    return [
        (f.label, f.value)
        for f in Scrubber().detect(text)
        if label is None or f.label == label
    ]


def test_luhn():
    assert luhn_valid("4111 1111 1111 1111")
    assert luhn_valid("378282246310005")
    assert not luhn_valid("4111 1111 1111 1112")
    assert not luhn_valid("")


@pytest.mark.parametrize(
    "email",
    ["jo@example.com", "first.last+tag@sub.example.co.uk", "a_b%c@example.io"],
)
def test_email(email):
    assert found(f"mail {email}, please") == [("EMAIL", email)]


def test_email_trailing_dot_is_not_included():
    assert found("Write to jo@example.com.") == [("EMAIL", "jo@example.com")]


def test_not_an_email():
    assert found("user@localhost or @handle") == []


@pytest.mark.parametrize(
    "phone",
    [
        "+14155552671",
        "+1 (415) 555-0132",
        "(415) 555-0132",
        "415-555-0132",
        "415.555.0132",
        "+44 20 7946 0958",
        "+91 98765 43210",
    ],
)
def test_phone(phone):
    assert found(f"call {phone} today") == [("PHONE", phone)]


@pytest.mark.parametrize(
    "text",
    ["on 2024-01-15 at 10:30", "version 3.11.4", "order 12345", "took 1500 ms", "1,000,000"],
)
def test_not_a_phone(text):
    assert found(text) == []


@pytest.mark.parametrize(
    "card",
    ["4111111111111111", "4111 1111 1111 1111", "5500-0000-0000-0004", "378282246310005"],
)
def test_credit_card(card):
    assert found(f"card: {card}.") == [("CREDIT_CARD", card)]


def test_card_failing_luhn_is_left_alone():
    assert found("ref 4111 1111 1111 1112") == []
    assert found("0000 0000 0000 0000") == []


def test_ssn():
    assert found("SSN 123-45-6789") == [("SSN", "123-45-6789")]
    assert found("SSN 000-45-6789") == []


@pytest.mark.parametrize("ip", ["203.0.113.42", "10.0.0.1", "2001:db8::ff00:42:8329", "::1"])
def test_ip(ip):
    assert found(f"from {ip} port 443") == [("IP", ip)]


@pytest.mark.parametrize("text", ["999.1.1.1", "at 12:30:45", "std::vector", "1.2.3"])
def test_not_an_ip(text):
    assert found(text, "IP") == []


def test_api_keys():
    github = "ghp_" + "a1B2" * 9
    slack = "xoxb-" + "1234567890-abcdefghij"
    sk = "sk-" + "proj-" + "Zz9" * 10
    for token in ("AKIAIOSFODNN7EXAMPLE", github, slack, sk):
        assert found(f"key {token} here") == [("API_KEY", token)]


def test_jwt_and_bearer():
    jwt = ".".join(["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NSJ9", "c2lnbmF0dXJlMTIz"])
    assert found(f"jwt={jwt}") == [("TOKEN", jwt)]
    opaque = "abcDEF0123456789abcDEF"
    assert found(f"Authorization: Bearer {opaque}") == [("TOKEN", opaque)]


def test_private_key_block():
    block = (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34\n"
        "-----END RSA PRIVATE KEY-----"
    )
    assert found(f"key:\n{block}\ndone") == [("PRIVATE_KEY", block)]


def test_secret_assignment_captures_only_the_value():
    assert found('DB_PASSWORD="s3cr3t-value!"') == [("SECRET", "s3cr3t-value!")]
    assert found("api_key: abcd1234efgh") == [("SECRET", "abcd1234efgh")]
    assert found("password: short") == []


def test_specific_label_beats_generic_secret():
    assert found("api_key=AKIAIOSFODNN7EXAMPLE") == [("API_KEY", "AKIAIOSFODNN7EXAMPLE")]


def test_findings_do_not_overlap_and_are_ordered():
    text = "a@example.com 10.0.0.1 415-555-0132 a@example.com"
    findings = Scrubber().detect(text)
    assert [f.label for f in findings] == ["EMAIL", "IP", "PHONE", "EMAIL"]
    for before, after in zip(findings, findings[1:]):
        assert before.end <= after.start
    assert all(text[f.start : f.end] == f.value for f in findings)


def test_regex_detector_with_group_and_validator():
    detector = regex_detector(
        "EMPLOYEE", r"emp:(\d+)", group=1, validator=lambda v: int(v) > 100
    )
    findings = Scrubber([detector]).detect("emp:42 emp:4200")
    assert [(f.label, f.value) for f in findings] == [("EMPLOYEE", "4200")]


def test_callable_detector_accepts_spans_and_strings():
    names = callable_detector("NAME", lambda text: ["Dana"])
    spans = callable_detector("FIRST3", lambda text: [(0, 3)])
    findings = Scrubber([names, spans]).detect("Hi, Dana and Dana")
    assert [(f.label, f.value) for f in findings] == [
        ("FIRST3", "Hi,"),
        ("NAME", "Dana"),
        ("NAME", "Dana"),
    ]


def test_callable_detector_rejects_bad_span():
    bad = callable_detector("BAD", lambda text: [(5, 2)])
    with pytest.raises(ValueError):
        Scrubber([bad]).detect("hello world")


def test_label_must_be_upper_snake_case():
    with pytest.raises(ValueError):
        regex_detector("order id", r"\d+")
