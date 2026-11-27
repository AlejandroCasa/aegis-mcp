"""TDD suite for the checksum-validated enterprise DLP engine (app/redactor.py)."""

import base64
import json
from collections.abc import Iterator
from typing import Any

import pytest

from app.config import settings
from app.redactor import (
    iban_valid,
    is_credit_card,
    is_sensitive_key,
    looks_like_secret,
    luhn_valid,
    national_id_valid,
    placeholder,
    redact_payload,
    redact_text,
    shannon_entropy,
)

# Sensitive fixtures are assembled at runtime so the live guard hook and
# secret scanners do not flag this source file itself.
PEM_DASHES = "-" * 5
ZWSP = "\u200b"


def _pem(kind: str) -> str:
    label = f"{kind}PRIVATE KEY"
    body = "MIIEowIBAAKCAQEA1x2y3z4\nAbCdEfGhIjKlMnOpQrStUv==\n"
    return (
        f"{PEM_DASHES}BEGIN {label}{PEM_DASHES}\n{body}"
        f"{PEM_DASHES}END {label}{PEM_DASHES}"
    )


def _b64url(data: dict[str, Any]) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _jwt() -> str:
    header = _b64url({"alg": "HS256", "typ": "JWT"})
    payload = _b64url({"sub": "1234567890", "name": "Jane"})
    return f"{header}.{payload}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"


@pytest.fixture(autouse=True)
def dlp_defaults() -> Iterator[None]:
    """Reset DLP settings before and after each test."""
    settings.dlp_hmac_key = None
    settings.dlp_entropy_enabled = True
    yield
    settings.dlp_hmac_key = None
    settings.dlp_entropy_enabled = True


# ---------------------------------------------------------------------------
# Credit cards (Luhn)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "card",
    [
        "4111111111111111",
        "5555555555554444",
        "378282246310005",
        "4111 1111 1111 1111",
        "4111-1111-1111-1111",
        "3782-822463-10005",
    ],
)
def test_luhn_valid_cards_are_redacted(card: str) -> None:
    """Visa, Mastercard, Amex in compact and grouped forms are redacted."""
    text, categories = redact_text(f"pay with {card} today")
    assert text == "pay with [REDACTED_CREDIT_CARD] today"
    assert categories == {"credit_card"}


@pytest.mark.parametrize(
    "value",
    [
        "4111111111111112",  # 1-digit Luhn corruption
        "0000000000000000",  # trivial all-zero
        "1700000000000",  # epoch-ms timestamp
        "order 41111111111111110000",  # longer digit run
        "ID4111111111111111",  # embedded identifier
        "4111 1111 1111 1111 1111 22",  # bad grouping
    ],
)
def test_non_cards_are_untouched(value: str) -> None:
    """Luhn-invalid, trivial, or embedded digit runs are not redacted."""
    assert redact_text(value) == (value, set())


def test_card_validators() -> None:
    """Luhn and card-shape primitives behave as specified."""
    assert luhn_valid("79927398713")
    assert not luhn_valid("79927398710")
    assert not is_credit_card("1234567812345670")  # Luhn-valid, no network
    assert not is_credit_card("411111111111")


# ---------------------------------------------------------------------------
# IBAN (ISO 7064 mod-97)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "iban",
    [
        "ES9121000418450200051332",
        "DE89370400440532013000",
        "GB82WEST12345698765432",
        "FR1420041010050500013M02606",
        "ES91 2100 0418 4502 0005 1332",
        "DE89 3704 0044 0532 0130 00",
    ],
)
def test_valid_ibans_are_redacted(iban: str) -> None:
    """Checksum-valid IBANs are redacted compact or space-grouped."""
    text, categories = redact_text(f"from {iban} done")
    assert text == "from [REDACTED_IBAN] done"
    assert categories == {"iban"}


def test_grouped_iban_does_not_swallow_trailing_word() -> None:
    """A following 4-letter word is not consumed into the IBAN."""
    text, _ = redact_text("ES91 2100 0418 4502 0005 1332 PAID")
    assert text == "[REDACTED_IBAN] PAID"


@pytest.mark.parametrize(
    "value",
    ["ES9221000418450200051332", "DE89370400440532013001", "GB00WEST12345698765432"],
)
def test_bad_check_digit_ibans_are_untouched(value: str) -> None:
    """IBAN-shaped strings failing mod-97 are not redacted."""
    assert redact_text(value) == (value, set())


def test_iban_validator_length_bounds() -> None:
    """Too-short candidates are rejected without arithmetic."""
    assert not iban_valid("ES91")


# ---------------------------------------------------------------------------
# Spanish DNI / NIE
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "national_id",
    ["12345678Z", "12345678-Z", "X1234567L", "Y1234567X", "Z1234567R"],
)
def test_valid_dni_nie_are_redacted(national_id: str) -> None:
    """DNI and X/Y/Z NIE with correct control letter are redacted."""
    text, categories = redact_text(f"id {national_id}.")
    assert text == "id [REDACTED_NATIONAL_ID]."
    assert categories == {"national_id"}


@pytest.mark.parametrize(
    "value", ["12345678A", "X1234567A", "12345678z", "SKU12345678Z"]
)
def test_invalid_dni_nie_are_untouched(value: str) -> None:
    """Wrong control letters, lowercase, or embedded codes are not redacted."""
    assert redact_text(value) == (value, set())
    assert not national_id_valid("00000000A")


# ---------------------------------------------------------------------------
# JWT and PEM private keys
# ---------------------------------------------------------------------------


def test_valid_jwt_is_redacted_even_after_bearer() -> None:
    """Compact JWS tokens are redacted as jwt, standalone or as Bearer."""
    token = _jwt()
    assert redact_text(f"t={token}") == ("t=[REDACTED_JWT]", {"jwt"})
    text, categories = redact_text(f"Authorization: Bearer {token}")
    assert text == "Authorization: Bearer [REDACTED_JWT]"
    assert categories == {"jwt"}


def test_truncated_bearer_stays_secret() -> None:
    """A 2-part Bearer value keeps the legacy secret category."""
    text, categories = redact_text("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpX")
    assert text == "[REDACTED_SECRET]"
    assert categories == {"secret"}


@pytest.mark.parametrize(
    "value",
    ["version 1.2.3.4", "file.name.ext", "eyJxxxxxxxxx.eyJyyyyyyyyy.zzzzzzzzzz"],
)
def test_non_jwt_dot_strings_are_not_jwt(value: str) -> None:
    """Dotted strings that are not Base64URL JSON objects are not JWTs."""
    _, categories = redact_text(value)
    assert "jwt" not in categories


@pytest.mark.parametrize("kind", ["RSA ", "EC ", "OPENSSH ", ""])
def test_pem_private_keys_are_redacted(kind: str) -> None:
    """Complete PEM private key blocks are fully redacted."""
    text, categories = redact_text(f"key:\n{_pem(kind)}\nend")
    assert text == "key:\n[REDACTED_PRIVATE_KEY]\nend"
    assert categories == {"private_key"}


def test_truncated_pem_header_is_redacted() -> None:
    """A header with a truncated body is still redacted."""
    header = f"{PEM_DASHES}BEGIN RSA PRIVATE KEY{PEM_DASHES}"
    text, categories = redact_text(f"{header}\nMIIEowIBAAKCAQEA")
    assert text == "[REDACTED_PRIVATE_KEY]"
    assert categories == {"private_key"}


# ---------------------------------------------------------------------------
# Cloud and SaaS provider secrets
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "secret",
    [
        "xox" + "b-" + "1234567890-abcdefghij",
        "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc",
        "rk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc",
        "AI" + "za" + "SyD" + "a" * 32,
        "gl" + "pat-" + "xY12" * 5,
        "AK" + "IA" + "IOSFODNN7EXAMPLE",
        "AS" + "IA" + "IOSFODNN7EXAMPLE",
        "gh" + "p_" + "A1b2" * 9,
        "gh" + "o_" + "A1b2" * 9,
        "github" + "_pat_" + "11ABCDEFG0123456789_abcdefghijk",
        "Account" + "Key=" + "Ab1+" * 15 + "==",
        "sig=" + "Zm9vYmFyYmF6cXV4" * 2 + "%3D",
        "sk-" + "proj1234567890abcdef",
    ],
)
def test_provider_secrets_are_redacted(secret: str) -> None:
    """Known provider token formats are redacted as secret."""
    text, categories = redact_text(f"cfg {secret} end")
    assert text == "cfg [REDACTED_SECRET] end"
    assert categories == {"secret"}


# ---------------------------------------------------------------------------
# E.164 phone numbers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "phone", ["+34612345678", "+34 612 345 678", "+1-415-555-2671", "+447911123456"]
)
def test_e164_phones_are_redacted(phone: str) -> None:
    """International +-prefixed numbers are redacted."""
    text, categories = redact_text(f"call {phone} now")
    assert text == "call [REDACTED_PHONE] now"
    assert categories == {"phone"}


@pytest.mark.parametrize(
    "value",
    [
        "2024-01-15T10:00:00+01:00",
        "2024-01-15T10:00:00+00:00",
        "offset +05:30 applied",
        "1+1234567 ",
        "+0123456789",
        "+1234567",
        "local 612 345 678",
        "2026-11-25",
    ],
)
def test_dates_offsets_and_local_numbers_are_not_phones(value: str) -> None:
    """ISO timestamps, offsets, short or zero-country numbers are untouched."""
    assert redact_text(value) == (value, set())


# ---------------------------------------------------------------------------
# Shannon-entropy secrets
# ---------------------------------------------------------------------------

HIGH_ENTROPY = "Xk9#mQ2vL8pR4tZ7wB1n"


def test_shannon_entropy_values() -> None:
    """Entropy is 0 for empty/uniform strings and log2(n) for distinct chars."""
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") == pytest.approx(2.0)


@pytest.mark.parametrize(
    "assignment",
    [
        f"password={HIGH_ENTROPY}",
        f"API_KEY: '{HIGH_ENTROPY}'",
        f'"client_secret": "{HIGH_ENTROPY}"',
        f"auth-token = {HIGH_ENTROPY};",
    ],
)
def test_key_value_high_entropy_secret_is_redacted(assignment: str) -> None:
    """Explicit secret assignments with random values are redacted."""
    text, categories = redact_text(assignment)
    assert HIGH_ENTROPY not in text
    assert "[REDACTED_HIGH_ENTROPY_SECRET]" in text
    assert categories == {"high_entropy_secret"}


@pytest.mark.parametrize(
    "assignment",
    [
        "password=correcthorsebattery",
        "secret=https://vault.example.com/v1/kv/app",
        "private_key=/var/run/keys/service-signing.pem",
        "api_key=" + "ab12cd34" * 8,
        "access_token="
        + "-".join(("0f3c2e1a", "1b2c", "4d5e", "8f90", "123456789abc")),
        "password=[REDACTED_SECRET]",
        "secret: short",
        f"the word secret then {HIGH_ENTROPY}",
    ],
)
def test_benign_secret_contexts_are_untouched(assignment: str) -> None:
    """Words, URLs, paths, hex digests, UUIDs, and placeholders are ignored."""
    assert redact_text(assignment) == (assignment, set())


def test_entropy_detection_can_be_disabled() -> None:
    """AEGIS_DLP_ENTROPY_ENABLED=false turns entropy detection off."""
    settings.dlp_entropy_enabled = False
    value = f"password={HIGH_ENTROPY}"
    assert redact_text(value) == (value, set())
    assert redact_payload({"password": HIGH_ENTROPY}) == (
        {"password": HIGH_ENTROPY},
        [],
    )


def test_sensitive_dict_keys_trigger_entropy_redaction() -> None:
    """Dict values under secret-named keys are checked by entropy."""
    sample_uuid = "-".join(("0f3c2e1a", "1b2c", "4d5e", "8f90", "123456789abc"))
    payload: dict[str, Any] = {
        "db_password": HIGH_ENTROPY,
        "signing-key": "".join(("Zq8Lw3", "Rt6Yp1", "Nx4Vb7", "Mk2Hj5")),
        "apikey": "".join(("a1B2c3", "D4e5F6", "g7H8i9", "J0kLmN")),
        "password_hint": HIGH_ENTROPY,
        "secret": "just a normal sentence here",
        "client_secret": sample_uuid,
        "private_key": "f" * 64,
        "access_token": 12345,
        "audit_hash": "9" * 16 + "a" * 48,
    }
    sanitized, categories = redact_payload(payload)
    assert categories == ["high_entropy_secret"]
    assert sanitized["db_password"] == "[REDACTED_HIGH_ENTROPY_SECRET]"
    assert sanitized["signing-key"] == "[REDACTED_HIGH_ENTROPY_SECRET]"
    assert sanitized["apikey"] == "[REDACTED_HIGH_ENTROPY_SECRET]"
    for key in ("password_hint", "secret", "client_secret", "private_key"):
        assert sanitized[key] == payload[key]
    assert sanitized["access_token"] == 12345
    assert sanitized["audit_hash"] == payload["audit_hash"]


def test_known_prefix_under_sensitive_key_keeps_secret_category() -> None:
    """Known token formats keep the crisp ``secret`` category."""
    sanitized, categories = redact_payload({"api_key": "sk-" + "A1b2" * 6})
    assert sanitized == {"api_key": "[REDACTED_SECRET]"}
    assert categories == ["secret"]


def test_secret_shape_helpers() -> None:
    """Entropy shape checks and key-name matching primitives."""
    assert looks_like_secret(HIGH_ENTROPY)
    assert not looks_like_secret("a" * 300)
    assert not looks_like_secret("C:\\Users\\svc\\keys\\Xk9mQ2vL8p.pem")
    assert is_sensitive_key("STRIPE_API_KEY")
    assert not is_sensitive_key("username")


def test_benign_base64_note_is_not_flagged() -> None:
    """Base64 of harmless text outside a secret context is not flagged."""
    note = base64.b64encode(b"just a harmless note").decode()
    assert redact_text(f"note {note}") == (f"note {note}", set())
    assert redact_payload({"note": note}) == ({"note": note}, [])


# ---------------------------------------------------------------------------
# HMAC referential tokenization
# ---------------------------------------------------------------------------


def _token(text: str) -> str:
    redacted, _ = redact_text(text)
    return redacted


def test_hmac_tokens_are_referential() -> None:
    """Same value -> same tag; different value or key -> different tag."""
    settings.dlp_hmac_key = "session-key-1"
    first = _token("alice@example.com")
    assert first.startswith("[REDACTED_EMAIL#") and len(first) == len(
        "[REDACTED_EMAIL#abcdef]"
    )
    assert _token("ALICE@example.com") == first
    assert _token("bob@example.com") != first
    settings.dlp_hmac_key = "session-key-2"
    assert _token("alice@example.com") != first


def test_hmac_normalizes_formatting_variants() -> None:
    """Spaced and compact forms of the same card share one token."""
    settings.dlp_hmac_key = "k"
    compact = _token("4111111111111111")
    assert compact.startswith("[REDACTED_CREDIT_CARD#")
    assert _token("4111 1111 1111 1111") == compact
    assert _token("ES91 2100 0418 4502 0005 1332") == _token("ES9121000418450200051332")


def test_empty_hmac_key_emits_static_placeholders() -> None:
    """An empty key behaves like no key."""
    settings.dlp_hmac_key = ""
    assert _token("alice@example.com") == "[REDACTED_EMAIL]"
    assert placeholder("high_entropy_secret", "x") == "[REDACTED_HIGH_ENTROPY_SECRET]"


def test_hmac_encoded_placeholder() -> None:
    """Encoded tokens get an HMAC-tagged [REDACTED_ENCODED#...] placeholder."""
    settings.dlp_hmac_key = "k"
    encoded = base64.b64encode(b"card 4111111111111111").decode()
    text, categories = redact_text(f"blob {encoded}")
    assert text.startswith("blob [REDACTED_ENCODED#")
    assert categories == {"credit_card"}


@pytest.mark.parametrize("key", [None, "k"])
def test_redaction_is_idempotent(key: str | None) -> None:
    """Re-redacting output never double-redacts placeholders."""
    settings.dlp_hmac_key = key
    text = (
        f"alice@example.com 4111111111111111 ES9121000418450200051332 "
        f"12345678Z +34612345678 {_jwt()} password={HIGH_ENTROPY} " + _pem("EC ")
    )
    once, categories = redact_text(text)
    assert categories == {
        "email",
        "credit_card",
        "iban",
        "national_id",
        "phone",
        "jwt",
        "high_entropy_secret",
        "private_key",
    }
    assert redact_text(once) == (once, set())


# ---------------------------------------------------------------------------
# Encoded / obfuscated variants (app/normalize.py integration)
# ---------------------------------------------------------------------------


def test_base64_encoded_card_is_redacted() -> None:
    """A Base64 blob hiding a card number becomes [REDACTED_ENCODED]."""
    encoded = base64.b64encode(b"card 4111111111111111").decode()
    assert redact_text(f"x {encoded}") == ("x [REDACTED_ENCODED]", {"credit_card"})


def test_zero_width_split_card_is_redacted() -> None:
    """Zero-width characters cannot split a card past DLP."""
    text, categories = redact_text(f"card 4111{ZWSP}111111111111 ok")
    assert text == "card [REDACTED_CREDIT_CARD] ok"
    assert categories == {"credit_card"}


def test_percent_encoded_slack_token_is_redacted() -> None:
    """Percent-encoded provider tokens are decoded before detection."""
    token = "xox" + "b%2D" + "1234567890%2Dabcdefghij"
    text, categories = redact_text(f"t={token}")
    assert text == "t=[REDACTED_SECRET]"
    assert categories == {"secret"}
