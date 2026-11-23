"""Anti-evasion canonicalization pipeline applied before detection rules.

Threat rules and DLP patterns are plain regular expressions, so an attacker
can evade them by encoding the payload. Every inspected text is expanded
into a bounded set of *detection views* that rules are evaluated against:

1. **Unicode folding**: Unicode tag characters (``U+E0020``-``U+E007E``, the
   "ASCII smuggling" channel) are revealed as ASCII, zero-width / bidi
   controls (Trojan Source, CVE-2021-42574) and other invisible format
   characters are stripped, the text is NFKC-normalized (fullwidth and
   compatibility forms) and common Cyrillic/Greek homoglyphs are folded to
   their Latin look-alikes.
2. **Layer decoding**: percent-encoding and HTML entities are decoded
   repeatedly until a fixed point (bounded depth).
3. **Bounded recursive decoding**: Base64 (standard and URL-safe) and hex
   tokens are decoded when the result is printable UTF-8 text, and the
   decoded text is canonicalized again, up to ``MAX_DECODE_DEPTH`` levels
   and ``MAX_DECODED_TOKENS`` successful decodes per input.

The original text is always the first view, so canonicalization only ever
adds detection coverage; it never hides a match the raw text would produce.
"""

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import unquote

MAX_DECODE_DEPTH = 3
MAX_DECODED_TOKENS = 64
MAX_VIEW_CHARS = 262_144
MIN_ENCODED_LENGTH = 10  # unpadded characters (~7 decoded bytes)
PRINTABLE_RATIO = 0.85

_TAG_BASE = 0xE0000
_TAG_PRINTABLE = range(0xE0020, 0xE007F)


def _char_class(ranges: tuple[tuple[int, int], ...]) -> re.Pattern[str]:
    """Compile a character class from inclusive code point ranges.

    Built from integers so this source file never contains the invisible or
    bidi characters it detects (Trojan Source hygiene, bandit B613).
    """
    parts = (
        re.escape(chr(low)) + ("" if low == high else "-" + re.escape(chr(high)))
        for low, high in ranges
    )
    return re.compile("[" + "".join(parts) + "]")


# Bidi embedding/override/isolate controls and implicit marks.
BIDI_RANGES: tuple[tuple[int, int], ...] = (
    (0x061C, 0x061C),
    (0x200E, 0x200F),
    (0x202A, 0x202E),
    (0x2066, 0x2069),
)
# Soft hyphen, combining grapheme joiner, Hangul/Khmer fillers, Mongolian
# selectors, zero-width characters, invisible operators, variation
# selectors, BOM, tag characters and supplementary variation selectors.
INVISIBLE_RANGES: tuple[tuple[int, int], ...] = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200D),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xE0000, 0xE007F),
    (0xE0100, 0xE01EF),
    *BIDI_RANGES,
)
INVISIBLE_PATTERN = _char_class(INVISIBLE_RANGES)
BIDI_CONTROL_PATTERN = _char_class(BIDI_RANGES)

ENCODED_TOKEN_PATTERN = re.compile(
    rf"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{{{MIN_ENCODED_LENGTH},}}={{0,2}}"
)
_HEX_TOKEN = re.compile(r"(?:[0-9A-Fa-f]{2})+")

# Latin look-alikes from the Cyrillic and Greek blocks (Unicode TR39 subset).
_CONFUSABLE_PAIRS = {
    "a": (0x0430, 0x03B1, 0x0251),
    "c": (0x0441, 0x03F2),
    "d": (0x0501,),
    "e": (0x0435, 0x03B5),
    "h": (0x04BB,),
    "i": (0x0456, 0x03B9, 0x0131),
    "j": (0x0458, 0x03F3),
    "k": (0x03BA,),
    "l": (0x04CF,),
    "o": (0x043E, 0x03BF, 0x0585),
    "p": (0x0440, 0x03C1),
    "q": (0x051B,),
    "s": (0x0455,),
    "u": (0x03C5, 0x057D),
    "v": (0x03BD,),
    "w": (0x051D,),
    "x": (0x0445, 0x03C7),
    "y": (0x0443,),
    "A": (0x0410, 0x0391),
    "B": (0x0412, 0x0392),
    "C": (0x0421,),
    "E": (0x0415, 0x0395),
    "H": (0x041D, 0x0397),
    "I": (0x0406, 0x0399),
    "J": (0x0408,),
    "K": (0x041A, 0x039A),
    "M": (0x041C, 0x039C),
    "N": (0x039D,),
    "O": (0x041E, 0x039F),
    "P": (0x0420, 0x03A1),
    "S": (0x0405,),
    "T": (0x0422, 0x03A4),
    "X": (0x0425, 0x03A7),
    "Y": (0x03A5,),
    "Z": (0x0396,),
}
CONFUSABLES: dict[int, str] = {
    codepoint: latin
    for latin, codepoints in _CONFUSABLE_PAIRS.items()
    for codepoint in codepoints
}
_TAG_TRANSLATION: dict[int, str] = {
    codepoint: chr(codepoint - _TAG_BASE) for codepoint in _TAG_PRINTABLE
}


def has_invisible(text: str) -> bool:
    """Return True if ``text`` carries invisible, bidi, or tag characters."""
    return INVISIBLE_PATTERN.search(text) is not None


def fold_unicode(text: str) -> str:
    """Reveal tag smuggling, strip invisibles, NFKC, and fold homoglyphs."""
    revealed = text.translate(_TAG_TRANSLATION)
    stripped = INVISIBLE_PATTERN.sub("", revealed)
    return unicodedata.normalize("NFKC", stripped).translate(CONFUSABLES)


def decode_layers(text: str) -> str:
    """Decode percent-encoding and HTML entities to a bounded fixed point."""
    for _ in range(MAX_DECODE_DEPTH):
        decoded = html.unescape(unquote(text))
        if decoded == text:
            break
        text = decoded
    return text


def canonicalize_text(text: str) -> str:
    """Return the folded and layer-decoded canonical form of ``text``."""
    return decode_layers(fold_unicode(text[:MAX_VIEW_CHARS]))


def _hex_bytes(token: str) -> bytes | None:
    """Decode an even-length hex token."""
    try:
        return binascii.unhexlify(token)
    except (binascii.Error, ValueError):
        return None


def _base64_bytes(token: str) -> bytes | None:
    """Decode a standard or URL-safe Base64 token (padding optional)."""
    body = token.rstrip("=").replace("-", "+").replace("_", "/")
    if len(body) % 4 == 1:
        return None
    try:
        return base64.b64decode(body + "=" * (-len(body) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def _looks_textual(text: str) -> bool:
    """Return True for non-empty text that is mostly printable."""
    if not text:
        return False
    printable = sum(1 for char in text if char.isprintable() or char in "\n\r\t")
    return printable / len(text) >= PRINTABLE_RATIO


def decode_token(token: str) -> str | None:
    """Decode a hex or Base64 token into printable UTF-8 text, else None."""
    is_hex = _HEX_TOKEN.fullmatch(token) is not None
    raw = _hex_bytes(token) if is_hex else _base64_bytes(token)
    if raw is None:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if _looks_textual(text) else None


@dataclass
class DetectionViews:
    """Distinct texts detection rules must be evaluated against.

    ``views[0]`` is always the original text. ``exhausted`` is True when the
    decode budget ran out before every encoded token could be expanded (a
    padding-based evasion signal).
    """

    views: list[str] = field(default_factory=list)
    decoded_tokens: int = 0
    exhausted: bool = False

    def add(self, text: str) -> None:
        """Append ``text`` unless it is already a view."""
        if text not in self.views:
            self.views.append(text)


def _expand(text: str, depth: int, result: DetectionViews) -> None:
    """Add the canonical view of ``text`` and recurse into encoded tokens."""
    canonical = canonicalize_text(text)
    result.add(canonical)
    if depth >= MAX_DECODE_DEPTH:
        return
    for match in ENCODED_TOKEN_PATTERN.finditer(canonical):
        decoded = decode_token(match.group())
        if decoded is None:
            continue
        if result.decoded_tokens >= MAX_DECODED_TOKENS:
            result.exhausted = True
            return
        result.decoded_tokens += 1
        result.add(decoded)
        _expand(decoded, depth + 1, result)


def detection_views(text: str) -> DetectionViews:
    """Expand ``text`` into its original, canonical, and decoded views."""
    result = DetectionViews(views=[text])
    _expand(text, 0, result)
    return result
