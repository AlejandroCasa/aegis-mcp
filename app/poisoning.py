"""Tool poisoning and cross-server shadowing scanner for MCP definitions.

MCP clients paste server ``instructions`` and every tool, prompt, and
resource definition (descriptions, JSON Schemas, parameter names) straight
into the model context, so a malicious server can hide instructions there
("tool poisoning") or steer how the model uses *other* servers' tools
("shadowing"). This module scans those definitions statically:

* **Text rules** run on every detection view of every string, including
  JSON Schema property names (``app/normalize.py``: Unicode folding,
  percent/HTML and recursive Base64/hex decoding). Rules cover hidden
  instruction tags, concealment from the user, instruction overrides,
  sensitive file access, credential exfiltration, and pre-emptive
  invocation directives. A match only visible after decoding also reports
  ``obfuscated_content``.
* **Unicode smuggling**: bidi controls and tag characters are critical;
  other invisible characters are suspicious.
* **Schema rules**: parameters designed to siphon context or secrets
  (``sidenote``, ``conversation_history``, ``private_key`` ...).
* **Cross-server rules**: a tool name exposed by several servers
  (``tool_name_collision``) and descriptions referencing another server's
  distinctive tool names (``cross_server_reference``).

Scores follow the firewall scale: >= 90 critical, >= 70 high (blocks at the
default threshold), >= 40 medium, otherwise low.
"""

import functools
import json
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Literal

from app.normalize import (
    BIDI_CONTROL_PATTERN,
    detection_views,
    fold_unicode,
    has_invisible,
)
from app.redactor import redact_text

POISONING_VIOLATION = "tool_poisoning"
MAX_SCAN_DEPTH = 32
MAX_SCAN_STRINGS = 10_000
MAX_DESCRIPTION_CHARS = 4096
EVIDENCE_RADIUS = 40

Severity = Literal["low", "medium", "high", "critical"]
SEVERITY_ORDER: dict[Severity, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_I = re.IGNORECASE
TEXT_RULES: tuple[tuple[str, int, re.Pattern[str]], ...] = (
    (
        "hidden_instruction_tag",
        90,
        re.compile(
            r"<\s*/?\s*(?:important|system|instructions?|secret|hidden|admin)\b"
            r"[^>]{0,64}>",
            _I,
        ),
    ),
    (
        "concealment_directive",
        90,
        re.compile(
            r"(?:\b(?:do\s+not|don'?t|never)\s+(?:tell|mention|inform|reveal|"
            r"show|notify|alert)\b[^.\n]{0,40}\b(?:user|human|operator)s?\b)|"
            r"(?:\bwithout\s+(?:the\s+)?(?:user|human)(?:'s)?\s+"
            r"(?:knowing|knowledge|noticing|consent)\b)|"
            r"(?:\b(?:secretly|covertly|surreptitiously)\b)",
            _I,
        ),
    ),
    (
        "instruction_override",
        90,
        re.compile(
            r"\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:the\s+)?"
            r"(?:previous|prior|above|earlier|other|system)\s+"
            r"(?:instructions|rules|directions|prompts?)\b|"
            r"\boverride\s+(?:the\s+)?(?:system|security|safety)\b",
            _I,
        ),
    ),
    (
        "sensitive_file_access",
        85,
        re.compile(
            r"~/[.]ssh\b|\bid_(?:rsa|ed25519|ecdsa)\b|[.]aws/credentials|"
            r"[.]npmrc\b|[.]netrc\b|[.]git-credentials|\bmcp[.]json\b|"
            r"claude_desktop_config|/etc/(?:passwd|shadow)\b|(?<![\w-])[.]env\b",
            _I,
        ),
    ),
    (
        "exfiltration_directive",
        75,
        re.compile(
            r"\b(?:send|forward|upload|post|transmit|exfiltrate|leak|include|"
            r"pass|append|embed)\b[^.\n]{0,60}\b(?:credentials?|secrets?|"
            r"passwords?|private\s+keys?|api[\s_-]?keys?|access\s+tokens?|"
            r"conversation(?:\s+history)?|chat\s+history|system\s+prompt)\b",
            _I,
        ),
    ),
    (
        "preemptive_invocation",
        70,
        re.compile(
            r"\bbefore\s+(?:using|calling|invoking|running)\s+(?:this|any|the)\b"
            r"[^.\n]{0,60}\b(?:must|always|first)\b|\bmust\s+(?:always\s+)?first\b",
            _I,
        ),
    ),
)

SUSPICIOUS_PARAMETERS = re.compile(
    r"^(?:side_?note|notes?_for_(?:the_)?(?:model|assistant)|system_?prompt|"
    r"(?:conversation|chat)_?history|previous_?messages|context_?dump|"
    r"ssh_?key|private_?key|credentials?|passwords?|api_?key|secret)$",
    _I,
)
DISTINCTIVE_NAME = re.compile(r"[_.\-]|[a-z][A-Z]|\d")


def severity_for(score: int) -> Severity:
    """Map a 0-100 risk score onto a severity label."""
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    return "medium" if score >= 40 else "low"


@dataclass(frozen=True)
class Finding:
    """One poisoning indicator in a server, tool, prompt, or resource."""

    server: str
    kind: str
    name: str
    rule: str
    score: int
    location: str
    evidence: str

    @property
    def severity(self) -> Severity:
        """Severity derived from the score."""
        return severity_for(self.score)

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "server": self.server,
            "kind": self.kind,
            "name": self.name,
            "rule": self.rule,
            "score": self.score,
            "severity": self.severity,
            "location": self.location,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class ScanReport:
    """All findings of a scan with the aggregate risk score."""

    findings: tuple[Finding, ...]

    @property
    def risk_score(self) -> int:
        """Highest finding score (0 when clean)."""
        return max((finding.score for finding in self.findings), default=0)

    def at_least(self, severity: Severity) -> list[Finding]:
        """Findings whose severity is ``severity`` or worse."""
        floor = SEVERITY_ORDER[severity]
        return [f for f in self.findings if SEVERITY_ORDER[f.severity] >= floor]


@dataclass(frozen=True)
class _Hit:
    """A rule hit inside one string before it is bound to a definition."""

    rule: str
    score: int
    evidence: str


def _evidence(text: str, start: int = 0, end: int = 0) -> str:
    """Return a short, visible, DLP-redacted snippet around a match."""
    begin = max(0, start - EVIDENCE_RADIUS)
    snippet = fold_unicode(text[begin : end + EVIDENCE_RADIUS])
    return redact_text(" ".join(snippet.split()))[0][: EVIDENCE_RADIUS * 4]


def iter_strings(
    node: Any, path: str = "", depth: int = 0
) -> Iterator[tuple[str, str]]:
    """Yield ``(location, text)`` for every string value and object key."""
    if depth > MAX_SCAN_DEPTH:
        return
    if isinstance(node, str):
        yield path or "$", node
    elif isinstance(node, dict):
        for key, value in node.items():
            child = f"{path}.{key}" if path else str(key)
            yield f"{child}#key", str(key)
            yield from iter_strings(value, child, depth + 1)
    elif isinstance(node, list):
        for index, item in enumerate(node):
            yield from iter_strings(item, f"{path}[{index}]", depth + 1)


def _unicode_hits(text: str) -> list[_Hit]:
    """Flag bidi/tag smuggling (critical) and other invisible characters."""
    if not has_invisible(text):
        return []
    smuggled = BIDI_CONTROL_PATTERN.search(text) or any(
        0xE0000 <= ord(char) <= 0xE007F for char in text
    )
    if smuggled:
        return [_Hit("unicode_smuggling", 90, _evidence(text))]
    return [_Hit("invisible_characters", 50, _evidence(text))]


def scan_text(text: str) -> list[_Hit]:
    """Run Unicode and text rules over every detection view of ``text``."""
    hits = _unicode_hits(text)
    views = detection_views(text).views
    obfuscated = False
    for rule, score, pattern in TEXT_RULES:
        for index, view in enumerate(views):
            match = pattern.search(view)
            if match:
                hits.append(_Hit(rule, score, _evidence(view, *match.span())))
                obfuscated = obfuscated or index > 0
                break
    if obfuscated:
        hits.append(_Hit("obfuscated_content", 80, _evidence(text)))
    return hits


def _schema_parameters(
    node: Any, path: str, depth: int = 0
) -> Iterator[tuple[str, str]]:
    """Yield ``(location, name)`` for every JSON Schema property name."""
    if depth > MAX_SCAN_DEPTH or not isinstance(node, dict):
        return
    properties = node.get("properties")
    if isinstance(properties, dict):
        for name, child in properties.items():
            location = f"{path}.properties.{name}"
            yield location, str(name)
            yield from _schema_parameters(child, location, depth + 1)
    for key in ("items", "additionalProperties"):
        yield from _schema_parameters(node.get(key), f"{path}.{key}", depth + 1)


def _definition_name(kind: str, definition: Mapping[str, Any]) -> str:
    """Return the identity of a definition for reporting."""
    key = definition.get("uri" if kind == "resource" else "name")
    return key if isinstance(key, str) and key else "<anonymous>"


class _Collector:
    """Binds hits to the definition being scanned."""

    def __init__(self, server: str, kind: str, name: str) -> None:
        self.server, self.kind, self.name = server, kind, name
        self.findings: list[Finding] = []

    def add(self, rule: str, score: int, location: str, evidence: str) -> None:
        """Record a finding unless the same rule already fired at ``location``."""
        if any(f.rule == rule and f.location == location for f in self.findings):
            return
        finding = Finding(
            self.server, self.kind, self.name, rule, score, location, evidence
        )
        self.findings.append(finding)


def _scan_strings(collector: _Collector, definition: Mapping[str, Any]) -> None:
    """Apply text rules to every string and key of a definition."""
    for count, (location, text) in enumerate(iter_strings(dict(definition))):
        if count >= MAX_SCAN_STRINGS:
            collector.add("scan_budget_exceeded", 50, location, "")
            return
        for hit in scan_text(text):
            collector.add(hit.rule, hit.score, location, hit.evidence)


def _scan_shape(collector: _Collector, definition: Mapping[str, Any]) -> None:
    """Flag oversized descriptions and context-siphoning parameters."""
    description = definition.get("description")
    if isinstance(description, str) and len(description) > MAX_DESCRIPTION_CHARS:
        evidence = f"{len(description)} characters"
        collector.add("excessive_description", 30, "description", evidence)
    for field in ("inputSchema", "arguments"):
        for location, name in _parameter_names(definition.get(field), field):
            if SUSPICIOUS_PARAMETERS.fullmatch(name):
                collector.add("suspicious_parameter", 60, location, name)


def _parameter_names(node: Any, field: str) -> Iterator[tuple[str, str]]:
    """Yield schema property names (tools) or prompt argument names."""
    if isinstance(node, list):
        for index, argument in enumerate(node):
            if isinstance(argument, dict) and isinstance(argument.get("name"), str):
                yield f"{field}[{index}].name", argument["name"]
        return
    yield from _schema_parameters(node, field)


def _scan_cross_server(
    collector: _Collector,
    definition: Mapping[str, Any],
    foreign_tools: frozenset[str],
) -> None:
    """Flag tool name collisions and references to other servers' tools."""
    if collector.kind == "tool" and collector.name in foreign_tools:
        collector.add("tool_name_collision", 60, "name", collector.name)
    texts = [text for loc, text in iter_strings(dict(definition)) if "#key" not in loc]
    corpus = "\n".join(texts)
    for foreign in sorted(foreign_tools - {collector.name}):
        if not DISTINCTIVE_NAME.search(foreign):
            continue
        pattern = re.compile(rf"(?<![\w-]){re.escape(foreign)}(?![\w-])")
        match = pattern.search(corpus)
        if match:
            evidence = _evidence(corpus, *match.span())
            collector.add("cross_server_reference", 80, "description", evidence)


def scan_definition(
    server: str,
    kind: str,
    definition: Any,
    foreign_tools: frozenset[str] = frozenset(),
) -> list[Finding]:
    """Scan one server/tool/prompt/resource definition for poisoning."""
    if not isinstance(definition, dict):
        return []
    collector = _Collector(server, kind, _definition_name(kind, definition))
    _scan_strings(collector, definition)
    _scan_shape(collector, definition)
    _scan_cross_server(collector, definition, foreign_tools)
    return collector.findings


MANIFEST_KINDS: tuple[tuple[str, str], ...] = (
    ("tools", "tool"),
    ("prompts", "prompt"),
    ("resources", "resource"),
    ("resourceTemplates", "resource"),
)


def scan_manifest(
    server: str,
    manifest: Mapping[str, Any],
    foreign_tools: frozenset[str] = frozenset(),
) -> list[Finding]:
    """Scan a server manifest (``instructions`` plus definition lists)."""
    findings: list[Finding] = []
    instructions = manifest.get("instructions")
    if isinstance(instructions, str):
        server_definition = {"name": "initialize", "instructions": instructions}
        findings.extend(scan_definition(server, "server", server_definition))
    for field, kind in MANIFEST_KINDS:
        items = manifest.get(field)
        for item in items if isinstance(items, list) else []:
            findings.extend(scan_definition(server, kind, item, foreign_tools))
    return findings


def tool_names(manifest: Mapping[str, Any]) -> frozenset[str]:
    """Return the tool names a manifest exposes."""
    tools = manifest.get("tools")
    items = tools if isinstance(tools, list) else []
    return frozenset(
        item["name"]
        for item in items
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    )


@functools.lru_cache(maxsize=4096)
def _cached_blocking_rules(
    kind: str, definition_json: str, foreign: frozenset[str], threshold: int
) -> tuple[str, ...]:
    """Memoized scan of a serialized definition (discovery repeats often)."""
    findings = scan_definition("", kind, json.loads(definition_json), foreign)
    return tuple(sorted({f.rule for f in findings if f.score >= threshold}))


def blocking_rules(
    kind: str,
    definition: Any,
    foreign_tools: frozenset[str],
    threshold: int,
) -> list[str]:
    """Return the rules scoring at least ``threshold`` for a definition."""
    if not isinstance(definition, dict):
        return []
    serialized = json.dumps(definition, sort_keys=True, default=str)
    return list(_cached_blocking_rules(kind, serialized, foreign_tools, threshold))


def scan_servers(manifests: Mapping[str, Mapping[str, Any]]) -> ScanReport:
    """Scan several servers, including cross-server shadowing checks."""
    names = {server: tool_names(manifest) for server, manifest in manifests.items()}
    findings: list[Finding] = []
    for server, manifest in manifests.items():
        foreign = frozenset().union(
            *(tools for other, tools in names.items() if other != server)
        )
        findings.extend(scan_manifest(server, manifest, foreign))
    return ScanReport(tuple(findings))
