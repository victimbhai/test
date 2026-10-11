"""Diff generation and security-relevant change indicators.

Two capabilities live here:

1. **Diffs** — a structured, renderer-agnostic diff of two JavaScript
   versions (replaces the original ``difflib.HtmlDiff`` HTML file that was
   attached to notifications). The dashboard renders this as Monaco line
   decorations; notifications carry a text summary plus a link.
2. **Review indicators** — patterns that are worth a human look in changed
   JavaScript. These are explicitly *review indicators*, never confirmed
   vulnerabilities.

Beautification is display-only: hashing always uses the original bytes.
"""

from __future__ import annotations

import difflib
import math
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

# ---------------------------------------------------------------------------
# Review indicators
# ---------------------------------------------------------------------------

@dataclass
class Indicator:
    """A single security-relevant finding inside a changed file."""

    category: str
    label: str
    severity: str  # "high" | "medium" | "low"
    line_number: int
    match: str
    context: str = ""

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "label": self.label,
            "severity": self.severity,
            "line_number": self.line_number,
            "match": self.match[:200],
            "context": self.context[:400],
        }


@dataclass(frozen=True)
class IndicatorRule:
    name: str
    category: str
    severity: str
    pattern: re.Pattern


def _rule(name: str, category: str, severity: str, pattern: str, flags=re.IGNORECASE) -> IndicatorRule:
    return IndicatorRule(name, category, severity, re.compile(pattern, flags))


INDICATOR_RULES: tuple[IndicatorRule, ...] = (
    # --- endpoints / routes ------------------------------------------------
    _rule("api_path", "Endpoint", "high",
          r"""["'`](?:/)?(?:api|v\d|rest|graphql)/[A-Za-z0-9_\-./{}]{2,80}["'`]"""),
    _rule("graphql_endpoint", "Endpoint", "high",
          r"""(?:https?://[^\s"'`]+)?/graphql(?:\?[^\s"'`]*)?["'`]?"""),
    _rule("websocket", "Endpoint", "high",
          r"""wss?://[A-Za-z0-9._\-:/?&=%]{4,120}"""),
    _rule("route_definition", "Route", "medium",
          r"""(?:path|route|url|endpoint)\s*[:=]\s*["'`]/[A-Za-z0-9_\-./{}]{2,80}["'`]"""),
    _rule("http_verb_call", "Endpoint", "low",
          r"""\.(?:get|post|put|patch|delete|head|options)\s*\(\s*["'`]/[A-Za-z0-9_\-./{}]{2,80}["'`]"""),

    # --- auth / authorization ---------------------------------------------
    _rule("auth_header", "Authentication", "high",
          r"""(?:authorization|auth[-_]?token|x[-_]?api[-_]?key|bearer)\s*[:=]\s*["'`][^"'`]{4,}["'`]"""),
    _rule("auth_function", "Authentication", "medium",
          r"""\b(?:login|logout|signIn|signOut|authenticate|refreshToken|getToken|isAuthenticated|hasRole|checkPermission|requireAuth|authorize)\s*\("""),
    _rule("cookie_handling", "Authentication", "medium",
          r"""(?:document\s*\.\s*cookie|setCookie|getCookie|withCredentials\s*:\s*true)"""),
    _rule("jwt", "Authentication", "high",
          r"""eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}"""),
    _rule("password_field", "Authentication", "medium",
          r"""(?:password|passwd|pwd|secret|credential)s?\s*[:=]\s*["'`][^"'`]{3,}["'`]"""),

    # --- debug / feature flags --------------------------------------------
    _rule("debug_flag", "Debug", "medium",
          r"""["'`]?(?:debug|verbose|trace|devMode|developmentMode|__DEV__|isDebug|DEBUG_MODE)["'`]?\s*[:=]\s*(?:true|!0|1)\b"""),
    _rule("feature_flag", "Feature flag", "medium",
          r"""(?:featureFlag|feature_flag|flags?\.|enableFeature|isFeatureEnabled|toggle)\s*[.(]?\s*["'`][A-Za-z0-9_\-.]{3,48}["'`]"""),
    _rule("admin_reference", "Authorization", "high",
          r"""["'`](?:/[A-Za-z0-9_\-.]*)?(?:admin|internal|superuser|staff|backoffice)[A-Za-z0-9_\-./]*["'`]"""),

    # --- secrets / credentials --------------------------------------------
    _rule("cloud_key", "Credential", "high",
          r"""(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})"""),
    _rule("google_key", "Credential", "medium",
          r"""AIza[0-9A-Za-z_\-]{35}"""),
    _rule("slack_token", "Credential", "high",
          r"""xox[baprs]-[0-9A-Za-z\-]{10,}"""),
    _rule("github_token", "Credential", "high",
          r"""gh[pousr]_[0-9A-Za-z]{20,}"""),
    _rule("private_key", "Credential", "high",
          r"""-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY"""),
    _rule("generic_secret", "Credential", "high",
          r"""(?:api[-_]?key|api[-_]?secret|client[-_]?secret|access[-_]?token|private[-_]?token|secret[-_]?key)\s*[:=]\s*["'`][A-Za-z0-9_\-./+=]{12,}["'`]"""),
    _rule("sk_key", "Credential", "high",
          r"""\b(?:sk|pk|rk|api|tok|key|secret)[_-]?(?:live|test|prod|public|private)?[_-]?[A-Za-z0-9]{16,}\b"""),
    _rule("env_leak", "Credential", "medium",
          r"""["'`](?:[A-Z][A-Z0-9_]*_(?:KEY|TOKEN|SECRET|PASSWORD|PASS|CREDENTIALS?))["'`]\s*[:=]"""),

    # --- source maps / dependencies ---------------------------------------
    _rule("source_map", "Source map", "medium",
          r"""//[#@]\s*sourceMappingURL\s*=\s*([^\s"'`]+)"""),
    _rule("dependency_cdn", "Dependency", "low",
          r"""["'`](?:https?:)?//[A-Za-z0-9._\-]+/[^\s"'`]*?(?:jquery|react|vue|angular|lodash|bootstrap|moment|axios)[^\s"'`]*\.js["'`]"""),

    # --- storage / transport ----------------------------------------------
    _rule("local_storage", "Data handling", "low",
          r"""(?:localStorage|sessionStorage)\s*\.\s*(?:set|get)Item\s*\(\s*["'`][^"'`]{3,}["'`]"""),
    _rule("postmessage", "Data handling", "medium",
          r"""\.postMessage\s*\(\s*[^,]{1,200},\s*["'`]\*["'`]"""),
    _rule("insecure_http", "Data handling", "medium",
          r"""["'`]http://(?!localhost|127\.)[A-Za-z0-9._\-]{4,}[^\s"'`]*["'`]"""),
    _rule("eval_usage", "Dangerous API", "high",
          r"""\b(?:eval|new\s+Function|document\s*\.\s*write)\s*\("""),
    _rule("inner_html", "Dangerous API", "medium",
          r"""\.innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML\s*\("""),
)

# Only added lines are scanned for indicators, so every finding is new.


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


# A quoted string of this length or longer is entropy-checked.
_ENTROPY_MIN_LENGTH = 24
_ENTROPY_THRESHOLD = 3.6
_QUOTED_STRING = re.compile(r"""["'`]([A-Za-z0-9_\-]{24,})["'`]""")


def _entropy_indicator(line: str, line_number: int) -> Indicator | None:
    """Flag quoted strings that look like generated credentials.

    Catches high-entropy tokens assigned to non-obvious names
    (``token = "sk_live_..."``) that name-based rules miss.
    """
    for match in _QUOTED_STRING.finditer(line):
        candidate = match.group(1)
        # Skip anything that is obviously not a secret.
        if candidate.lower() in _ENTROPY_SKIPLIST:
            continue
        if not any(c.isdigit() for c in candidate):
            continue
        if not any(c.isalpha() for c in candidate):
            continue
        if len(set(candidate)) < 12:
            continue
        if shannon_entropy(candidate) >= _ENTROPY_THRESHOLD:
            return Indicator(
                category="Credential",
                label="High Entropy String",
                severity="high",
                line_number=line_number,
                match=match.group(0),
                context=line.strip()[:300],
            )
    return None


_ENTROPY_SKIPLIST = {
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789abcdefghijklmnop",
    "application/javascript",
    "text/javascript",
    "utf-8",
}


def scan_indicators(
    old_text: str,
    new_text: str,
    *,
    max_results: int = 100,
) -> list[Indicator]:
    """Scan only the *added* lines of a change for review indicators."""
    old_lines = old_text.splitlines()
    new_lines = new_text.splitlines()

    previous = set(old_lines)
    added = [line for line in new_lines if line not in previous]

    found: list[Indicator] = []
    seen: set[tuple] = set()

    for idx, line in enumerate(added, start=1):
        for rule in INDICATOR_RULES:
            match = rule.pattern.search(line)
            if not match:
                continue
            key = (rule.name, match.group(0)[:80])
            if key in seen:
                continue
            seen.add(key)
            found.append(
                Indicator(
                    category=rule.category,
                    label=rule.name.replace("_", " ").title(),
                    severity=rule.severity,
                    line_number=idx,
                    match=match.group(0),
                    context=line.strip()[:300],
                )
            )
            if len(found) >= max_results:
                return found

        entropy_hit = _entropy_indicator(line, idx)
        if entropy_hit is not None:
            key = ("High Entropy String", entropy_hit.match[:80])
            if key not in seen:
                seen.add(key)
                found.append(entropy_hit)
                if len(found) >= max_results:
                    return found

    return found


def summarize_indicators(indicators: Iterable[Indicator]) -> dict:
    """Aggregate indicators into per-category / per-severity counts."""
    by_category: dict[str, int] = {}
    by_severity: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    total = 0
    for ind in indicators:
        total += 1
        by_category[ind.category] = by_category.get(ind.category, 0) + 1
        if ind.severity in by_severity:
            by_severity[ind.severity] += 1
    return {"total": total, "by_category": by_category, "by_severity": by_severity}


# ---------------------------------------------------------------------------
# Diff generation
# ---------------------------------------------------------------------------

@dataclass
class DiffHunk:
    """A contiguous block of changes with surrounding context."""

    old_start: int
    old_lines: list[str]
    new_start: int
    new_lines: list[str]


@dataclass
class DiffResult:
    """A renderer-agnostic diff between two file versions."""

    unified: str
    hunks: list[DiffHunk] = field(default_factory=list)
    added_lines: int = 0
    removed_lines: int = 0
    indicators: list[Indicator] = field(default_factory=list)
    truncated: bool = False
    old_lines: int = 0
    new_lines: int = 0
    context_lines: int = 3
    max_lines: int = 0

    def to_dict(self) -> dict:
        return {
            "unified": self.unified,
            "hunks": [
                {
                    "old_start": h.old_start,
                    "old_lines": h.old_lines,
                    "new_start": h.new_start,
                    "new_lines": h.new_lines,
                }
                for h in self.hunks
            ],
            "added_lines": self.added_lines,
            "removed_lines": self.removed_lines,
            "old_lines": self.old_lines,
            "new_lines": self.new_lines,
            "truncated": self.truncated,
            "context_lines": self.context_lines,
            "indicators": [i.to_dict() for i in self.indicators],
        }

    @property
    def is_identical(self) -> bool:
        return self.added_lines == 0 and self.removed_lines == 0


def _decode(data: bytes) -> str:
    """Decode downloaded bytes as text without ever raising."""
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def build_diff(
    old_bytes: Optional[bytes],
    new_bytes: bytes,
    *,
    context_lines: int = 3,
    max_lines: int = 20000,
    scan_indicators_enabled: bool = True,
) -> DiffResult:
    """Create a unified diff of two JavaScript versions."""
    old_text = _decode(old_bytes) if old_bytes is not None else ""
    new_text = _decode(new_bytes)

    old_lines = old_text.splitlines()
    new_lines = new_text.splitlines()

    diff_gen = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile="previous",
        tofile="current",
        lineterm="",
        n=context_lines,
    )
    unified = "\n".join(diff_gen)

    hunks = _extract_hunks(old_lines, new_lines, context_lines)
    added = sum(
        1 for line in unified.splitlines() if line.startswith("+") and not line.startswith("+++")
    )
    removed = sum(
        1 for line in unified.splitlines() if line.startswith("-") and not line.startswith("---")
    )

    truncated = False
    if len(unified.splitlines()) > max_lines:
        kept = "\n".join(unified.splitlines()[:max_lines])
        unified = kept + "\n... (diff truncated)"
        truncated = True

    indicators: list[Indicator] = []
    if scan_indicators_enabled:
        indicators = scan_indicators(old_text, new_text)

    return DiffResult(
        unified=unified,
        hunks=hunks,
        added_lines=added,
        removed_lines=removed,
        indicators=indicators,
        truncated=truncated,
        old_lines=len(old_lines),
        new_lines=len(new_lines),
        context_lines=context_lines,
        max_lines=max_lines,
    )


def _extract_hunks(
    old_lines: list[str], new_lines: list[str], context: int
) -> list[DiffHunk]:
    """Group the SequenceMatcher opcodes into human-sized hunks."""
    matcher = difflib.SequenceMatcher(a=old_lines, b=new_lines, autojunk=False)
    opcodes = matcher.get_opcodes()
    hunks: list[DiffHunk] = []
    for tag, i1, i2, j1, j2 in opcodes:
        if tag == "equal":
            continue
        start_old = max(0, i1 - context)
        end_old = min(len(old_lines), i2 + context)
        start_new = max(0, j1 - context)
        end_new = min(len(new_lines), j2 + context)
        hunks.append(
            DiffHunk(
                old_start=start_old + 1,
                old_lines=old_lines[start_old:end_old],
                new_start=start_new + 1,
                new_lines=new_lines[start_new:end_new],
            )
        )
    return hunks


# ---------------------------------------------------------------------------
# Beautification (display only)
# ---------------------------------------------------------------------------

def beautify(text: str, *, indent: int = 2) -> str:
    """Lightweight JS beautifier used for display purposes only.

    jsbeautifier is an optional dependency; when it is unavailable we fall
    back to a simple newline splitter so the dashboard still renders
    something readable. Hashing is never affected by this function.
    """
    try:
        import jsbeautifier  # type: ignore

        opts = {
            "indent_size": indent,
            "indent_with_tabs": False,
            "keep_function_indentation": False,
            "preserve_newlines": True,
            "max_preserve_newlines": 2,
        }
        return jsbeautifier.beautify(text, opts)
    except Exception:
        # Fallback: put each statement-ish segment on its own line.
        return re.sub(r";\s*", ";\n", text)


def change_summary(diff: DiffResult, old_size: int, new_size: int) -> dict:
    """Compact summary stored on a change event."""
    summary = summarize_indicators(diff.indicators)
    delta = new_size - old_size
    pct = 0.0
    if old_size:
        pct = round((delta / old_size) * 100, 2)
    return {
        "added_lines": diff.added_lines,
        "removed_lines": diff.removed_lines,
        "size_delta_bytes": delta,
        "size_delta_percent": pct,
        "indicator_summary": summary,
        "truncated": diff.truncated,
    }
