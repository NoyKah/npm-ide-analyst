from __future__ import annotations

from pathlib import Path

import esprima
import jsbeautifier

from ..models import Finding, Severity
from .ioc_scan import iter_js_files


def deminify(source: str) -> str:
    return jsbeautifier.beautify(source)


def _child_keys(node) -> list[str]:
    """Return the attribute names that may hold child node(s) for `node`.

    esprima-python node objects (esprima.objects.Object subclasses) implement
    a real dict-like `.keys()` that includes every attribute set on the node
    (e.g. "type", "callee", "arguments", ...). Prefer that when available;
    fall back to `vars()`/`__dict__` for node-like objects that don't expose
    `.keys()`, so traversal degrades gracefully rather than silently stopping
    at the top level.
    """
    keys_fn = getattr(node, "keys", None)
    if callable(keys_fn):
        try:
            return list(keys_fn())
        except TypeError:
            pass
    try:
        return list(vars(node).keys())
    except TypeError:
        return []


def _walk(node):
    """Yield every esprima node in the tree (depth-first, includes `node`)."""
    if isinstance(node, list):
        for item in node:
            yield from _walk(item)
        return
    if not hasattr(node, "type"):
        return
    yield node
    for key in _child_keys(node):
        if key == "type":
            continue
        yield from _walk(getattr(node, key, None))


def _callee_name(node) -> str | None:
    callee = getattr(node, "callee", None)
    if callee is None:
        return None
    if getattr(callee, "type", None) == "Identifier":
        return callee.name
    return None


def analyze_ast(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for js in iter_js_files(root):
        rel = str(js.relative_to(root))
        try:
            source = js.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            tree = esprima.parseScript(source, tolerant=True)
        except Exception:
            findings.append(Finding(
                id=f"AST-UNPARSEABLE-{rel}",
                title="JavaScript failed to parse",
                severity=Severity.INFO,
                category="obfuscation",
                detail=f"{rel} could not be parsed — often a sign of heavy obfuscation.",
                location=rel,
            ))
            continue
        for node in _walk(tree):
            if getattr(node, "type", None) != "CallExpression":
                continue
            name = _callee_name(node)
            if name in ("eval", "Function"):
                findings.append(Finding(
                    id=f"AST-DYN-{name}-{rel}",
                    title="Dynamic code execution",
                    severity=Severity.HIGH,
                    category="dynamic-code",
                    detail=f"{name}(...) call in {rel}.",
                    location=rel,
                ))
            elif name == "require":
                args = getattr(node, "arguments", [])
                if args and getattr(args[0], "type", None) != "Literal":
                    findings.append(Finding(
                        id=f"AST-DYNREQ-{rel}",
                        title="Dynamic require()",
                        severity=Severity.MEDIUM,
                        category="dynamic-require",
                        detail=f"require(<non-literal>) in {rel}.",
                        location=rel,
                    ))
    return findings
