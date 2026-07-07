from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import Report, Severity

_ENV = Environment(
    loader=FileSystemLoader(str(Path(__file__).parent)),
    autoescape=select_autoescape(["html", "j2"]),
)

_DYNAMIC_LOC = "[dynamic]"


def write_html(report: Report, out_path: Path) -> None:
    # Split findings into what was read statically vs. observed during detonation,
    # and precompute the summary stats the template's masthead + stat strip show.
    static = [f for f in report.findings if f.location != _DYNAMIC_LOC]
    dynamic = [f for f in report.findings if f.location == _DYNAMIC_LOC]
    high_count = sum(
        1 for f in report.findings
        if f.severity in (Severity.HIGH, Severity.CRITICAL)
    )
    categories = sorted({f.category for f in report.findings})
    template = _ENV.get_template("template.html.j2")
    out_path.write_text(
        template.render(r=report, static=static, dynamic=dynamic,
                        high_count=high_count, categories=categories),
        encoding="utf-8",
    )
