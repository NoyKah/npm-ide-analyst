from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import Report

_ENV = Environment(
    loader=FileSystemLoader(str(Path(__file__).parent)),
    autoescape=select_autoescape(["html", "j2"]),
)


def write_html(report: Report, out_path: Path) -> None:
    template = _ENV.get_template("template.html.j2")
    out_path.write_text(template.render(r=report), encoding="utf-8")
