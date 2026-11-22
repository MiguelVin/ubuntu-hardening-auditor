"""Self-contained HTML report (one file, no internet needed to open it)."""

from __future__ import annotations

from jinja2 import Environment, PackageLoader

from hardaudit.reports.data import mitre_url
from hardaudit.score import grade

# autoescape=True: text from the audited system (file names, log lines) is
# escaped, so a file named "<script>..." cannot inject code into the report.
_env = Environment(loader=PackageLoader("hardaudit", "reports/templates"), autoescape=True)
_env.filters["mitre_url"] = mitre_url


# Terminal colour of the grade -> CSS variable used by the score ring.
_RING_COLOUR = {"green": "pass", "yellow": "skip", "dark_orange": "high", "red": "fail"}


def render_html(report: dict) -> str:
    _, colour = grade(report["score"])
    ring = _RING_COLOUR.get(colour, "muted")
    return _env.get_template("report.html.j2").render(report=report, ring_colour=ring)
