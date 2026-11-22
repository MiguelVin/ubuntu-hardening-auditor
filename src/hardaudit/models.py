"""Core data types shared by checks, the runner and the reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """How bad a failed check is. The weight drives the final score."""

    CRITICAL = ("critical", 10)
    HIGH = ("high", 6)
    MEDIUM = ("medium", 3)
    LOW = ("low", 1)

    def __init__(self, label: str, weight: int) -> None:
        self.label = label
        self.weight = weight


class Status(Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"  # could not be evaluated: not applicable, or needs root
    ERROR = "error"  # unexpected error while running the check


@dataclass(frozen=True)
class CheckMeta:
    """Static description of a check."""

    id: str
    title: str
    group: str
    severity: Severity
    mitre: tuple[str, ...] = ()  # MITRE ATT&CK techniques this setting helps prevent


@dataclass
class Outcome:
    """What a check function returns: the verdict for this system."""

    status: Status
    detail: str
    remediation: list[str] = field(default_factory=list)


@dataclass
class CheckResult:
    """A check's metadata combined with its outcome."""

    meta: CheckMeta
    status: Status
    detail: str
    remediation: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.meta.id,
            "title": self.meta.title,
            "group": self.meta.group,
            "severity": self.meta.severity.label,
            "mitre": list(self.meta.mitre),
            "status": self.status.value,
            "detail": self.detail,
            "remediation": self.remediation,
        }


class SkipCheck(Exception):
    """Raised by a check when it does not apply to this system."""


def passed(detail: str) -> Outcome:
    return Outcome(Status.PASS, detail)


def failed(detail: str, remediation: list[str]) -> Outcome:
    return Outcome(Status.FAIL, detail, remediation)
