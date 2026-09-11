import anthropic
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    evidence: str
    remediation: str
    agent: str
    url: Optional[str] = None
    parameter: Optional[str] = None
    extra: dict = field(default_factory=dict)


class BaseAgent:
    """Base class for all pentest agents."""

    name: str = "BaseAgent"
    description: str = "Base agent"

    def __init__(self, target: str, client: anthropic.Anthropic):
        self.target = target
        self.client = client
        self.findings: list[Finding] = []

    def _ask_claude(self, system: str, user: str, max_tokens: int = 4096) -> str:
        """Call Claude Opus 5 with adaptive thinking."""
        response = self.client.messages.create(
            model="claude-opus-5",
            max_tokens=max_tokens,
            thinking={"type": "adaptive"},
            output_config={"effort": "high"},
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        for block in response.content:
            if block.type == "text":
                return block.text
        return ""

    def _add_finding(
        self,
        title: str,
        severity: Severity,
        description: str,
        evidence: str,
        remediation: str,
        url: Optional[str] = None,
        parameter: Optional[str] = None,
        extra: Optional[dict] = None,
    ):
        self.findings.append(
            Finding(
                title=title,
                severity=severity,
                description=description,
                evidence=evidence,
                remediation=remediation,
                agent=self.name,
                url=url,
                parameter=parameter,
                extra=extra or {},
            )
        )

    async def run(self) -> list[Finding]:
        raise NotImplementedError
