from dataclasses import dataclass


@dataclass
class SecurityFinding:
    tool: str
    rule: str
    severity: str
    file: str
    line: int
    message: str
    cwe: int | None = None
    code: str | None = None