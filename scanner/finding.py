from dataclasses import dataclass
import hashlib


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

    @property
    def finding_id(self):
        value = "|".join(
            [
                self.tool,
                self.rule,
                self.file,
                str(self.line),
                self.message,
            ]
        )

        digest = hashlib.sha256(
            value.encode("utf-8")
        ).hexdigest()[:8]

        return f"SNT-{digest.upper()}"