import json
from datetime import datetime, timezone
from pathlib import Path


AUDIT_LOG_FILE = "sentinel_audit.jsonl"


def write_audit_event(
    event,
    target,
    finding=None,
    remediation=None,
    status=None,
    details=None,
):
    """
    Write one remediation event to the Sentinel audit log.

    The log uses JSON Lines format so each event is stored
    independently and can be processed later.
    """

    record = {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "event": event,
        "target": str(
            Path(target).resolve()
        ),
        "status": status,
    }

    if finding is not None:
        record["finding"] = {
            "id": finding.finding_id,
            "tool": finding.tool,
            "rule": finding.rule,
            "severity": finding.severity,
            "file": finding.file,
            "line": finding.line,
            "message": finding.message,
            "cwe": finding.cwe,
        }

    if remediation is not None:
        record["remediation"] = {
            "summary": remediation.get(
                "summary",
                "",
            ),
            "patch": remediation.get(
                "patch",
                "",
            ),
            "changes": remediation.get(
                "changes",
                [],
            ),
        }

    if details is not None:
        record["details"] = details

    with open(
        AUDIT_LOG_FILE,
        "a",
        encoding="utf-8",
    ) as file:
        file.write(
            json.dumps(
                record,
                ensure_ascii=False,
            )
            + "\n"
        )


def read_audit_events():
    """
    Read all Sentinel audit events.

    Returns an empty list when the audit log
    does not exist.
    """

    log_path = Path(
        AUDIT_LOG_FILE
    )

    if not log_path.exists():
        return []

    events = []

    with open(
        log_path,
        "r",
        encoding="utf-8",
    ) as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                events.append(
                    json.loads(line)
                )
            except json.JSONDecodeError:
                continue

    return events