import json

from openai import APIError, RateLimitError, APITimeoutError

from agent.ai_analyzer import get_client
from scanner.finding import SecurityFinding


def _empty_remediation(summary, explanation):
    return {
        "summary": summary,
        "explanation": explanation,
        "fixed_code": "",
        "patch": "",
        "changes": [],
        "testing": "",
    }


def _request_remediation(prompt):
    response = get_client().responses.create(
        model="gpt-5.6-luna",
        input=prompt,
    )

    text = response.output_text

    try:
        result = json.loads(text)
    except json.JSONDecodeError:
        return _empty_remediation(
            "Remediation proposal returned invalid JSON.",
            text,
        )

    return {
        "summary": result.get("summary", ""),
        "explanation": result.get("explanation", ""),
        "fixed_code": result.get("fixed_code", ""),
        "patch": result.get("patch", ""),
        "changes": result.get("changes", []),
        "testing": result.get("testing", ""),
    }


def generate_remediation(finding: SecurityFinding):
    prompt = f"""
You are a senior application security engineer.

Create a safe remediation proposal for this security finding.

Finding ID: {finding.finding_id}

Tool: {finding.tool}

Rule: {finding.rule}

Severity: {finding.severity}

File: {finding.file}

Line: {finding.line}

Message: {finding.message}

CWE: {finding.cwe}

Relevant code:
{finding.code or "No source code was provided."}

Return ONLY valid JSON in this exact structure:

{{
    "summary": "short description of the recommended fix",
    "explanation": "why the current code is vulnerable",
    "fixed_code": "the corrected code fragment",
    "patch": "a unified diff showing the proposed change",
    "changes": [
        "specific change made",
        "another specific change if needed"
    ],
    "testing": "how to verify the vulnerability is fixed"
}}

Rules:

1. Do not invent unrelated code.
2. Do not modify behavior unrelated to the security issue.
3. Prefer the smallest safe change that fixes the vulnerability.
4. The patch must be a unified diff.
5. The patch must identify the actual file:
   {finding.file}
6. The patch must show removed lines with '-' and added
   lines with '+'.
7. Do not claim that a change was applied.
8. If the available code is insufficient to safely create
   a patch, set both "fixed_code" and "patch" to empty
   strings and explain what additional context is required.
"""

    try:
        result = _request_remediation(prompt)

        if result.get("patch"):
            return result

        retry_prompt = f"""
Your previous remediation response did not contain a patch.

Generate a safe unified-diff patch for this security finding.

Finding ID: {finding.finding_id}
Tool: {finding.tool}
Rule: {finding.rule}
Severity: {finding.severity}
File: {finding.file}
Line: {finding.line}
Message: {finding.message}
CWE: {finding.cwe}

Relevant code:
{finding.code or "No source code was provided."}

Return ONLY valid JSON:

{{
    "summary": "short description of the fix",
    "explanation": "why the code is vulnerable",
    "fixed_code": "corrected code fragment",
    "patch": "unified diff",
    "changes": [
        "specific change"
    ],
    "testing": "verification steps"
}}

Patch requirements:

1. Produce a unified diff if the supplied code is sufficient.
2. The patch must target this exact file:
   {finding.file}
3. Include both removed '-' lines and added '+' lines.
4. Make the smallest security-focused change possible.
5. Do not invent unrelated application behavior.
6. Do not claim the patch has already been applied.
7. If a safe patch genuinely cannot be produced from the
   supplied code, return an empty patch and explain why.
"""

        return _request_remediation(retry_prompt)

    except RateLimitError:
        return _empty_remediation(
            "AI remediation unavailable.",
            "The API rate or credit limit was reached.",
        )

    except APITimeoutError:
        return _empty_remediation(
            "AI remediation timed out.",
            "The remediation request timed out.",
        )

    except APIError as error:
        return _empty_remediation(
            "AI remediation failed.",
            f"AI analysis failed: {error}",
        )

    except Exception as error:
        return _empty_remediation(
            "Unexpected remediation error.",
            f"Unexpected AI remediation error: {error}",
        )