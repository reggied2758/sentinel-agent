import json

from openai import APIError, RateLimitError, APITimeoutError

from agent.ai_analyzer import get_client
from scanner.finding import SecurityFinding


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
7. Do not claim that a change was applied. This is only a
   proposed patch.
8. If the available code is insufficient to safely create
   a patch, set both "fixed_code" and "patch" to empty
   strings and explain what additional context is required.
"""

    try:
        response = get_client().responses.create(
            model="gpt-5.6-luna",
            input=prompt,
        )

        text = response.output_text

        try:
            result = json.loads(text)

        except json.JSONDecodeError:
            return {
                "summary": (
                    "Remediation proposal returned "
                    "invalid JSON."
                ),
                "explanation": text,
                "fixed_code": "",
                "patch": "",
                "changes": [],
                "testing": "",
            }

        return {
            "summary": result.get(
                "summary",
                "",
            ),
            "explanation": result.get(
                "explanation",
                "",
            ),
            "fixed_code": result.get(
                "fixed_code",
                "",
            ),
            "patch": result.get(
                "patch",
                "",
            ),
            "changes": result.get(
                "changes",
                [],
            ),
            "testing": result.get(
                "testing",
                "",
            ),
        }

    except RateLimitError:
        return {
            "summary": "AI remediation unavailable.",
            "explanation": (
                "The API rate or credit limit was reached."
            ),
            "fixed_code": "",
            "patch": "",
            "changes": [],
            "testing": "",
        }

    except APITimeoutError:
        return {
            "summary": "AI remediation timed out.",
            "explanation": (
                "The remediation request timed out."
            ),
            "fixed_code": "",
            "patch": "",
            "changes": [],
            "testing": "",
        }

    except APIError as error:
        return {
            "summary": "AI remediation failed.",
            "explanation": (
                f"AI analysis failed: {error}"
            ),
            "fixed_code": "",
            "patch": "",
            "changes": [],
            "testing": "",
        }

    except Exception as error:
        return {
            "summary": "Unexpected remediation error.",
            "explanation": (
                f"Unexpected AI remediation error: {error}"
            ),
            "fixed_code": "",
            "patch": "",
            "changes": [],
            "testing": "",
        }