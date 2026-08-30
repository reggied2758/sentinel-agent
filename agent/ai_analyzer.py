import json

from openai import OpenAI
from openai import APIError, RateLimitError, APITimeoutError

from scanner.finding import SecurityFinding


client = OpenAI()


def analyze_finding(finding: SecurityFinding):
    prompt = f"""
You are a cybersecurity analyst.

Analyze this security finding:

Tool: {finding.tool}
Rule: {finding.rule}
Severity: {finding.severity}
File: {finding.file}
Line: {finding.line}
Message: {finding.message}
CWE: {finding.cwe}

Return ONLY valid JSON in this exact structure:

{{
    "risk": "short risk name",
    "explanation": "what the vulnerability means",
    "impact": "what could happen if exploited",
    "recommendation": "how to fix it"
}}
"""

    try:
        response = client.responses.create(
            model="gpt-5.6-luna",
            input=prompt
        )

        text = response.output_text

        try:
            return json.loads(text)

        except json.JSONDecodeError:
            return {
                "risk": finding.rule,
                "explanation": text,
                "impact": "",
                "recommendation": ""
            }

    except RateLimitError:
        return {
            "risk": finding.rule,
            "explanation": "AI analysis unavailable because the API rate or credit limit was reached.",
            "impact": "",
            "recommendation": "Review the scanner finding manually and check your OpenAI API billing and usage."
        }

    except APITimeoutError:
        return {
            "risk": finding.rule,
            "explanation": "AI analysis timed out.",
            "impact": "",
            "recommendation": "Review the scanner finding manually and retry the analysis."
        }

    except APIError as error:
        return {
            "risk": finding.rule,
            "explanation": f"AI analysis failed: {error}",
            "impact": "",
            "recommendation": "Review the scanner finding manually and retry the analysis."
        }

    except Exception as error:
        return {
            "risk": finding.rule,
            "explanation": f"Unexpected AI analysis error: {error}",
            "impact": "",
            "recommendation": "Review the scanner finding manually and retry the analysis."
        }