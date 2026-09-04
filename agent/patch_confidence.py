def evaluate_patch_confidence(
    finding,
    patch,
    validation,
    dry_run_result,
):
    """
    Evaluate whether a proposed remediation patch is safe
    enough to recommend for application.

    This does not apply the patch. It only evaluates the
    evidence collected by the remediation workflow.
    """

    reasons = []
    score = 0

    # Patch exists.
    if patch and patch.strip():
        score += 1
        reasons.append(
            "A remediation patch was generated."
        )
    else:
        reasons.append(
            "No remediation patch was generated."
        )

    # Validation.
    if validation.get("valid"):
        score += 2
        reasons.append(
            "Patch structure validation passed."
        )
    else:
        reasons.append(
            "Patch structure validation failed."
        )

    # Dry-run.
    if dry_run_result.get("valid"):
        score += 3
        reasons.append(
            "Patch dry-run application passed."
        )
    else:
        reasons.append(
            "Patch dry-run application failed."
        )

    # Scope.
    changed_files = 0

    for line in patch.splitlines():
        if line.startswith("+++ "):
            changed_files += 1

    if changed_files == 1:
        score += 2
        reasons.append(
            "Patch modifies exactly one file."
        )
    elif changed_files > 1:
        reasons.append(
            f"Patch modifies {changed_files} files."
        )

    # Severity-aware recommendation.
    if score >= 7:
        confidence = "HIGH"
        recommendation = "APPLY"
    elif score >= 4:
        confidence = "MEDIUM"
        recommendation = "REVIEW"
    else:
        confidence = "LOW"
        recommendation = "DO NOT APPLY"

    return {
        "confidence": confidence,
        "recommendation": recommendation,
        "score": score,
        "reasons": reasons,
    }
