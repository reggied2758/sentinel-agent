from agent.patch_confidence import evaluate_patch_confidence


def test_high_confidence_patch():
    finding = object()

    patch = """--- app.py
+++ app.py
@@ -1,1 +1,1 @@
-old
+new
"""

    validation = {
        "valid": True,
    }

    dry_run_result = {
        "valid": True,
    }

    result = evaluate_patch_confidence(
        finding,
        patch,
        validation,
        dry_run_result,
    )

    assert result["confidence"] == "HIGH"
    assert result["recommendation"] == "APPLY"
    assert result["score"] == 8


def test_low_confidence_patch():
    finding = object()

    result = evaluate_patch_confidence(
        finding,
        "",
        {"valid": False},
        {"valid": False},
    )

    assert result["confidence"] == "LOW"
    assert result["recommendation"] == "DO NOT APPLY"
    assert result["score"] == 0