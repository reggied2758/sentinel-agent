from agent.patch_validator import validate_patch


def test_valid_patch():
    patch = """--- vulnerable_app/app.py
+++ vulnerable_app/app.py
@@ -16,2 +16,2 @@
-    shell=True,
+    shell=False,
"""

    result = validate_patch(patch, "vulnerable_app")

    assert result["valid"] is True
    assert result["errors"] == []


def test_empty_patch():
    result = validate_patch("", "vulnerable_app")

    assert result["valid"] is False
    assert "Patch is empty." in result["errors"]


def test_patch_outside_target():
    patch = """--- vulnerable_app/app.py
+++ ../outside.py
@@ -1,1 +1,1 @@
-old
+new
"""

    result = validate_patch(patch, "vulnerable_app")

    assert result["valid"] is False
    assert any(
        "outside the target" in error
        for error in result["errors"]
    )
