from pathlib import Path

from agent.patch_applier import (
    apply_patch,
    dry_run_patch,
)


def test_apply_patch(tmp_path):
    app_file = tmp_path / "app.py"

    app_file.write_text(
        "def hello():\n"
        "    return 'hello'\n"
    )

    patch = """--- app.py
+++ app.py
@@ -1,2 +1,2 @@
 def hello():
-    return 'hello'
+    return 'safe'
"""

    result = apply_patch(
        patch,
        tmp_path,
    )

    assert result["applied"] is True
    assert result["errors"] == []

    assert app_file.read_text() == (
        "def hello():\n"
        "    return 'safe'\n"
    )


def test_reject_empty_patch(tmp_path):
    result = apply_patch(
        "",
        tmp_path,
    )

    assert result["applied"] is False
    assert "Patch is empty." in result["errors"]


def test_reject_invalid_patch(tmp_path):
    result = apply_patch(
        "this is not a patch",
        tmp_path,
    )

    assert result["applied"] is False
    assert result["errors"]


def test_dry_run_patch_does_not_modify_file(tmp_path):
    app_file = tmp_path / "app.py"

    original_content = (
        "def hello():\n"
        "    return 'hello'\n"
    )

    app_file.write_text(original_content)

    patch = """--- app.py
+++ app.py
@@ -1,2 +1,2 @@
 def hello():
-    return 'hello'
+    return 'safe'
"""

    result = dry_run_patch(
        patch,
        tmp_path,
    )

    assert result["valid"] is True
    assert result["applied"] is False
    assert result["errors"] == []

    assert app_file.read_text() == original_content


def test_dry_run_rejects_invalid_patch(tmp_path):
    result = dry_run_patch(
        "this is not a patch",
        tmp_path,
    )

    assert result["valid"] is False
    assert result["applied"] is False
    assert result["errors"]