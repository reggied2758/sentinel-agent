from pathlib import Path

from agent.patch_applier import apply_patch


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
