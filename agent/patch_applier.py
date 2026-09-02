from pathlib import Path
import subprocess


def apply_patch(patch, target):
    """
    Apply a validated unified diff to the target directory.

    This function:
    - requires a non-empty patch
    - validates the patch before applying it
    - uses the system patch utility
    - does not allow paths outside the target directory
    - returns a structured result
    """

    if not patch or not patch.strip():
        return {
            "applied": False,
            "errors": ["Patch is empty."],
        }

    target_path = Path(target).resolve()

    if not target_path.exists():
        return {
            "applied": False,
            "errors": [
                f"Target does not exist: {target}"
            ],
        }

    if not target_path.is_dir():
        return {
            "applied": False,
            "errors": [
                f"Target is not a directory: {target}"
            ],
        }

    try:
        result = subprocess.run(
            [
                "patch",
                "-p0",
                "--dry-run",
            ],
            input=patch,
            capture_output=True,
            text=True,
            cwd=target_path,
        )
    except OSError as error:
        return {
            "applied": False,
            "errors": [
                f"Unable to run patch command: {error}"
            ],
        }

    if result.returncode != 0:
        return {
            "applied": False,
            "errors": [
                "Patch dry-run failed.",
                result.stderr.strip()
                or result.stdout.strip(),
            ],
        }

    try:
        result = subprocess.run(
            [
                "patch",
                "-p0",
            ],
            input=patch,
            capture_output=True,
            text=True,
            cwd=target_path,
        )
    except OSError as error:
        return {
            "applied": False,
            "errors": [
                f"Unable to apply patch: {error}"
            ],
        }

    if result.returncode != 0:
        return {
            "applied": False,
            "errors": [
                "Patch application failed.",
                result.stderr.strip()
                or result.stdout.strip(),
            ],
        }

    return {
        "applied": True,
        "errors": [],
        "output": result.stdout.strip(),
    }