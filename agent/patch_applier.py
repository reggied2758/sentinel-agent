from pathlib import Path
import subprocess

from agent.patch_validator import validate_patch


def _normalize_patch_paths(patch, target):
    """
    Convert absolute paths inside the target directory
    into paths relative to the target.

    This prevents spaces in absolute paths from confusing
    the patch command.
    """

    target_path = Path(target).resolve()
    normalized_lines = []

    for line in patch.splitlines():
        if line.startswith("--- ") or line.startswith("+++ "):
            prefix = line[:4]
            file_name = line[4:].strip()

            if file_name in {
                "/dev/null",
                "dev/null",
            }:
                normalized_lines.append(line)
                continue

            if file_name.startswith("a/") or file_name.startswith("b/"):
                prefix_path = file_name[:2]
                actual_path = file_name[2:]
            else:
                prefix_path = ""
                actual_path = file_name

            file_path = Path(actual_path)

            if file_path.is_absolute():
                try:
                    relative_path = file_path.resolve().relative_to(
                        target_path
                    )
                except ValueError:
                    normalized_lines.append(line)
                    continue

                actual_path = str(relative_path)

            if prefix_path:
                actual_path = prefix_path + actual_path

            normalized_lines.append(
                prefix + actual_path
            )
        else:
            normalized_lines.append(line)

    return "\n".join(normalized_lines) + "\n"


def dry_run_patch(patch, target):
    """
    Validate a patch and test whether it can be applied.

    This function NEVER modifies files.
    """

    if not patch or not patch.strip():
        return {
            "valid": False,
            "applied": False,
            "errors": [
                "Patch is empty."
            ],
        }

    target_path = Path(target).resolve()

    if not target_path.exists():
        return {
            "valid": False,
            "applied": False,
            "errors": [
                f"Target does not exist: {target}"
            ],
        }

    if not target_path.is_dir():
        return {
            "valid": False,
            "applied": False,
            "errors": [
                f"Target is not a directory: {target}"
            ],
        }

    validation = validate_patch(
        patch,
        target,
    )

    if not validation["valid"]:
        return {
            "valid": False,
            "applied": False,
            "errors": [
                "Patch validation failed.",
                *validation["errors"],
            ],
        }

    normalized_patch = _normalize_patch_paths(
        patch,
        target,
    )

    try:
        result = subprocess.run(
            [
                "patch",
                "-p0",
                "--dry-run",
            ],
            input=normalized_patch,
            capture_output=True,
            text=True,
            cwd=target_path,
        )
    except OSError as error:
        return {
            "valid": False,
            "applied": False,
            "errors": [
                f"Unable to run patch command: {error}"
            ],
        }

    if result.returncode != 0:
        return {
            "valid": False,
            "applied": False,
            "errors": [
                "Patch dry-run failed.",
                result.stderr.strip()
                or result.stdout.strip()
                or "Unknown patch error.",
            ],
        }

    return {
        "valid": True,
        "applied": False,
        "errors": [],
        "output": (
            result.stdout.strip()
            or "Patch dry-run completed successfully."
        ),
    }


def apply_patch(patch, target):
    """
    Apply a validated unified diff to the target directory.

    This function:

    - requires a non-empty patch
    - validates the patch before applying it
    - normalizes absolute paths safely
    - performs a dry-run before modifying files
    - applies only after the dry-run succeeds
    - keeps execution inside the target directory
    """

    dry_run_result = dry_run_patch(
        patch,
        target,
    )

    if not dry_run_result["valid"]:
        return {
            "applied": False,
            "errors": dry_run_result["errors"],
        }

    target_path = Path(target).resolve()
    normalized_patch = _normalize_patch_paths(
        patch,
        target,
    )

    try:
        result = subprocess.run(
            [
                "patch",
                "-p0",
            ],
            input=normalized_patch,
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
                or result.stdout.strip()
                or "Unknown patch error.",
            ],
        }

    return {
        "applied": True,
        "errors": [],
        "output": result.stdout.strip(),
    }