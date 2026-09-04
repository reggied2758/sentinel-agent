from pathlib import Path


def validate_patch(patch, target):
    """
    Validate a proposed unified diff before it can be applied.

    This function does NOT modify any files.
    """

    errors = []

    if not patch or not patch.strip():
        return {
            "valid": False,
            "errors": ["Patch is empty."],
        }

    target_path = Path(target).resolve()

    lines = patch.splitlines()

    has_diff_header = False
    has_target_header = False
    referenced_files = []
    hunk_count = 0

    for line in lines:
        if line.startswith("--- "):
            has_diff_header = True
            referenced_files.append(line[4:].strip())

        elif line.startswith("+++ "):
            has_target_header = True
            referenced_files.append(line[4:].strip())

        elif line.startswith("@@ "):
            hunk_count += 1

    if not has_diff_header:
        errors.append(
            "Patch does not contain a unified diff header."
        )

    if not has_target_header:
        errors.append(
            "Patch does not contain a target file."
        )

    if hunk_count == 0:
        errors.append(
            "Patch does not contain a unified diff hunk."
        )

    for file_name in referenced_files:
        if file_name in {
            "/dev/null",
            "dev/null",
        }:
            continue

        if file_name.startswith("a/") or file_name.startswith("b/"):
            file_name = file_name[2:]

        file_path = Path(file_name)

        if file_path.is_absolute():
            resolved_file = file_path.resolve()
        else:
            resolved_file = (
                target_path / file_path
            ).resolve()

        try:
            resolved_file.relative_to(target_path)
        except ValueError:
            errors.append(
                "Patch references a file outside "
                f"the target: {file_name}"
            )

    return {
        "valid": len(errors) == 0,
        "errors": errors,
    }
