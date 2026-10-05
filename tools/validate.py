#!/usr/bin/env python3
from daclib import ValidationError, validate_project
from daclog import error, info


def main() -> int:
    info("validate", "starting project validation")
    try:
        rules = validate_project()
    except ValidationError as exc:
        for line in str(exc).splitlines() or [str(exc)]:
            error("validate", line)
        return 1

    info("validate", "project validation passed", rules=len(rules))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
