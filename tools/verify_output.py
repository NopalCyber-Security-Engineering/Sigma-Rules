#!/usr/bin/env python3
from pathlib import Path
import argparse
import hashlib
import json

from daclib import validate_arm_document
from daclog import error, info


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify generated MS-Sentinel repository content")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    root = args.output.resolve()
    manifest_path = root / "_build" / "build-manifest.json"

    info("verify", "starting generated-content verification", output=root)
    if not manifest_path.exists():
        error("verify", "build manifest missing", path=manifest_path)
        return 1

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        error("verify", "cannot read build manifest", path=manifest_path, detail=exc)
        return 1

    errors: list[tuple[str | None, str | None, str]] = []
    count = 0
    for client, cdata in manifest.get("clients", {}).items():
        for item in cdata.get("rules", []):
            rule_id = item.get("ruleId")
            path = root / item["artifact"]
            if not path.exists():
                errors.append((client, rule_id, f"missing artifact: {path}"))
                continue
            text = path.read_text(encoding="utf-8")
            if sha256_text(text) != item["artifactSha256"]:
                errors.append((client, rule_id, f"hash mismatch: {path}"))
            try:
                doc = json.loads(text)
            except json.JSONDecodeError as exc:
                errors.append((client, rule_id, f"invalid JSON: {path}: {exc}"))
                continue
            for validation_error in validate_arm_document(doc, path):
                errors.append((client, rule_id, validation_error))
            count += 1

    if errors:
        for client, rule_id, message in errors:
            error("verify", message, client=client, rule=rule_id)
        return 1

    info("verify", "generated content verified", templates=count, clients=len(manifest.get("clients", {})))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
