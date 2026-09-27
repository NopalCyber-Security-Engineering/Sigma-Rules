#!/usr/bin/env python3
from pathlib import Path
import argparse
import hashlib
import json

from daclib import ValidationError, validate_arm_document


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify generated MS-Sentinel repository content")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    root = args.output.resolve()
    manifest_path = root / "_build" / "build-manifest.json"
    if not manifest_path.exists():
        print(f"VERIFY FAILED: missing {manifest_path}")
        return 1
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    errors = []
    count = 0
    for client, cdata in manifest.get("clients", {}).items():
        for item in cdata.get("rules", []):
            path = root / item["artifact"]
            if not path.exists():
                errors.append(f"missing artifact: {path}")
                continue
            text = path.read_text(encoding="utf-8")
            if sha256_text(text) != item["artifactSha256"]:
                errors.append(f"hash mismatch: {path}")
            try:
                doc = json.loads(text)
            except json.JSONDecodeError as exc:
                errors.append(f"invalid JSON: {path}: {exc}")
                continue
            errors.extend(validate_arm_document(doc, path))
            count += 1
    if errors:
        print("VERIFY FAILED")
        for error in errors:
            print(" -", error)
        return 1
    print(f"VERIFY PASSED: {count} generated ARM template(s) are structurally valid and match the manifest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
