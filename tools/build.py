#!/usr/bin/env python3
from pathlib import Path
import argparse
import json
import shutil

from daclib import (
    CLIENTS_FILE, SETTINGS_FILE, PROJECT_ROOT, ValidationError, arm_template,
    compile_rule, load_yaml, normalized_json, sha256_text, validate_arm_document,
    validate_project,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Sigma rules into Microsoft Sentinel ARM templates")
    parser.add_argument("--compiler", choices=["pysigma", "offline-demo"], default="pysigma")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        rules = validate_project()
        rules_by_id = {r.id: r for r in rules}
        clients = load_yaml(CLIENTS_FILE)["clients"]
        settings = load_yaml(SETTINGS_FILE)["rules"]

        out = args.output.resolve()
        clients_out = out / "Clients"
        build_out = out / "_build"
        if clients_out.exists():
            shutil.rmtree(clients_out)
        if build_out.exists():
            shutil.rmtree(build_out)
        clients_out.mkdir(parents=True, exist_ok=True)
        build_out.mkdir(parents=True, exist_ok=True)

        print(f"[validate] {len(rules)} Sigma rules passed project validation")

        compiled: dict[str, str] = {}
        for rule in rules:
            compiled[rule.id] = compile_rule(rule, args.compiler)
            print(f"[compile:{args.compiler}] {rule.id}  {rule.data['title']}")

        manifest = {
            "formatVersion": 1,
            "compiler": args.compiler,
            "safeDefaults": {"rulesEnabled": False, "publishEnabledByDefault": False},
            "clients": {},
        }
        generated_count = 0

        for client, client_cfg in clients.items():
            client_items = []
            for rule_id in client_cfg["rules"]:
                rule = rules_by_id[rule_id]
                arm = arm_template(rule, compiled[rule_id], settings[rule_id])
                errors = validate_arm_document(arm)
                if errors:
                    raise ValidationError("\n".join(errors))
                rel = Path("Clients") / client / "Solutions" / rule.solution / "Analytic Rules" / f"{rule.slug}.json"
                dest = out / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                rendered = normalized_json(arm)
                dest.write_text(rendered, encoding="utf-8")
                source_text = rule.path.read_text(encoding="utf-8")
                client_items.append({
                    "ruleId": rule.id,
                    "title": rule.data["title"],
                    "source": str(rule.path.relative_to(PROJECT_ROOT)).replace("\\", "/"),
                    "sourceSha256": sha256_text(source_text),
                    "artifact": str(rel).replace("\\", "/"),
                    "artifactSha256": sha256_text(rendered),
                })
                generated_count += 1
            manifest["clients"][client] = {
                "compilerProfile": client_cfg["compiler_profile"],
                "rules": client_items,
            }

        (build_out / "build-manifest.json").write_text(normalized_json(manifest), encoding="utf-8")
        print(f"[wrap/render] {generated_count} ARM rule template(s) generated across {len(clients)} client root(s)")
        print(f"[manifest] {build_out / 'build-manifest.json'}")
        print("BUILD PASSED")
        return 0
    except ValidationError as exc:
        print("BUILD FAILED")
        print(exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
