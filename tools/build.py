#!/usr/bin/env python3
from pathlib import Path
import argparse
import shutil

from daclib import (
    SETTINGS_FILE, PROJECT_ROOT, ValidationError, arm_template,
    compile_rule, load_yaml, normalized_json, resolve_compiler_profile,
    resolve_rule_settings, sha256_text, validate_arm_document, validate_project,
)
from daclog import error, info


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Sigma rules into Microsoft Sentinel ARM templates")
    parser.add_argument("--compiler", choices=["pysigma", "offline-demo"], default="pysigma")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        rules = validate_project()
        rules_by_id = {r.id: r for r in rules}
        from targets import resolve_targets
        targets = resolve_targets(rules)
        clients = {t.client: t.config for t in targets if t.platform == "microsoft-sentinel"}
        settings = load_yaml(SETTINGS_FILE)["rules"] if clients else {}

        out = args.output.resolve()
        clients_out = out / "Clients"
        build_out = out / "_build"
        if clients_out.exists():
            shutil.rmtree(clients_out)
        if build_out.exists():
            shutil.rmtree(build_out)
        clients_out.mkdir(parents=True, exist_ok=True)
        build_out.mkdir(parents=True, exist_ok=True)

        info("build", "source validation passed", rules=len(rules), compiler=args.compiler)

        # Compile once per rule/profile pair. Different clients can map the same
        # portable Sigma rule to different Sentinel schemas without copying it.
        compiled: dict[tuple[str, str], str] = {}
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
                profile = resolve_compiler_profile(client_cfg, rule)
                cache_key = (rule.id, profile)
                if cache_key not in compiled:
                    info("sentinel-compile", "compiling rule", rule=rule.id, client=client, profile=profile, compiler=args.compiler)
                    compiled[cache_key] = compile_rule(rule, args.compiler, profile)
                    info("sentinel-compile", "rule compiled", rule=rule.id, client=client, profile=profile, compiler=args.compiler)

                effective_settings = resolve_rule_settings(settings[rule_id], client_cfg, rule_id)
                arm = arm_template(rule, compiled[cache_key], effective_settings)
                errors = validate_arm_document(arm)
                if errors:
                    raise ValidationError(f"client={client} rule={rule.id}: " + "; ".join(errors))

                rel = Path("Clients") / client / "Solutions" / rule.solution / "Analytic Rules" / f"{rule.slug}.json"
                dest = out / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                rendered = normalized_json(arm)
                dest.write_text(rendered, encoding="utf-8", newline="\n")
                source_text = rule.path.read_text(encoding="utf-8")
                client_items.append({
                    "ruleId": rule.id,
                    "title": rule.data["title"],
                    "compilerProfile": profile,
                    "source": str(rule.path.relative_to(PROJECT_ROOT)).replace("\\", "/"),
                    "sourceSha256": sha256_text(source_text),
                    "artifact": str(rel).replace("\\", "/"),
                    "artifactSha256": sha256_text(rendered),
                })
                generated_count += 1
            manifest["clients"][client] = {"rules": client_items}
            info("render", "client artifacts generated", client=client, rules=len(client_items))

        (build_out / "build-manifest.json").write_text(normalized_json(manifest), encoding="utf-8", newline="\n",)
        info("build", "build passed", templates=generated_count, clients=len(clients), manifest=build_out / "build-manifest.json")
        return 0
    except ValidationError as exc:
        error("build", str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
