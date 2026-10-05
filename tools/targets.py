"""Resolve external platform/client assignments without coupling Sigma validation."""
from dataclasses import dataclass
import re

from daclib import PROJECT_ROOT, ValidationError, load_yaml
from daclog import info, warning


@dataclass(frozen=True)
class Target:
    rule_id: str
    platform: str
    client: str
    config: dict


def resolve_targets(rules):
    ids = {r.id for r in rules}
    targets = []
    for path in sorted((PROJECT_ROOT / "platforms").glob("*/clients.yml")):
        platform = path.parent.name
        clients = load_yaml(path).get("clients", {})
        if not isinstance(clients, dict):
            raise ValidationError(f"{path}: clients must be a mapping")
        for client, cfg in sorted(clients.items()):
            if not isinstance(client, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", client):
                raise ValidationError(f"{path}: invalid client alias {client!r}")
            if not isinstance(cfg, dict) or not isinstance(cfg.get("rules", []), list):
                raise ValidationError(f"{path}: client={client}: rules must be a list")
            assigned = cfg.get("rules", [])
            if any(not isinstance(rid, str) for rid in assigned):
                raise ValidationError(f"{path}: client={client}: rule IDs must be strings")
            if len(set(assigned)) != len(assigned):
                raise ValidationError(f"{path}: client={client}: duplicate assignments")
            for rid in sorted(assigned):
                if rid not in ids:
                    raise ValidationError(f"{path}: client={client}: unknown rule {rid}")
                targets.append(Target(rid, platform, client, cfg))
                if platform != "microsoft-sentinel":
                    warning("target-resolution", "automatic Sigma compilation is not implemented/supported", platform=platform, client=client, rule=rid)
    for rule in rules:
        count = sum(t.rule_id == rule.id for t in targets)
        info("target-resolution", "platform targets resolved" if count else "no platform targets configured", rule=rule.id, targets=count)
    return targets
