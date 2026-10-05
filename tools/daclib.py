from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import hashlib
import json
import re
import subprocess
import uuid

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOLUTION_ROOT = PROJECT_ROOT / "Solutions"
PLATFORM_ROOT = PROJECT_ROOT / "platforms" / "microsoft-sentinel"
PIPELINES_ROOT = PLATFORM_ROOT / "pipelines"
CLIENTS_FILE = PLATFORM_ROOT / "clients.yml"
SETTINGS_FILE = PLATFORM_ROOT / "rule-settings.yml"
ARM_API_VERSION = "2025-09-01"

REQUIRED_SIGMA_KEYS = {
    "title", "id", "logsource", "detection"
}
ALLOWED_LEVELS = {"informational", "low", "medium", "high", "critical"}
ALLOWED_TRIGGER_OPERATORS = {"GreaterThan", "LessThan", "Equal", "NotEqual"}
ALLOWED_SEVERITIES = {"Informational", "Low", "Medium", "High"}
ALLOWED_EVENT_GROUPING = {"AlertPerResult", "SingleAlert"}
ALLOWED_RULE_OVERRIDE_KEYS = {
    "enabled", "queryFrequency", "queryPeriod", "triggerOperator", "triggerThreshold",
    "suppressionDuration", "suppressionEnabled", "eventGrouping", "createIncident",
    "severity", "entityMappings",
}


@dataclass(frozen=True)
class RuleSource:
    path: Path
    solution: str
    data: dict[str, Any]

    @property
    def id(self) -> str:
        return str(self.data["id"])

    @property
    def slug(self) -> str:
        return self.path.stem


class ValidationError(Exception):
    pass


def load_yaml(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValidationError(f"{path}: cannot read YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ValidationError(f"{path}: expected a YAML mapping at document root")
    return data


def discover_rules() -> list[RuleSource]:
    rules: list[RuleSource] = []
    paths = set(SOLUTION_ROOT.glob("*/Analytic Rules/*.yml")) | set(SOLUTION_ROOT.glob("*/Analytic Rules/*.yaml"))
    for path in sorted(paths):
        solution = path.parents[1].name
        rules.append(RuleSource(path=path, solution=solution, data=load_yaml(path)))
    return rules


def validate_uuid(value: str, label: str) -> None:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValidationError(f"{label}: {value!r} is not a UUID") from exc
    if str(parsed) != value.lower():
        raise ValidationError(f"{label}: UUID must use canonical lower-case form")


def validate_sigma_rule(rule: RuleSource) -> list[str]:
    errors: list[str] = []
    missing = sorted(REQUIRED_SIGMA_KEYS - set(rule.data))
    if missing:
        errors.append(f"{rule.path}: missing required keys: {', '.join(missing)}")
        return errors
    try:
        validate_uuid(str(rule.data["id"]), str(rule.path))
    except ValidationError as exc:
        errors.append(str(exc))
    if "level" in rule.data and str(rule.data["level"]).lower() not in ALLOWED_LEVELS:
        errors.append(f"{rule.path}: unsupported level {rule.data.get('level')!r}")
    if not isinstance(rule.data["title"], str) or not rule.data["title"].strip():
        errors.append(f"{rule.path}: title must be a non-empty string")
    if not isinstance(rule.data["logsource"], dict) or not rule.data["logsource"]:
        errors.append(f"{rule.path}: logsource must be a non-empty mapping")
    detection = rule.data.get("detection")
    if not isinstance(detection, dict) or not isinstance(detection.get("condition"), str) or not detection["condition"].strip():
        errors.append(f"{rule.path}: detection.condition is required")
    tags = rule.data.get("tags", [])
    if tags is not None and not isinstance(tags, list):
        errors.append(f"{rule.path}: tags must be a list")
    return errors


def validate_sentinel_settings(cfg: dict[str, Any], label: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(cfg, dict):
        return [f"{label}: required Sentinel settings missing"]
    required = {"queryFrequency", "queryPeriod", "triggerOperator", "triggerThreshold", "suppressionDuration", "suppressionEnabled", "eventGrouping", "createIncident", "severity"}
    missing = sorted(required - set(cfg))
    if missing:
        errors.append(f"{label}: required Sentinel settings missing: {', '.join(missing)}")
    for key in ("enabled", "suppressionEnabled", "createIncident"):
        if key in cfg and not isinstance(cfg[key], bool):
            errors.append(f"{label}: {key} must be a boolean")
    if cfg.get("triggerOperator") not in ALLOWED_TRIGGER_OPERATORS:
        errors.append(f"{label}: invalid triggerOperator")
    if cfg.get("severity") not in ALLOWED_SEVERITIES:
        errors.append(f"{label}: invalid severity")
    if cfg.get("eventGrouping") not in ALLOWED_EVENT_GROUPING:
        errors.append(f"{label}: invalid eventGrouping")
    for duration_key in ("queryFrequency", "queryPeriod", "suppressionDuration"):
        if not re.fullmatch(r"P(?!$).+", str(cfg.get(duration_key, ""))):
            errors.append(f"{label}: {duration_key} must be ISO 8601 duration")
    try:
        int(cfg.get("triggerThreshold"))
    except (TypeError, ValueError):
        errors.append(f"{label}: triggerThreshold must be an integer")
    if not isinstance(cfg.get("entityMappings", []), list):
        errors.append(f"{label}: entityMappings must be a list")
    return errors


def pipeline_path(profile: str) -> Path:
    return PIPELINES_ROOT / f"{profile}.yml"


def resolve_compiler_profile(client_cfg: dict[str, Any], rule: RuleSource) -> str:
    profiles = client_cfg.get("compiler_profiles", {})
    profile = profiles.get(rule.solution) if isinstance(profiles, dict) else None
    if not profile:
        raise ValidationError(f"No compiler profile configured for solution {rule.solution!r}")
    return str(profile)


def resolve_rule_settings(defaults: dict[str, Any], client_cfg: dict[str, Any], rule_id: str) -> dict[str, Any]:
    merged = dict(defaults)
    overrides = client_cfg.get("rule_overrides", {}) or {}
    merged.update(overrides.get(rule_id, {}) or {})
    return merged


def validate_project() -> list[RuleSource]:
    rules = discover_rules()
    if not rules:
        raise ValidationError("No Sigma rules found under Solutions/*/Analytic Rules/")
    errors: list[str] = []
    ids: dict[str, Path] = {}
    rules_by_id: dict[str, RuleSource] = {}
    for rule in rules:
        errors.extend(validate_sigma_rule(rule))
        if "id" not in rule.data:
            continue
        if rule.id in ids:
            errors.append(f"Duplicate rule id {rule.id}: {ids[rule.id]} and {rule.path}")
        ids[rule.id] = rule.path
        rules_by_id[rule.id] = rule

    if errors:
        raise ValidationError("\n".join(errors))
    from daclog import info
    for rule in rules:
        info("validate", "Sigma rule valid", rule=rule.id)
    from targets import resolve_targets
    targets = resolve_targets(rules)
    sentinel_targets = [t for t in targets if t.platform == "microsoft-sentinel"]
    settings = load_yaml(SETTINGS_FILE).get("rules", {}) if sentinel_targets and SETTINGS_FILE.exists() else {}
    if not isinstance(settings, dict):
        raise ValidationError(f"{SETTINGS_FILE}: rules must be a mapping")
    if sentinel_targets:
        for rid in settings:
            if rid not in ids:
                errors.append(f"stage=sentinel-config platform=microsoft-sentinel rule={rid}: settings reference unknown rule")
    for target in sentinel_targets:
        label = f"stage=sentinel-config platform=microsoft-sentinel client={target.client} rule={target.rule_id}"
        rule = rules_by_id[target.rule_id]
        cfg = target.config
        defaults = settings.get(rule.id)
        if not isinstance(defaults, dict):
            errors.append(f"{label}: required Sentinel settings missing")
        else:
            overrides = cfg.get("rule_overrides", {}) or {}
            if not isinstance(overrides, dict):
                errors.append(f"{label}: rule_overrides must be a mapping")
                continue
            for rid, override in overrides.items():
                if rid not in cfg["rules"] or not isinstance(override, dict):
                    errors.append(f"{label}: invalid override for {rid}")
                elif set(override) - ALLOWED_RULE_OVERRIDE_KEYS:
                    errors.append(f"{label}: unsupported override keys for {rid}")
            if any(not isinstance(v, dict) for v in overrides.values()):
                continue
            errors.extend(validate_sentinel_settings(resolve_rule_settings(defaults, cfg, rule.id), label))
        try:
            profile = resolve_compiler_profile(cfg, rule)
            path = pipeline_path(profile)
            if not re.fullmatch(r"[a-zA-Z0-9_-]+", profile) or not path.exists():
                raise ValidationError(f"missing or invalid compiler profile {profile!r}")
            if int(load_yaml(path).get("priority", 999)) > 9:
                raise ValidationError("custom pySigma pipeline priority must be <= 9")
        except (ValidationError, TypeError, ValueError) as exc:
            errors.append(f"{label}: {exc}")

    if errors:
        from daclog import error
        for message in errors:
            context, _, reason = message.partition(": ")
            fields = dict(part.split("=", 1) for part in context.split() if "=" in part)
            error(fields.pop("stage", "validate"), reason, **fields)
        raise ValidationError("\n".join(errors))
    return rules


def kql_string(value: str) -> str:
    return json.dumps(value)


def offline_demo_compile(rule: RuleSource) -> str:
    """Compile the deliberately tiny bundled demo subset.

    This is intentionally NOT advertised as pySigma. Production CI uses sigma-cli.
    It exists solely so the repository can be demonstrated offline.
    """
    detection = rule.data["detection"]
    if detection.get("condition") != "selection" or not isinstance(detection.get("selection"), dict):
        raise ValidationError(
            f"offline-demo only supports detection.condition == 'selection': {rule.path}"
        )
    field_map = {
        "Vendor": "DeviceVendor",
        "Product": "DeviceProduct",
        "Activity": "Activity",
        "Outcome": "EventOutcome",
        "Action": "SimplifiedDeviceAction",
        "SourceIP": "SourceIP",
        "DestinationIP": "DestinationIP",
        "DestinationPort": "DestinationPort",
        "User": "SourceUserName",
    }
    clauses: list[str] = []
    for raw_field, value in detection["selection"].items():
        parts = raw_field.split("|")
        source_field = parts[0]
        modifier = parts[1] if len(parts) > 1 else None
        field = field_map.get(source_field)
        if not field:
            raise ValidationError(f"offline-demo has no field mapping for {source_field!r}")
        values = value if isinstance(value, list) else [value]
        exprs: list[str] = []
        for item in values:
            if isinstance(item, bool):
                literal = "true" if item else "false"
            elif isinstance(item, (int, float)):
                literal = str(item)
            else:
                literal = kql_string(str(item))
            if modifier == "contains":
                exprs.append(f"{field} contains {literal}")
            elif modifier == "startswith":
                exprs.append(f"{field} startswith {literal}")
            elif modifier == "endswith":
                exprs.append(f"{field} endswith {literal}")
            elif modifier is None:
                if isinstance(item, str):
                    exprs.append(f"{field} =~ {literal}")
                else:
                    exprs.append(f"{field} == {literal}")
            else:
                raise ValidationError(f"offline-demo does not support modifier {modifier!r}")
        clauses.append("(" + " or ".join(exprs) + ")")
    return (
        "// OFFLINE DEMO COMPILER OUTPUT - production CI uses pySigma/sigma-cli\n"
        "CommonSecurityLog\n| where " + " and ".join(clauses)
    )


def pysigma_compile(rule: RuleSource, profile: str) -> str:
    profile_path = pipeline_path(profile)
    cmd = [
        "sigma", "convert", "-t", "kusto",
        "-p", "azure_monitor",
        "-p", str(profile_path),
        "-f", "default",
        str(rule.path),
    ]
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise ValidationError(
            "sigma-cli is not installed. Install requirements-ci.txt or use --compiler offline-demo for the bundled offline demo."
        ) from exc
    if proc.returncode != 0:
        raise ValidationError(
            f"pySigma conversion failed for {rule.path} using profile {profile!r}:\n{proc.stderr.strip()}\n{proc.stdout.strip()}"
        )
    query = proc.stdout.strip()
    if not query:
        raise ValidationError(f"pySigma produced empty KQL for {rule.path}")
    return query


def compile_rule(rule: RuleSource, compiler: str, profile: str) -> str:
    if compiler == "offline-demo":
        if profile != "fortigate-commonsecuritylog":
            raise ValidationError(f"offline-demo only supports compiler profile 'fortigate-commonsecuritylog', got {profile!r}")
        return offline_demo_compile(rule)
    if compiler == "pysigma":
        return pysigma_compile(rule, profile)
    raise ValidationError(f"Unknown compiler {compiler!r}")


def extract_attack(rule: RuleSource) -> tuple[list[str], list[str]]:
    tactic_map = {
        "reconnaissance": "Reconnaissance",
        "resource_development": "ResourceDevelopment",
        "initial_access": "InitialAccess",
        "execution": "Execution",
        "persistence": "Persistence",
        "privilege_escalation": "PrivilegeEscalation",
        "defense_evasion": "DefenseEvasion",
        "credential_access": "CredentialAccess",
        "discovery": "Discovery",
        "lateral_movement": "LateralMovement",
        "collection": "Collection",
        "command_and_control": "CommandAndControl",
        "exfiltration": "Exfiltration",
        "impact": "Impact",
    }
    tactics: list[str] = []
    techniques: list[str] = []
    for tag in rule.data.get("tags", []) or []:
        if not isinstance(tag, str) or not tag.startswith("attack."):
            continue
        value = tag[len("attack."):]
        if value in tactic_map:
            tactics.append(tactic_map[value])
        elif re.fullmatch(r"t\d{4}(?:\.\d{3})?", value, flags=re.IGNORECASE):
            techniques.append(value.upper().removeprefix("T"))
    return sorted(set(tactics)), sorted(set(techniques))


def arm_template(rule: RuleSource, kql: str, settings: dict[str, Any]) -> dict[str, Any]:
    tactics, techniques = extract_attack(rule)
    rid = rule.id
    props = {
        "displayName": rule.data["title"],
        "description": str(rule.data.get("description", "")).strip(),
        "severity": settings["severity"],
        "enabled": bool(settings.get("enabled", False)),
        "query": kql,
        "queryFrequency": settings["queryFrequency"],
        "queryPeriod": settings["queryPeriod"],
        "triggerOperator": settings["triggerOperator"],
        "triggerThreshold": int(settings["triggerThreshold"]),
        "suppressionDuration": settings["suppressionDuration"],
        "suppressionEnabled": bool(settings["suppressionEnabled"]),
        "tactics": tactics,
        "techniques": techniques,
        "eventGroupingSettings": {"aggregationKind": settings["eventGrouping"]},
        "incidentConfiguration": {
            "createIncident": bool(settings["createIncident"]),
            "groupingConfiguration": {
                "enabled": False,
                "reopenClosedIncident": False,
                "lookbackDuration": "PT5H",
                "matchingMethod": "AllEntities",
                "groupByEntities": [],
                "groupByAlertDetails": [],
                "groupByCustomDetails": [],
            },
        },
        "entityMappings": settings.get("entityMappings", []),
    }
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "workspace": {
                "type": "String",
                "metadata": {"description": "Microsoft Sentinel Log Analytics workspace name"},
            }
        },
        "resources": [
            {
                "id": "[concat(resourceId('Microsoft.OperationalInsights/workspaces/providers', parameters('workspace'), 'Microsoft.SecurityInsights'),'/alertRules/" + rid + "')]",
                "name": "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/" + rid + "')]",
                "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
                "apiVersion": ARM_API_VERSION,
                "kind": "Scheduled",
                "properties": props,
            }
        ],
    }


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalized_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=False, ensure_ascii=False) + "\n"


def validate_arm_document(doc: dict[str, Any], path: Path | None = None) -> list[str]:
    prefix = f"{path}: " if path else ""
    errors: list[str] = []
    if doc.get("$schema") != "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#":
        errors.append(prefix + "unexpected or missing ARM $schema")
    if doc.get("contentVersion") != "1.0.0.0":
        errors.append(prefix + "contentVersion must be 1.0.0.0")
    workspace = doc.get("parameters", {}).get("workspace", {})
    if workspace.get("type") not in {"String", "string"}:
        errors.append(prefix + "workspace string parameter is required")
    resources = doc.get("resources")
    if not isinstance(resources, list) or len(resources) != 1:
        errors.append(prefix + "exactly one ARM resource is required per generated rule file")
        return errors
    resource = resources[0]
    if resource.get("type") != "Microsoft.OperationalInsights/workspaces/providers/alertRules":
        errors.append(prefix + "unexpected Sentinel alert rule resource type")
    if resource.get("apiVersion") != ARM_API_VERSION:
        errors.append(prefix + f"apiVersion must be {ARM_API_VERSION}")
    if resource.get("kind") != "Scheduled":
        errors.append(prefix + "kind must be Scheduled")
    props = resource.get("properties", {})
    required_props = {
        "displayName", "description", "severity", "enabled", "query",
        "queryFrequency", "queryPeriod", "triggerOperator", "triggerThreshold",
        "suppressionDuration", "suppressionEnabled", "eventGroupingSettings",
        "incidentConfiguration", "entityMappings"
    }
    missing = sorted(required_props - set(props))
    if missing:
        errors.append(prefix + "missing Scheduled rule properties: " + ", ".join(missing))
    if props.get("severity") not in ALLOWED_SEVERITIES:
        errors.append(prefix + "invalid severity")
    if props.get("triggerOperator") not in ALLOWED_TRIGGER_OPERATORS:
        errors.append(prefix + "invalid triggerOperator")
    if props.get("enabled") is not False:
        errors.append(prefix + "generated demo rules must remain disabled")
    if not str(props.get("query", "")).strip():
        errors.append(prefix + "query must not be empty")
    return errors
