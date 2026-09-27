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
PIPELINE_FILE = PLATFORM_ROOT / "pipelines" / "fortigate-commonsecuritylog.yml"
CLIENTS_FILE = PLATFORM_ROOT / "clients.yml"
SETTINGS_FILE = PLATFORM_ROOT / "rule-settings.yml"
ARM_API_VERSION = "2025-09-01"

REQUIRED_SIGMA_KEYS = {
    "title", "id", "status", "description", "logsource", "detection", "level"
}
ALLOWED_LEVELS = {"informational", "low", "medium", "high", "critical"}
ALLOWED_TRIGGER_OPERATORS = {"GreaterThan", "LessThan", "Equal", "NotEqual"}
ALLOWED_SEVERITIES = {"Informational", "Low", "Medium", "High"}
ALLOWED_EVENT_GROUPING = {"AlertPerResult", "SingleAlert"}


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
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValidationError(f"{path}: expected a YAML mapping at document root")
    return data


def discover_rules() -> list[RuleSource]:
    rules: list[RuleSource] = []
    for path in sorted(SOLUTION_ROOT.glob("*/Analytic Rules/*.yml")):
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
    if str(rule.data.get("level", "")).lower() not in ALLOWED_LEVELS:
        errors.append(f"{rule.path}: unsupported level {rule.data.get('level')!r}")
    detection = rule.data.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        errors.append(f"{rule.path}: detection.condition is required")
    tags = rule.data.get("tags", [])
    if tags is not None and not isinstance(tags, list):
        errors.append(f"{rule.path}: tags must be a list")
    return errors


def validate_project() -> list[RuleSource]:
    rules = discover_rules()
    if not rules:
        raise ValidationError("No Sigma rules found under Solutions/*/Analytic Rules/")
    errors: list[str] = []
    ids: dict[str, Path] = {}
    for rule in rules:
        errors.extend(validate_sigma_rule(rule))
        if rule.id in ids:
            errors.append(f"Duplicate rule id {rule.id}: {ids[rule.id]} and {rule.path}")
        ids[rule.id] = rule.path

    settings_doc = load_yaml(SETTINGS_FILE)
    settings = settings_doc.get("rules", {})
    if not isinstance(settings, dict):
        errors.append(f"{SETTINGS_FILE}: rules must be a mapping")
        settings = {}

    for rule in rules:
        if rule.id not in settings:
            errors.append(f"{SETTINGS_FILE}: missing Sentinel settings for rule {rule.id}")

    for rule_id, cfg in settings.items():
        if rule_id not in ids:
            errors.append(f"{SETTINGS_FILE}: settings reference unknown rule {rule_id}")
            continue
        if cfg.get("triggerOperator") not in ALLOWED_TRIGGER_OPERATORS:
            errors.append(f"{SETTINGS_FILE}: invalid triggerOperator for {rule_id}")
        if cfg.get("severity") not in ALLOWED_SEVERITIES:
            errors.append(f"{SETTINGS_FILE}: invalid severity for {rule_id}")
        if cfg.get("eventGrouping") not in ALLOWED_EVENT_GROUPING:
            errors.append(f"{SETTINGS_FILE}: invalid eventGrouping for {rule_id}")
        for duration_key in ("queryFrequency", "queryPeriod", "suppressionDuration"):
            if not re.fullmatch(r"P(?!$).+", str(cfg.get(duration_key, ""))):
                errors.append(f"{SETTINGS_FILE}: {duration_key} for {rule_id} must be ISO 8601 duration")

    clients_doc = load_yaml(CLIENTS_FILE)
    clients = clients_doc.get("clients", {})
    if not isinstance(clients, dict) or not clients:
        errors.append(f"{CLIENTS_FILE}: clients must be a non-empty mapping")
    else:
        for client, cfg in clients.items():
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", client):
                errors.append(f"{CLIENTS_FILE}: invalid client alias {client!r}")
            if cfg.get("compiler_profile") != "fortigate-commonsecuritylog":
                errors.append(f"{CLIENTS_FILE}: unsupported compiler_profile for {client}")
            assigned = cfg.get("rules", [])
            if not isinstance(assigned, list) or not assigned:
                errors.append(f"{CLIENTS_FILE}: {client} must have at least one rule assignment")
            for rule_id in assigned:
                if rule_id not in ids:
                    errors.append(f"{CLIENTS_FILE}: {client} references unknown rule {rule_id}")

    if errors:
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


def pysigma_compile(rule: RuleSource) -> str:
    cmd = [
        "sigma", "convert", "-t", "kusto",
        "-p", "azure_monitor",
        "-p", str(PIPELINE_FILE),
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
            f"pySigma conversion failed for {rule.path}:\n{proc.stderr.strip()}\n{proc.stdout.strip()}"
        )
    query = proc.stdout.strip()
    if not query:
        raise ValidationError(f"pySigma produced empty KQL for {rule.path}")
    return query


def compile_rule(rule: RuleSource, compiler: str) -> str:
    if compiler == "offline-demo":
        return offline_demo_compile(rule)
    if compiler == "pysigma":
        return pysigma_compile(rule)
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
        "description": rule.data["description"].strip(),
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
