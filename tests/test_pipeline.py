import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from daclib import (
    SETTINGS_FILE, CLIENTS_FILE, arm_template, compile_rule, load_yaml,
    resolve_compiler_profile, resolve_rule_settings, validate_arm_document,
    validate_project,
)


class PipelineTests(unittest.TestCase):
    def test_source_project_validates(self):
        rules = validate_project()
        self.assertEqual(2, len(rules))
        self.assertEqual(2, len({r.id for r in rules}))

    def test_offline_demo_compiles_bundled_rules(self):
        clients = load_yaml(CLIENTS_FILE)["clients"]
        client_cfg = clients["demo-client-01"]
        for rule in validate_project():
            profile = resolve_compiler_profile(client_cfg, rule)
            query = compile_rule(rule, "offline-demo", profile)
            self.assertIn("CommonSecurityLog", query)
            self.assertIn("| where", query)

    def test_arm_renderer_uses_safe_defaults(self):
        defaults = load_yaml(SETTINGS_FILE)["rules"]
        client_cfg = load_yaml(CLIENTS_FILE)["clients"]["demo-client-01"]
        for rule in validate_project():
            profile = resolve_compiler_profile(client_cfg, rule)
            query = compile_rule(rule, "offline-demo", profile)
            settings = resolve_rule_settings(defaults[rule.id], client_cfg, rule.id)
            doc = arm_template(rule, query, settings)
            self.assertEqual([], validate_arm_document(doc))
            props = doc["resources"][0]["properties"]
            self.assertFalse(props["enabled"])
            self.assertEqual("Scheduled", doc["resources"][0]["kind"])

    def test_client_config_supports_solution_profiles_and_rule_overrides(self):
        rules = validate_project()
        client_cfg = load_yaml(CLIENTS_FILE)["clients"]["demo-client-01"]
        defaults = load_yaml(SETTINGS_FILE)["rules"]
        for rule in rules:
            self.assertEqual("fortigate-commonsecuritylog", resolve_compiler_profile(client_cfg, rule))
            overridden = dict(client_cfg)
            overridden["rule_overrides"] = {rule.id: {"severity": "High"}}
            effective = resolve_rule_settings(defaults[rule.id], overridden, rule.id)
            self.assertEqual("High", effective["severity"])
            self.assertEqual(defaults[rule.id]["queryFrequency"], effective["queryFrequency"])


if __name__ == "__main__":
    unittest.main()
