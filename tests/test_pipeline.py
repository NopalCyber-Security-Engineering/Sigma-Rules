import json
import tempfile
import unittest
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from daclib import arm_template, compile_rule, load_yaml, validate_arm_document, validate_project, SETTINGS_FILE


class PipelineTests(unittest.TestCase):
    def test_source_project_validates(self):
        rules = validate_project()
        self.assertEqual(2, len(rules))
        self.assertEqual(2, len({r.id for r in rules}))

    def test_offline_demo_compiles_bundled_rules(self):
        for rule in validate_project():
            query = compile_rule(rule, "offline-demo")
            self.assertIn("CommonSecurityLog", query)
            self.assertIn("| where", query)

    def test_arm_renderer_uses_safe_defaults(self):
        settings = load_yaml(SETTINGS_FILE)["rules"]
        for rule in validate_project():
            query = compile_rule(rule, "offline-demo")
            doc = arm_template(rule, query, settings[rule.id])
            self.assertEqual([], validate_arm_document(doc))
            props = doc["resources"][0]["properties"]
            self.assertFalse(props["enabled"])
            self.assertEqual("Scheduled", doc["resources"][0]["kind"])


if __name__ == "__main__":
    unittest.main()
