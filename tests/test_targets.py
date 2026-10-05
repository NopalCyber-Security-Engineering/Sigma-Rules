import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import daclib
import targets


class TargetTests(unittest.TestCase):
    def setUp(self):
        self.rule = daclib.RuleSource(Path("Solutions/example/Analytic Rules/minimal.yml"), "example", {
            "title": "Portable rule", "id": "0f4e1da3-d52e-4ec1-b8eb-a937f57d87a1",
            "logsource": {"product": "example"}, "detection": {"selection": {"field": "value"}, "condition": "selection"}})

    def test_zero_targets_pass_without_platform_configuration(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(targets, "PROJECT_ROOT", Path(directory)), patch.object(daclib, "discover_rules", return_value=[self.rule]), contextlib.redirect_stdout(io.StringIO()) as logs:
            self.assertEqual([self.rule], daclib.validate_project())
            self.assertIn("targets=0 | no platform targets configured", logs.getvalue())

    def test_missing_sentinel_settings_fail_with_context(self):
        target = targets.Target(self.rule.id, "microsoft-sentinel", "new-client", {"rules": [self.rule.id]})
        with patch.object(daclib, "discover_rules", return_value=[self.rule]), patch.object(targets, "resolve_targets", return_value=[target]), patch.object(daclib, "SETTINGS_FILE", Path("absent.yml")):
            with self.assertRaisesRegex(daclib.ValidationError, "stage=sentinel-config.*client=new-client.*required Sentinel settings missing"):
                daclib.validate_project()

    def test_missing_id_is_validation_error(self):
        data = dict(self.rule.data)
        del data["id"]
        with patch.object(daclib, "discover_rules", return_value=[daclib.RuleSource(self.rule.path, self.rule.solution, data)]):
            with self.assertRaisesRegex(daclib.ValidationError, "missing required keys: id"):
                daclib.validate_project()

    def test_multiple_platforms_and_arbitrary_clients(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(targets, "PROJECT_ROOT", Path(directory)):
            for platform in ("wazuh", "future-platform"):
                path = Path(directory) / "platforms" / platform / "clients.yml"
                path.parent.mkdir(parents=True)
                path.write_text("clients:\n  customer-new:\n    rules:\n      - " + self.rule.id + "\n", encoding="utf-8")
            self.assertEqual(2, len(targets.resolve_targets([self.rule])))

    def test_pysigma_command_preserves_backend_and_profiles(self):
        from subprocess import CompletedProcess
        with patch.object(daclib.subprocess, "run", return_value=CompletedProcess([], 0, "Table | where field == 1\n", "")) as run:
            self.assertEqual("Table | where field == 1", daclib.pysigma_compile(self.rule, "profile"))
            command = run.call_args.args[0]
            self.assertEqual(["sigma", "convert", "-t", "kusto", "-p", "azure_monitor"], command[:6])

    def test_zero_target_cli_build_and_verification(self):
        import shutil
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(Path(daclib.__file__).parent, root / "tools")
            path = root / "Solutions/example/Analytic Rules/minimal.yml"
            path.parent.mkdir(parents=True)
            import yaml
            path.write_text(yaml.safe_dump(self.rule.data), encoding="utf-8")
            output = root / "output"
            for command in (["tools/validate.py"], ["tools/build.py", "--output", str(output)], ["tools/verify_output.py", str(output)]):
                process = subprocess.run([sys.executable, *command], cwd=root, capture_output=True, text=True)
                self.assertEqual(0, process.returncode, process.stdout + process.stderr)
            import json
            manifest = json.loads((output / "_build/build-manifest.json").read_text())
            self.assertEqual({}, manifest["clients"])


if __name__ == "__main__":
    unittest.main()
