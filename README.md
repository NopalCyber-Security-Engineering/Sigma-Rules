# Sigma-Rules

Source-of-truth repository for Detection-as-Code rules.

## What this repository proves today

A detection engineer can edit a Sigma rule and run one pipeline that:

1. validates Sigma metadata and local project policy;
2. compiles the Sigma detection into Microsoft Sentinel KQL through `sigma-cli` + `pySigma` + `pysigma-backend-kusto`;
3. enriches the portable Sigma rule with Sentinel-specific scheduling/entity settings;
4. renders workspace-independent ARM templates for Microsoft Sentinel Scheduled analytics rules;
5. verifies the generated templates;
6. publishes generated client roots to the separate `MS-Sentinel` repository when publishing is explicitly enabled.

The live Microsoft Sentinel repository connection is intentionally **not** required for build/test. That final Azure-side connection can be added later without changing the source-rule layout.

## Repository layout

```text
Sigma-Rules/
├── Solutions/
│   └── Fortinet FortiGate/
│       └── Analytic Rules/
│           ├── fortigate_vpn_authentication_failure.yml
│           └── fortigate_denied_remote_service_connection.yml
├── platforms/
│   └── microsoft-sentinel/
│       ├── clients.yml
│       ├── rule-settings.yml
│       └── pipelines/
│           └── fortigate-commonsecuritylog.yml
├── tools/
├── tests/
└── .github/workflows/detection-as-code.yml
```

## Important design boundary

Sigma remains portable. Microsoft Sentinel-only values such as query frequency, query period, incident settings and entity mappings live under `platforms/microsoft-sentinel/`, not inside the Sigma detection logic.

The bundled FortiGate mapping targets `CommonSecurityLog` only as a **verified demo profile**. Do not enable these demo rules in a customer workspace until the customer's actual FortiGate ingestion, values and field mappings have been checked.

## Local demo (works without Azure)

The sandbox used to build this package cannot download PyPI dependencies, so the project includes a deliberately limited `offline-demo` compiler for the two bundled rules. It proves the rest of the pipeline without pretending to be pySigma.

```bash
python tools/build.py --compiler offline-demo --output ../MS-Sentinel
python tools/verify_output.py ../MS-Sentinel
python -m unittest discover -s tests -v
```

On GitHub Actions or any machine with internet access, use the real compiler:

```bash
python -m pip install -r requirements-ci.txt
python tools/build.py --compiler pysigma --output ../MS-Sentinel
python tools/verify_output.py ../MS-Sentinel
```

## Safety defaults

- Generated Sentinel rules are disabled by default.
- Cross-repository publishing is disabled unless repository variable `PUBLISH_ENABLED=true` is set.
- No Azure credentials are stored here.
- No customer names, tenant IDs, subscriptions, resource groups, workspace names, logs, IPs or secrets are included.
- The five bundled client roots are placeholders used only to demonstrate multi-workspace fan-out.

See `docs/ARCHITECTURE.md`, `docs/DEMO.md`, and `docs/MONDAY_INTEGRATION.md` before connecting a real workspace.
