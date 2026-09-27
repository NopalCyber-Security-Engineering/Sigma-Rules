# Detection-as-Code Architecture

## Current scope

Microsoft Sentinel is the first deployment target. Wazuh, SentinelOne AI SIEM and SentinelOne EDR are deliberately deferred. The portable Sigma source tree and platform-adapter boundary are designed so those backends can be added later without moving existing source rules.

## Repositories

### `Sigma-Rules`
Human-authored source of truth.

```text
Solutions/<Solution>/Analytic Rules/<rule>.yml
```

### `MS-Sentinel`
Generated deployment repository.

`main` is a catalog branch showing all generated client outputs:

```text
Clients/<client-alias>/Solutions/<Solution>/Analytic Rules/<rule>.json
```

The publisher also maintains one isolated deployment branch per client/workspace:

```text
deploy/<client-alias>
└── Solutions/<Solution>/Analytic Rules/<rule>.json
```

**Sentinel workspaces connect to their own `deploy/<client-alias>` branch, never to `main`.** This prevents another client's generated content from being present during the initial repository deployment.

## Pipeline

```text
Sigma source
    |
    v
validate
    |
    v
compile (sigma-cli + pySigma + pysigma-backend-kusto)
    |
    v
wrap (Sigma metadata + Sentinel-specific rule-settings.yml)
    |
    v
render (workspace-independent ARM JSON)
    |
    v
verify (structure + manifest + safe defaults)
    |
    v
publish catalog to MS-Sentinel/main
    |
    +--> publish deploy/client-a branch
    +--> publish deploy/client-b branch
    +--> ...
    |
    v
Microsoft Sentinel Repository workflow on each client's isolated branch
```

## Why Sentinel-specific metadata is separate

Sigma describes the detection. Microsoft Sentinel Scheduled rules also need deployment/runtime settings such as `queryFrequency`, `queryPeriod`, `triggerOperator`, `triggerThreshold`, incident creation and entity mappings. Those values are maintained in `platforms/microsoft-sentinel/rule-settings.yml` rather than polluting the portable Sigma rule.

## Why branches are the live client boundary

Microsoft Sentinel creates and immediately uses a repository deployment workflow when a connection is created. Folder scoping is a later workflow customization, so relying only on folders in a shared branch creates an avoidable first-deployment cross-client risk.

A branch-per-workspace boundary keeps one centralized generated repository while ensuring that each workspace's selected branch contains only that client's deployable content from the start.

The `main` catalog still gives the team a single place to inspect all generated client outputs.

## Compiler profile boundary

The current demo profile maps FortiGate-oriented Sigma fields to Microsoft Sentinel `CommonSecurityLog`. Compiler profiles are selected **per client and per Solution** in `clients.yml`, and compilation is cached by `(rule, profile)`. That means the same portable Sigma rule can compile differently for two clients without copying the rule. If a real client uses ASIM or a different/custom table, add another processing pipeline and change only that client/Solution profile assignment; the source repository structure and publishing model do not change.

`rule-settings.yml` holds the shared Sentinel defaults for each rule. `clients.yml` also supports optional `rule_overrides` for genuine client-specific scheduling/severity/entity differences. This keeps customer variance in configuration rather than forking detection logic.

## Deployment format

The first implementation emits ARM JSON because Microsoft Sentinel Repositories supports ARM and it can be fully parsed and structurally checked in CI. Microsoft currently recommends Bicep; the renderer is isolated so a Bicep renderer can be added later without changing source rules, client routing, or repository boundaries.

## Safe-by-default behavior

Generated demo rules are disabled. Cross-repository publishing is disabled unless explicitly switched on. Live workspace deployment remains Microsoft's generated Sentinel repository workflow, not a home-grown Azure credential/deployment mechanism.
