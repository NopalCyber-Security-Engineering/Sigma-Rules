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
Generated deployment repository. One root is reserved per Sentinel workspace/client:

```text
Clients/<client-alias>/Solutions/<Solution>/Analytic Rules/<rule>.json
```

Each Microsoft Sentinel repository connection can later be scoped to its matching `Clients/<client-alias>` root.

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
publish to MS-Sentinel (explicitly enabled only)
    |
    v
Microsoft Sentinel Repository workflow (added per real workspace later)
```

## Why Sentinel-specific metadata is separate

Sigma describes the detection. Microsoft Sentinel Scheduled rules also need deployment/runtime settings such as `queryFrequency`, `queryPeriod`, `triggerOperator`, `triggerThreshold`, incident creation and entity mappings. Those values are maintained in `platforms/microsoft-sentinel/rule-settings.yml` rather than polluting the portable Sigma rule.

## Why five client roots instead of five source repositories

The detection source remains centralized while deployment boundaries remain isolated. A client can receive only the rules assigned to its alias. The target repository can be connected to multiple Sentinel workspaces with each generated Sentinel workflow scoped to its own root folder.

## Compiler profile boundary

The current demo profile maps FortiGate-oriented Sigma fields to Microsoft Sentinel `CommonSecurityLog`. This is intentionally a replaceable profile. If a real client uses ASIM or a different/custom table, add or select another processing pipeline and update that client's profile assignment; the source repository structure and publishing model do not change.

## Deployment format

The first implementation emits ARM JSON because Microsoft Sentinel Repositories supports ARM and it can be fully parsed and structurally checked in CI. The renderer is isolated; a Bicep renderer can be added later without changing source rules or client routing.

## Safe-by-default behavior

Generated demo rules are disabled. Publishing is disabled unless explicitly switched on. Live workspace deployment remains Microsoft's generated Sentinel repository workflow, not a home-grown Azure credential/deployment mechanism.
