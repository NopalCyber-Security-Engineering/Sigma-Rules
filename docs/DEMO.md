# Morning Demo

## The 3-minute story

1. Open `Solutions/Fortinet FortiGate/Analytic Rules/` and show the two human-readable Sigma source rules.
2. Open `.github/workflows/detection-as-code.yml` and show the real pipeline stages: validate → compile → wrap/render → verify → artifact → optional publish.
3. Open `platforms/microsoft-sentinel/clients.yml` and show that client routing, per-Solution compiler profiles, and future client-specific rule overrides are configuration—not copied detections.
4. Run the offline demo command if you are demonstrating locally:

```powershell
python tools\build.py --compiler offline-demo --output ..\MS-Sentinel
python tools\verify_output.py ..\MS-Sentinel
python -m unittest discover -s tests -v
```

5. Open `../MS-Sentinel/Clients/` on `main` and show the five-client generated catalog, then show the five local `deploy/demo-client-*` branches that provide isolated deployment boundaries.
6. Open one generated JSON rule and point out:
   - the compiled KQL;
   - Scheduled analytics rule settings;
   - ATT&CK mapping;
   - entity mapping;
   - `enabled: false` safety default;
   - workspace parameter instead of a hard-coded tenant/workspace.
7. Open `_build/build-manifest.json` and show source/artifact hashes and source-to-output traceability.
8. Explain the remaining live step: after replacing the demo aliases and verifying real schemas, connect each real workspace to only its own `deploy/<client>` branch using Microsoft Sentinel Repositories.

## What not to claim

Do not claim the bundled FortiGate detections are production-ready. They are disposable pipeline fixtures. Do not claim the sandbox-generated KQL came from pySigma: local sandbox networking prevented installing the compiler. The GitHub workflow is configured to use the real pinned pySigma toolchain.

## Strong tangible result

The useful demo is not the repository tree by itself. It is the transformation and traceability:

```text
1 Sigma rule
    -> validated source
    -> KQL
    -> deployable Sentinel ARM
    -> routed into multiple isolated client roots
    -> verified manifest/hash trail
```
