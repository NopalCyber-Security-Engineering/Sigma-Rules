# Verified External References

Checked during POC build on 2026-09-28. These are the external contracts this implementation intentionally depends on.

## Microsoft Sentinel repositories

- Deploy content as code from a repository: https://learn.microsoft.com/en-us/azure/sentinel/ci-cd
  - GitHub and Azure DevOps repository connections are supported.
  - GitHub collaborator access and GitHub Actions are prerequisites.
  - The connection creator needs Owner on the resource group containing the Sentinel workspace and must use a home-tenant identity; external/B2B guest identities and delegated access are not supported for creating the connection.
  - Creating the connection generates a deployment workflow and deploys repository content.
- Customize repository deployments: https://learn.microsoft.com/en-us/azure/sentinel/ci-cd-custom-deploy
  - The Sentinel-generated GitHub workflow can later be restricted to a root folder.
  - This project still uses a client deployment branch boundary so the *first* connection does not expose another client's catalog content.
- Manage repository content / supported formats: https://learn.microsoft.com/en-us/azure/sentinel/ci-cd-custom-content
  - ARM and Bicep are supported; Microsoft recommends Bicep.
  - This POC emits ARM JSON first and keeps the renderer isolated so Bicep can be added without changing Sigma source or client routing.
- Analytics rule resource reference: https://learn.microsoft.com/en-us/azure/templates/microsoft.securityinsights/alertrules
- Scheduled alert-rule REST API (2025-09-01): https://learn.microsoft.com/en-us/rest/api/securityinsights/alert-rules/create-or-update?view=rest-securityinsights-2025-09-01

## Sigma / Kusto compiler

- pySigma Kusto backend: https://github.com/AttackIQ/pySigma-backend-kusto
  - Supports `sigma convert -t kusto`.
  - Documents custom YAML pipelines with `query_table` and field mappings.
  - Custom pipeline priority must be 9 or lower when overriding built-in pipeline state; this project uses priority 1.
  - The Sentinel ASIM pipeline is documented as Beta with limited mappings; therefore it is not hardcoded as the universal target.
- Package: https://pypi.org/project/pySigma-backend-kusto/
  - POC pin: `pysigma-backend-kusto==1.0.1`.

## Important verification boundary

The sandbox could verify the local build/renderer/publisher logic but could not install the real compiler packages or connect to a live Sentinel workspace. Therefore the first office GitHub Actions run using `--compiler pysigma` and the first disabled-rule live deployment remain explicit gates.
