# Release Verification — v0.2.3

Date: 2026-03-16

## Scope
Post-release verification for package naming, runtime version alignment, Docker image behavior, and SBOM generation.

## Results

- PyPI package publish: `skillscan-security==0.2.3` ✅
- Docker release publish: `kurtpayne/skillscan:v0.2.3` ✅
- CLI version alignment:
  - clean Python sandbox install reports `skillscan 0.2.3` ✅
  - Docker image reports `skillscan 0.2.3` ✅
- SBOM generation:
  - Python CycloneDX SBOM generated (`sbom-python.cdx.json`) ✅
  - Docker SPDX SBOM generated (`sbom-docker.spdx.json`) ✅

## Notes

- GitHub Release asset attach for Docker SBOM was disabled to avoid integration permission failures.
- SBOM remains available as workflow artifact uploads.

## Follow-up

- Keep package name as `skillscan-security` while preserving CLI command as `skillscan`.
- Continue release verification using `docs/RELEASE_CHECKLIST.md`.
