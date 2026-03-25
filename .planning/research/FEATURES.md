# Feature Research

**Domain:** SBOM generation for Ansible automation content (CLI tool)
**Researched:** 2026-03-25
**Confidence:** HIGH

## Feature Landscape

### Table Stakes (Users Expect These)

Features users assume exist. Missing these means the SBOM is not useful or standards-compliant.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| NTIA minimum data fields | Federal mandate (EO 14028) and EU CRA require compliant SBOMs. Without all 7 fields (supplier, component name, version, unique ID, dependency relationship, SBOM author, timestamp), the output fails compliance checks. | MEDIUM | Fields: supplier name, component name, version, unique identifiers (PURL), dependency relationships, SBOM author, timestamp. CycloneDX 1.5 schema maps cleanly to these. |
| CycloneDX 1.5 JSON output | PROJECT.md specifies this. CycloneDX is the dominant security-focused format; JSON is the most consumed serialization. Grype, Snyk, Dependency-Track all ingest it natively. | MEDIUM | Must validate against official CycloneDX 1.5 JSON schema. Only `type` and `name` are required per spec, but PURL and version are effectively required for downstream tool compatibility. |
| Collection inventory (name, namespace, version) | Collections are the primary distribution unit in modern Ansible. Any Ansible SBOM without them is incomplete. | LOW | Read from `galaxy.yml` metadata and/or installed collection paths in the session venv. Galaxy Proxy already has this metadata. |
| Python dependency inventory | Collections depend on Python packages. Vulnerability scanners need the full Python dependency tree to be useful. | LOW | Read from `pip list --format=json` or `importlib.metadata` in the session venv. Well-understood problem. |
| Role inventory (name, version, source) | Roles are still widely used, especially in brownfield projects migrating to AAP 2.5+. | MEDIUM | Roles in `requirements.yml` have name+version. Standalone roles in `roles/` may lack version info -- need graceful handling. |
| PURL identifiers for components | PURLs are the de facto standard component identifier. Without them, vulnerability databases cannot match components. NTIA lists PURL as the primary "unique identifier" mechanism. | MEDIUM | No registered `pkg:ansible` type exists. Use `pkg:generic/<namespace>/<name>@<version>?repository_url=https://galaxy.ansible.com` for collections. Use `pkg:pypi/<name>@<version>` for Python deps. |
| Stdout output by default | Every SBOM CLI tool (Syft, Trivy, cdxgen) defaults to stdout for Unix pipeline composability. | LOW | Already specified in PROJECT.md. |
| `--output` / `-o` file flag | Standard pattern across Syft, Trivy, Snyk CLI. Users expect to redirect to a file without shell redirection. | LOW | Already specified in PROJECT.md. Follow Trivy pattern: separate `--output` for file path. |
| `--session` flag for venv reuse | Existing APME CLI pattern. All other subcommands (`scan`, `format`, `fix`) have this flag. Omitting it would break user expectations. | LOW | Reuse existing session management infrastructure. |
| Valid JSON schema compliance | Downstream tools (Grype, Dependency-Track, OWASP DT) validate incoming SBOMs against the CycloneDX schema. Invalid SBOMs are rejected silently or with cryptic errors. | MEDIUM | Must include `bomFormat`, `specVersion`, `version`, `serialNumber` (UUID), `metadata.timestamp`, `metadata.tools`, `metadata.component`, and `components[]`. Test against official schema. |
| Non-zero exit on error | CI/CD pipelines need reliable exit codes. Scan failures should be distinguishable from "no components found." | LOW | Exit 0 on success, exit 1 on error. Consistent with existing APME CLI behavior. |

### Differentiators (Competitive Advantage)

Features that set APME apart from generic SBOM generators. The key differentiator: APME understands Ansible content structure, not just Python packages.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Ansible-aware component classification | Generic SBOM tools treat everything as Python libraries. APME can classify components as `type: library` (collections), `type: application` (roles), with proper group/namespace from FQCN. No other SBOM tool does this for Ansible. | LOW | Map FQCN (e.g., `community.general`) to CycloneDX component fields: `group` = namespace, `name` = collection name. |
| Dependency relationship graph between collections | CycloneDX supports `dependencies[]` showing which components depend on which. APME can extract inter-collection dependencies from `galaxy.yml` `dependencies:` fields, giving vulnerability scanners blast-radius context. Steampunk Spotter does this but is SaaS-only and proprietary. | MEDIUM | Parse `galaxy.yml` `dependencies` for each installed collection. Map to CycloneDX `dependencies[].dependsOn[]`. |
| Galaxy source tracking | Record where each collection was installed from (Ansible Galaxy, Automation Hub, private Galaxy). Adds provenance context that generic Python SBOM tools cannot provide. | LOW | Available from Galaxy Proxy metadata and collection install manifests. Maps to CycloneDX `externalReferences[]`. |
| Integration with existing APME session | Reuse the same session venv from `scan`/`fix` commands. One `apme-scan scan --session my-project` followed by `apme-scan sbom --session my-project` gives a complete security picture without re-downloading anything. | LOW | Infrastructure already exists. Just wire it up. |
| Execution environment awareness | EE container images have specific collection+Python dep combinations. If APME can detect and label the EE, the SBOM becomes a per-EE artifact -- exactly what AAP 2.5+ operators need. | HIGH | Requires detecting EE metadata (`execution-environment.yml`). Defer to v1.x unless straightforward. |
| Human-readable summary mode | A `--summary` flag that prints a table of components (name, version, type) to stderr while the JSON goes to stdout. Useful for quick inspection without piping through `jq`. | LOW | Print to stderr so stdout JSON remains clean. Not a standard SBOM tool feature but good DX. |

### Anti-Features (Commonly Requested, Often Problematic)

Features that seem good but should be deliberately excluded from v1.

| Feature | Why Requested | Why Problematic | Alternative |
|---------|---------------|-----------------|-------------|
| Built-in CVE/vulnerability lookup | "Why generate an SBOM if I still need another tool to scan it?" | Requires maintaining or connecting to vulnerability databases (NVD, OSV, GHSA). Adds external API dependencies, rate limits, auth tokens, and staleness concerns. Every user already has a preferred scanner (Grype, Snyk, Trivy). PROJECT.md explicitly excludes this. | Generate standards-compliant SBOMs that pipe directly into existing scanners. Document the `apme-scan sbom | grype` workflow. |
| SPDX format output | "We need SPDX for compliance." | Supporting two formats doubles validation surface and testing. CycloneDX-to-SPDX conversion tools exist (`cyclonedx-cli convert`). SPDX is more complex (tag-value, RDF, JSON, YAML). PROJECT.md defers SPDX to future. | Ship CycloneDX only. Document conversion with `cyclonedx-cli`. Add `--format` flag now (accepting only `cyclonedx-json`) so the CLI interface is ready for future SPDX support without breaking changes. |
| License compliance analysis | "Tell me if my collections have compatible licenses." | License detection in Ansible collections is unreliable (many lack license metadata in `galaxy.yml`). License compatibility analysis is a separate domain with its own tooling (FOSSA, FOSSology). Mixing concerns dilutes the core value. | Include license info in SBOM components when available from `galaxy.yml` or Python package metadata. Let dedicated tools analyze it. |
| Transitive dependency resolution beyond venv | "Show me what my collections' Python deps will pull in." | The venv already has the resolved dependency tree. Going beyond it means speculatively resolving deps, which is fragile and misleading. | Inventory what is actually installed. The venv is the source of truth. Document that users should generate SBOMs after `pip install` completes. |
| SBOM signing | "We need signed SBOMs for supply chain security." | Signing requires key management infrastructure, which varies wildly between organizations. CycloneDX spec supports external signing. OWASP SCVS Level 2 expects external signing. | Document how to sign the output with `cosign` or `gpg`. Keep SBOM generation and signing as separate concerns. |
| Dashboard/web UI for SBOM viewing | "Show me the SBOM in the dashboard." | PROJECT.md explicitly defers dashboard integration (DR-003). Adding UI increases scope massively. | JSON output is viewable in any SBOM viewer (Dependency-Track, OWASP BOM Doctor). |
| Real-time/watch mode | "Re-generate SBOM when dependencies change." | SBOMs are point-in-time snapshots by definition (NTIA requires timestamp). Watch mode contradicts this model. | Generate in CI/CD on every build. The timestamp captures when. |

## Feature Dependencies

```
[Session venv access]
    |
    +--requires--> [Collection inventory]
    |                   |
    |                   +--enables--> [PURL generation for collections]
    |                   +--enables--> [Dependency relationship graph]
    |                   +--enables--> [Galaxy source tracking]
    |
    +--requires--> [Python dep inventory]
    |                   |
    |                   +--enables--> [PURL generation for Python deps]
    |
    +--requires--> [Role inventory]

[CycloneDX 1.5 JSON serialization]
    |
    +--requires--> [NTIA minimum fields (metadata, timestamp, author)]
    +--requires--> [Component inventory (collections + Python + roles)]
    +--requires--> [PURL generation]
    +--enables---> [Schema validation]

[CLI argument parsing]
    |
    +--requires--> [Subcommand registration in parser.py]
    +--requires--> [--output flag]
    +--requires--> [--session flag]

[Human-readable summary] --enhances--> [CLI output]
    (independent of CycloneDX serialization)
```

### Dependency Notes

- **CycloneDX serialization requires component inventory:** Cannot produce a valid BOM without at least one component source working.
- **PURL generation requires component inventory:** PURLs are computed from component name/version/source, not independent.
- **Dependency graph requires collection inventory:** Inter-collection deps come from `galaxy.yml` of installed collections.
- **Session venv is the foundation:** All inventory operations read from the session venv. Without it, nothing works.
- **CLI parsing is independent:** Can be implemented in parallel with inventory logic.

## MVP Definition

### Launch With (v1)

Minimum viable SBOM generator -- produces a compliant, useful SBOM from an APME session.

- [x] `apme-scan sbom [target]` subcommand -- entry point, consistent with existing CLI pattern
- [x] Collection inventory from session venv -- name, namespace, version from installed collections
- [x] Python dependency inventory from session venv -- name, version from installed packages
- [x] Role inventory from target directory -- name, version from `meta/main.yml` and `requirements.yml`
- [x] CycloneDX 1.5 JSON output with NTIA minimum fields -- compliant, ingestible by scanners
- [x] PURL identifiers for all components -- `pkg:pypi` for Python, `pkg:generic` for collections/roles
- [x] `--output`/`-o` file flag and stdout default -- Unix pipeline friendly
- [x] `--session` flag for venv reuse -- consistent with existing CLI
- [x] Schema validation of output -- ensure downstream tools accept it
- [x] Stdlib-only implementation -- zero new dependencies per ADR-014

### Add After Validation (v1.x)

Features to add once the core SBOM generation is working and users provide feedback.

- [ ] Dependency relationship graph (`dependencies[]` in CycloneDX) -- add when users request blast-radius analysis
- [ ] Galaxy source tracking (`externalReferences[]`) -- add when provenance questions arise
- [ ] `--summary` human-readable table to stderr -- add when users complain about needing `jq`
- [ ] Execution environment detection and labeling -- add when AAP 2.5+ EE workflows are better understood
- [ ] `--format` flag (accepting only `cyclonedx-json` initially) -- future-proof the CLI interface for SPDX

### Future Consideration (v2+)

Features to defer until the SBOM capability is proven and requested.

- [ ] SPDX format output -- defer until users demonstrate need beyond CycloneDX conversion tools
- [ ] SBOM diff (compare two SBOMs) -- useful for CI but CycloneDX CLI already does this
- [ ] SBOM merge (combine multiple SBOMs) -- useful for multi-project but CycloneDX CLI handles it
- [ ] License enrichment from Galaxy/PyPI APIs -- defer until license compliance becomes a user need
- [ ] gRPC endpoint for SBOM generation -- defer until dashboard or API consumers exist

## Feature Prioritization Matrix

| Feature | User Value | Implementation Cost | Priority |
|---------|------------|---------------------|----------|
| CycloneDX 1.5 JSON output | HIGH | MEDIUM | P1 |
| Collection inventory | HIGH | LOW | P1 |
| Python dep inventory | HIGH | LOW | P1 |
| NTIA minimum fields | HIGH | MEDIUM | P1 |
| PURL identifiers | HIGH | MEDIUM | P1 |
| Role inventory | MEDIUM | MEDIUM | P1 |
| `--output` file flag | HIGH | LOW | P1 |
| `--session` flag | HIGH | LOW | P1 |
| Schema validation | MEDIUM | LOW | P1 |
| Dependency relationship graph | MEDIUM | MEDIUM | P2 |
| Galaxy source tracking | MEDIUM | LOW | P2 |
| `--summary` flag | LOW | LOW | P2 |
| `--format` flag (future-proof) | LOW | LOW | P2 |
| EE detection | MEDIUM | HIGH | P3 |
| SPDX output | LOW | HIGH | P3 |

**Priority key:**
- P1: Must have for launch
- P2: Should have, add when possible
- P3: Nice to have, future consideration

## Competitor Feature Analysis

| Feature | Steampunk Spotter | cyclonedx-python | Syft | APME SBOM (planned) |
|---------|-------------------|------------------|------|---------------------|
| Ansible collection inventory | Yes (SaaS) | No | No | Yes (local CLI) |
| Python dep inventory | Via EE scanning | Yes (core feature) | Yes | Yes |
| Role inventory | Partial | No | No | Yes |
| CycloneDX output | Unknown format | Yes | Yes | Yes |
| SPDX output | No | No | Yes | No (v1) |
| CVE analysis | Yes (bundled) | No | No (use Grype) | No (by design) |
| PURL identifiers | Unknown | Yes | Yes | Yes |
| Dependency graph | Yes | Partial | Yes | No (v1), Yes (v1.x) |
| Offline/local operation | No (SaaS) | Yes | Yes | Yes |
| Ansible-aware classification | Yes | No | No | Yes |
| Stdlib-only (no deps) | N/A (SaaS) | No (uses cyclonedx-python-lib) | No (Go binary) | Yes |
| License | Proprietary/paid | Apache-2.0 | Apache-2.0 | Matches APME license |

**Key competitive insight:** No open-source, local CLI tool generates Ansible-aware SBOMs today. Steampunk Spotter is the only tool that understands Ansible content structure, but it is proprietary SaaS. APME fills a gap: an open, local, Ansible-native SBOM generator that produces standards-compliant output for existing vulnerability scanners.

## Sources

- [NTIA Minimum Elements for SBOM](https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom) - NTIA, 2021
- [CISA 2025 SBOM Minimum Elements Update](https://www.cisa.gov/sites/default/files/2025-08/2025_CISA_SBOM_Minimum_Elements.pdf) - CISA, 2025
- [CycloneDX 1.5 JSON Reference](https://cyclonedx.org/docs/1.5/json/) - OWASP CycloneDX
- [CycloneDX SBOM Capabilities](https://cyclonedx.org/capabilities/sbom/) - OWASP CycloneDX
- [PURL Specification](https://github.com/package-url/purl-spec) - package-url project
- [PURL Type Registry](https://github.com/package-url/purl-spec/blob/main/PURL-TYPES.rst) - package-url project
- [cyclonedx-python](https://github.com/CycloneDX/cyclonedx-python) - CycloneDX Python SBOM generator
- [Syft](https://github.com/anchore/syft) - Anchore SBOM generator
- [Steampunk Spotter SBOM + CVE](https://steampunk.si/spotter/blog/introducing-SBOM-CVE-analysis/) - XLAB Steampunk
- [Steampunk Spotter 5.0 Supply Chain](https://steampunk.si/spotter/blog/supply-chain-management-and-security-reports/) - XLAB Steampunk
- [OpenSSF Choosing an SBOM Tool](https://openssf.org/blog/2025/06/05/choosing-an-sbom-generation-tool/) - OpenSSF, 2025
- [SBOM Tools Comparison](https://sbomify.com/2026/01/26/sbom-generation-tools-comparison/) - Sbomify, 2026

---
*Feature research for: SBOM generation for Ansible automation content*
*Researched: 2026-03-25*
