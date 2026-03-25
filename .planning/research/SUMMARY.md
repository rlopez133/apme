# Project Research Summary

**Project:** APME SBOM Generation
**Domain:** Software Bill of Materials (SBOM) generation for Ansible automation content
**Researched:** 2026-03-25
**Confidence:** HIGH

## Executive Summary

APME needs to generate CycloneDX 1.5 JSON SBOMs for Ansible automation content (collections, roles, Python dependencies). This fills a critical gap: no open-source, local CLI tool currently generates Ansible-aware SBOMs. Steampunk Spotter does this but is proprietary SaaS-only. The recommended approach is a stdlib-only Python implementation (per ADR-014's zero-dependency constraint) that introspects session venvs via a new gRPC endpoint on the Primary service. The SBOM generator should be a library module invoked by Primary, not a separate validator service or CLI-local logic.

The key technical challenge is PURL generation for Ansible content: no official `pkg:ansible` type exists in the PURL spec. Research consensus is to use `pkg:generic/namespace/collection@version?repository_url=https://galaxy.ansible.com` for collections and roles, with `pkg:pypi/package@version` for Python dependencies. This pragmatic approach ensures downstream vulnerability scanners (Grype, Snyk, Dependency-Track) can consume the SBOMs.

Critical risks: (1) schema-valid but semantically empty SBOMs missing NTIA minimum elements, (2) incorrect component type classification causing scanners to skip components, (3) `bom-ref` collisions breaking dependency graphs. Mitigation: enforce "minimum viable component" contract (type + name + version + purl + bom-ref required), use `library` type consistently, use PURLs as bom-refs for uniqueness.

## Key Findings

### Recommended Stack

**Core: Python stdlib-only CycloneDX 1.5 JSON generator.** No external libraries. Hand-rolled serialization using `json`, `uuid`, `datetime`, `dataclasses`, `pathlib`, and `importlib.metadata`.

**Core technologies:**
- **json module**: CycloneDX JSON serialization — stdlib, zero-config, handles all JSON types
- **uuid module**: Generate RFC 4122 UUID v4 serial numbers — `uuid.uuid4().urn` produces `urn:uuid:...` directly
- **datetime module**: ISO 8601 timestamps — `datetime.now(timezone.utc).isoformat()`
- **dataclasses**: BOM/Component data models — clean modeling with custom `to_dict()` for hyphenated JSON keys
- **importlib.metadata**: Enumerate installed Python packages from venv — stdlib since Python 3.8, no subprocess needed
- **pathlib**: Collection/role discovery — modern filesystem introspection

**What NOT to use:**
- `cyclonedx-python-lib` — violates ADR-014 (stdlib-only), pulls in 3+ dependencies
- `packageurl-python` — PURL construction is trivial f-strings, not worth a dependency
- `jsonschema` — validation belongs in tests only; vendor the schema file, don't add runtime dependency

### Expected Features

**Must have (table stakes):**
- CycloneDX 1.5 JSON output with NTIA minimum fields — federal mandate (EO 14028) and EU CRA compliance requirement
- Collection inventory (name, namespace, version) — collections are primary Ansible distribution unit
- Python dependency inventory — vulnerability scanners need full dependency tree
- Role inventory (name, version, source) — still widely used in brownfield AAP 2.5+ migrations
- PURL identifiers for all components — de facto standard for vulnerability database matching
- `--output`/`-o` file flag with stdout default — Unix pipeline composability (pipe to `grype`/`snyk`)
- `--session` flag for venv reuse — consistent with existing APME CLI patterns
- Valid JSON schema compliance — downstream tools validate and reject non-conformant SBOMs

**Should have (competitive differentiators):**
- Ansible-aware component classification — map FQCN to CycloneDX `group`/`name` fields (no other SBOM tool does this)
- Dependency relationship graph — CycloneDX `dependencies[]` showing inter-collection deps from `galaxy.yml`
- Galaxy source tracking — record provenance (Galaxy, Automation Hub, private) via `externalReferences[]`
- Integration with existing APME session — reuse `scan`/`fix` venv for zero-redownload SBOM generation
- Human-readable summary mode — `--summary` flag prints table to stderr while JSON goes to stdout

**Defer (v2+):**
- SPDX format output — CycloneDX-to-SPDX conversion tools exist (`cyclonedx-cli convert`)
- Built-in CVE/vulnerability lookup — users already have preferred scanners, adds external API dependencies
- License compliance analysis — separate domain, dedicated tooling exists (FOSSA, FOSSology)
- SBOM signing — requires org-specific key management, external signing with `cosign`/`gpg` is cleaner
- Dashboard/web UI — PROJECT.md defers dashboard integration

### Architecture Approach

**SBOM generation must live in Primary, accessed via gRPC — not CLI-local.** Session venvs are managed exclusively by Primary and live under `$APME_COLLECTION_CACHE/sessions/{session_id}/{core_version}/venv/`. In container deployments, CLI cannot access the sessions volume. CLI-local generation would break the architecture.

**Major components:**
1. **src/apme_engine/cli/sbom.py** — Parse `sbom` subcommand args, call Primary gRPC, write CycloneDX JSON to stdout/file
2. **src/apme_engine/sbom/** (new module) — Enumerate collections/roles/Python deps from venv, build CycloneDX 1.5 JSON document (library, not service)
3. **src/apme_engine/daemon/primary_server.py** — Handle new `Sbom` RPC, acquire/reuse session venv, invoke sbom generator
4. **proto/apme/v1/primary.proto** — Define `SbomRequest`/`SbomResponse` messages

**Data sources:**
- Collections: `.dist-info/METADATA` in venv site-packages (primary), `MANIFEST.json`/`galaxy.yml` (fallback)
- Python deps: `importlib.metadata.distributions()` pointed at venv site-packages
- Roles: target directory `roles/*/meta/main.yml` and `requirements.yml` (CLI-discovered, sent in request)

**Why not a separate validator service:** SBOM is read-only but not detection/violation work. Forcing it into the `Validator` interface violates ADR-009's semantics.

### Critical Pitfalls

1. **No registered PURL type for Ansible Galaxy collections** — Using invented `pkg:ansible/...` silently breaks vulnerability scanners. Fix: use `pkg:generic/namespace/collection@version?repository_url=https://galaxy.ansible.com` and `pkg:pypi/package@version` for Python deps. Document in ADR.

2. **Schema-valid but semantically empty SBOMs** — CycloneDX 1.5 schema is permissive (nearly everything optional), but NTIA minimum elements are regulatory requirements. Fix: enforce internal "minimum viable component" contract (every component MUST have type + name + version + purl + bom-ref). Write validation function checked before serialization.

3. **Incorrect CycloneDX component type classification** — Using `framework` or `application` inconsistently causes Trivy/Dependency-Track to skip components. Fix: use `library` type for all collections, roles, and Python deps. Document in ADR alongside PURL decision.

4. **bom-ref collisions breaking dependency graphs** — Duplicate `bom-ref` values cause validator rejection. Fix: use PURL as `bom-ref` value (inherently unique, includes namespace + version). Fall back to `uuid.uuid4()` only when PURL unavailable.

5. **Stdlib JSON serialization producing non-conformant output** — `json.dumps()` naively serializes `None` as `null`, but CycloneDX expects field absence. Fix: strip None/empty values before serialization with dict-cleaning function: `{k: v for k, v in d.items() if v is not None and v != [] and v != {}}`.

6. **Extracting wrong version info from venv-installed collections** — Git-installed or local collections may have incomplete metadata. Fix: read `MANIFEST.json` (primary), fall back to `galaxy.yml`, use `"0.0.0"` for missing versions with property noting `"cdx:sbom:version-source": "unknown"`.

## Implications for Roadmap

Based on research, suggested phase structure with 4 phases:

### Phase 1: Core Data Model and PURL Strategy
**Rationale:** Foundation for everything — get PURL format and component schema wrong and every SBOM is useless. Zero dependencies on other phases.

**Delivers:**
- CycloneDX 1.5 data model (Bom, Component dataclasses)
- PURL generation functions (pypi_purl, collection_purl, role_purl)
- Component type classification logic (`library` for all)
- `bom-ref` uniqueness strategy (PURLs as refs)
- Validation function enforcing minimum viable component contract

**Addresses:**
- PURL identifiers (table stakes from FEATURES.md)
- NTIA minimum fields requirement
- Stdlib-only constraint (ADR-014)

**Avoids:**
- Pitfall 1 (wrong PURL type)
- Pitfall 3 (wrong component type)
- Pitfall 4 (bom-ref collisions)

**Research flag:** Standard patterns (skip deep research) — CycloneDX spec is well-documented, PURL format is defined in spec.

### Phase 2: Venv Introspection and Inventory Collection
**Rationale:** Cannot generate SBOMs without component data. Depends on Phase 1 data models to structure the collected information.

**Delivers:**
- Collection enumeration from venv site-packages (importlib.metadata)
- Python dependency enumeration from venv site-packages
- Role discovery from target directory (meta/main.yml parsing)
- Metadata extraction (version, license, author from .dist-info)
- Graceful handling of missing/incomplete metadata

**Uses:**
- importlib.metadata (STACK.md stdlib recommendation)
- pathlib for filesystem traversal
- Phase 1 data models to structure findings

**Implements:**
- src/apme_engine/sbom/ module (ARCHITECTURE.md component boundary)

**Avoids:**
- Pitfall 6 (wrong version extraction)

**Research flag:** Standard patterns (skip deep research) — importlib.metadata is well-documented stdlib.

### Phase 3: CycloneDX Serialization and Validation
**Rationale:** Must serialize data models to valid JSON. Depends on Phase 1 models and Phase 2 inventory to have data to serialize.

**Delivers:**
- JSON serialization with None/empty value stripping
- UUID v4 serial number generation
- ISO 8601 timestamp generation
- metadata.tools identification (APME as generator)
- Schema validation (test-time only, vendor schema file)

**Uses:**
- json, uuid, datetime from stdlib (STACK.md)
- Phase 1 data models
- Phase 2 inventory data

**Avoids:**
- Pitfall 2 (semantically empty SBOMs)
- Pitfall 5 (JSON non-conformance)

**Research flag:** Standard patterns (skip deep research) — stdlib JSON serialization is straightforward.

### Phase 4: gRPC Integration and CLI Wiring
**Rationale:** Last because it depends on all prior phases. Connects the SBOM generator to the existing APME architecture.

**Delivers:**
- proto/apme/v1/primary.proto additions (SbomRequest, SbomResponse, Sbom RPC)
- Primary server handler (acquire venv, invoke generator, return JSON)
- CLI subcommand (parse args, call Primary gRPC, write output)
- --output/-o flag and stdout default
- --session flag integration

**Uses:**
- Existing VenvSessionManager (ARCHITECTURE.md)
- Existing gRPC patterns (ADR-001, ADR-007)
- Phases 1-3 complete SBOM generator

**Implements:**
- gRPC contract (ARCHITECTURE.md component boundary)
- CLI presentation layer

**Avoids:**
- Anti-pattern: CLI-local venv access (ARCHITECTURE.md)
- Anti-pattern: Separate SBOM microservice

**Research flag:** Standard patterns (skip deep research) — follows existing scan/format/fix gRPC patterns.

### Phase Ordering Rationale

- **Phase 1 first:** Zero external dependencies. Defines output contract. Every other phase feeds into it. Get PURL strategy wrong and all downstream work is wasted.
- **Phases 2 and 3 could be parallel:** But Phase 3 needs real data for validation testing, so Phase 2 should complete first.
- **Phase 4 last:** Pure integration work, depends on functioning generator from Phases 1-3.

This order avoids heavyweight prototyping: CycloneDX generation is pure data transformation, so building the data model first enables test-driven development of inventory and serialization.

### Research Flags

**Phases with standard patterns (skip research-phase):**
- **Phase 1:** CycloneDX spec and PURL spec are authoritative references, well-documented
- **Phase 2:** importlib.metadata and pathlib are stdlib, extensive documentation
- **Phase 3:** JSON serialization is standard library, no exotic patterns
- **Phase 4:** gRPC patterns already established in APME codebase (ADR-001, ADR-007)

**No phases need deeper research.** All technical questions resolved by this research sweep.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | All stdlib modules, no version concerns, ADR-014 constraint explicit |
| Features | HIGH | NTIA requirements well-defined, competitive analysis clear (Steampunk Spotter comparison) |
| Architecture | HIGH | Existing APME patterns (gRPC, session venv) map cleanly to SBOM needs |
| Pitfalls | MEDIUM-HIGH | CycloneDX pitfalls well-documented in community sources; PURL strategy for Ansible content has MEDIUM confidence (no official type) |

**Overall confidence:** HIGH

### Gaps to Address

**PURL format for Ansible content (MEDIUM confidence gap):**
- No registered `pkg:ansible` type exists in PURL spec
- Using `pkg:generic/namespace/collection@version?repository_url=...` is pragmatic but not standardized
- Downstream vulnerability scanners may not match Ansible collections even with valid PURLs (no CVE database coverage for Ansible collections yet)
- **Handling:** Document decision in ADR. Include note in SBOM output (metadata.properties) that Ansible components use pkg:generic. Test with at least two scanners (Grype, Snyk) to verify consumption.

**Dependency graph implementation (deferred to Phase 2 or post-MVP):**
- CycloneDX `dependencies[]` array structure is clear, but extracting inter-collection dependencies from `galaxy.yml` requires parsing collection metadata
- Complexity: MEDIUM (not hard, but increases scope)
- **Handling:** Defer to v1.x if not essential for launch. Flat component list is valid and useful SBOM without dependency graph.

**Execution Environment detection (deferred to future):**
- EE metadata in `execution-environment.yml` could enrich SBOM provenance
- Complexity: HIGH (requires understanding EE build process)
- **Handling:** Explicitly defer to v2+ per FEATURES.md recommendation.

## Sources

### Primary (HIGH confidence)
- [CycloneDX 1.5 JSON Reference](https://cyclonedx.org/docs/1.5/json/) — official spec reference
- [CycloneDX 1.5 JSON Schema (GitHub)](https://github.com/CycloneDX/specification/blob/1.5/schema/bom-1.5.schema.json) — authoritative schema
- [PURL Specification](https://github.com/package-url/purl-spec) — Package URL standard
- [PURL Known Types](https://github.com/package-url/purl-spec/blob/main/PURL-TYPES.rst) — confirms no `pkg:ansible` type
- [NTIA Minimum Elements for SBOM](https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom) — regulatory requirements
- [Python uuid module docs](https://docs.python.org/3/library/uuid.html) — stdlib UUID generation
- [Python importlib.metadata docs](https://docs.python.org/3/library/importlib.metadata.html) — venv introspection
- APME codebase: ADR-014 (stdlib-only constraint), ADR-001 (gRPC), ADR-007 (async gRPC), ADR-009 (validator contract)

### Secondary (MEDIUM confidence)
- [CycloneDX BOM Examples](https://github.com/CycloneDX/bom-examples) — reference structures
- [CycloneDX Authoritative Guide to SBOM](https://cyclonedx.org/guides/sbom/relationships/) — best practices for bom-ref and dependency graphs
- [OpenSSF: Choosing an SBOM Generation Tool](https://openssf.org/blog/2025/06/05/choosing-an-sbom-generation-tool/) — tool comparison and evaluation criteria
- [Steampunk Spotter SBOM + CVE](https://steampunk.si/spotter/blog/introducing-SBOM-CVE-analysis/) — competitor feature analysis
- [Trivy unsupported framework component type (Discussion #7418)](https://github.com/aquasecurity/trivy/discussions/7418) — component type pitfall evidence

### Tertiary (LOW confidence)
- [5 Common SBOM Mistakes to Avoid](https://finitestate.io/blog/sbom-mistakes) — general pitfalls (not Ansible-specific)
- [Top 5 Things People Get Wrong About SBOM Generation](https://www.medcrypt.com/blog/top-5-things-people-get-wrong-about-sbom-generation) — practitioner experiences

---
*Research completed: 2026-03-25*
*Ready for roadmap: yes*
