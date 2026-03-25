# Architecture Patterns

**Domain:** SBOM generation for Ansible automation content (CycloneDX 1.5)
**Researched:** 2026-03-25

## Recommended Architecture

**SBOM generation should live in Primary, accessed via gRPC -- not CLI-local.**

The critical insight is that the data SBOM needs (installed collections, Python dependencies) lives inside session-scoped venvs managed exclusively by Primary. The CLI has no direct filesystem access to venvs -- they live under `$APME_COLLECTION_CACHE/sessions/{session_id}/{core_version}/venv/`. In container deployments, the CLI container does not mount the sessions volume. Attempting CLI-local SBOM generation would require either duplicating venv access logic or adding a new filesystem coupling that contradicts the existing architecture.

### Why Not a Separate Validator Service

SBOM generation is not validation. Validators implement the `Validator` gRPC service interface and return `ValidateResponse` with violations. SBOM generation produces a completely different output shape (CycloneDX JSON document). Forcing it into the validator model would violate ADR-009's read-only validator contract semantically -- SBOM is read-only but is not detection/violation work.

### Recommended: New RPC on Primary Service

Add an `Sbom` RPC to the `Primary` gRPC service. This follows the same pattern as `Scan`, `Format`, and `Health` -- Primary is "the sole API surface for all clients" (per the proto comments). The SBOM generator is a library module invoked by Primary, same as the engine or formatter.

```
┌──────────┐  SbomRequest   ┌──────────┐
│   CLI    │ ─────────────> │ Primary  │
│          │ <───────────── │  :50051  │
└──────────┘  SbomResponse  │          │
                            │ ┌──────┐ │
                            │ │ sbom │ │  (library, not service)
                            │ │ gen  │ │
                            │ └──┬───┘ │
                            │    │     │
                            │ ┌──┴───┐ │
                            │ │ venv │ │
                            │ │ mgr  │ │
                            └─┴──────┴─┘
```

### Component Boundaries

| Component | Responsibility | Communicates With |
|-----------|---------------|-------------------|
| `src/apme_engine/cli/sbom.py` | Parse `sbom` subcommand args, call Primary, write CycloneDX JSON to stdout/file | Primary (gRPC) |
| `src/apme_engine/sbom/` (new module) | Enumerate collections/roles/Python deps from venv; build CycloneDX 1.5 JSON document | VenvSessionManager, filesystem |
| `src/apme_engine/daemon/primary_server.py` | Handle `Sbom` RPC; acquire/reuse session venv; invoke sbom generator | sbom module, venv_manager |
| `proto/apme/v1/primary.proto` | Define `SbomRequest`/`SbomResponse` messages | All gRPC consumers |

## Data Sources for Each Component Type

### Collections (installed in session venv)

**Source 1 -- Session meta.json (HIGH confidence):**
The `VenvSession.installed_collections` field in `meta.json` tracks which collection specs were installed. This gives FQCN and version (e.g., `community.general:9.0.0`). Available via `VenvSessionManager.get(session_id, ansible_version)`.

**Source 2 -- dist-info in site-packages (HIGH confidence):**
Collections are installed as pip packages via Galaxy Proxy. Each collection has a `.dist-info/METADATA` file in `site-packages/` containing PEP 566 metadata: Name, Version, License, Author, Requires-Dist. This is the authoritative source for version, license, and dependency data. Access via `_venv_site_packages(venv_root)` which returns the site-packages path.

**Source 3 -- ansible_collections directory tree (HIGH confidence):**
The actual collection content lives at `site-packages/ansible_collections/{namespace}/{name}/`. Each collection has a `MANIFEST.json` or `galaxy.yml` with metadata. Useful for collection-level detail not captured in dist-info.

**Recommended approach:** Use dist-info METADATA as primary source (already structured, has version+license+deps). Fall back to `ansible_collections/{ns}/{name}/MANIFEST.json` for supplementary fields. Use `meta.json` only to enumerate which collections are expected.

**PURL format:** No registered PURL type for Ansible Galaxy collections. Use `pkg:generic/{namespace}.{collection}@{version}?repository_url=https://galaxy.ansible.com` -- this is the pragmatic choice. LOW confidence on whether a better convention emerges.

### Roles (from target directory)

**Source -- target project filesystem (HIGH confidence):**
Roles are discovered from the scan target directory, not the venv. The engine's `load_role()` function reads:
- `meta/main.yml` -- role metadata (author, license, dependencies, min_ansible_version)
- `requirements.yml` -- role-level dependency declarations
- Directory structure convention: `roles/{role_name}/` with `tasks/`, `handlers/`, `defaults/`, `vars/`, `meta/`

Roles in the target project are local (not installed via Galaxy), so version data may be absent. The SBOM should record what is available:
- `name` from directory name
- `version` from `meta/main.yml` if present (often not)
- `description` from `meta/main.yml`

**PURL format:** `pkg:generic/{role_name}@{version}` if version available, otherwise no version qualifier.

### Python Dependencies (from session venv)

**Source -- pip freeze / importlib.metadata in venv (HIGH confidence):**
The session venv contains all Python packages (ansible-core + collection Python deps). Two enumeration approaches:

1. **`pip freeze` / `uv pip freeze`** -- subprocess call using `get_venv_python(venv_root)`. Returns all installed packages with versions. Simple, reliable.
2. **`importlib.metadata.distributions()`** -- Python stdlib. Can enumerate dist-info directories directly from `site-packages/`. No subprocess needed. Works with the stdlib-only constraint (ADR-014).

**Recommended approach:** Use `importlib.metadata` pointed at the venv's site-packages path. This avoids subprocess overhead, works with the stdlib-only constraint, and gives access to full METADATA (license, author, homepage). The `_venv_site_packages()` helper already exists.

**Filtering:** Separate collection packages (those matching `ansible-collection-*` prefix, detectable via `galaxy_proxy.naming.is_collection_package()`) from pure Python dependencies. Report collections under `type: library` with Ansible-specific metadata; report Python deps under `type: library` with PyPI purl.

**PURL format:** `pkg:pypi/{package_name}@{version}` -- standard, well-supported by all vulnerability scanners (Snyk, Grype, etc.).

## Data Flow

### SBOM Request Flow

1. CLI parses `apme-scan sbom [target]` with `--session`, `--ansible-version`, `--collections` flags
2. CLI resolves session ID (same logic as scan: explicit `--session` or hash of project root)
3. CLI reads target directory to discover role metadata locally (or sends file list to Primary)
4. CLI sends `SbomRequest` to Primary via gRPC
5. Primary acquires/reuses session venv via `VenvSessionManager.acquire()`
6. Primary invokes `sbom.generate()` passing:
   - `venv_root` path (for collection + Python dep enumeration)
   - `VenvSession` metadata (session_id, ansible_version, installed_collections)
   - Role metadata (from target directory files, sent in request or discovered server-side)
7. SBOM generator:
   a. Enumerates `.dist-info/` directories in site-packages
   b. Separates collection packages from Python packages using `is_collection_package()`
   c. Reads METADATA from each dist-info for version, license, author
   d. Builds CycloneDX 1.5 JSON with `components[]` array
   e. Generates PURLs per component type
8. Primary returns `SbomResponse` containing CycloneDX JSON bytes
9. CLI writes to stdout (default) or file (`--output/-o`)

### Key Decision: Where to Discover Roles

Two options for role discovery:

**Option A (recommended): CLI sends role metadata in SbomRequest.**
The CLI already reads project files for scan. It can parse `roles/*/meta/main.yml` and include role metadata in the request. This keeps Primary venv-focused and avoids sending all project files just for SBOM.

**Option B: Primary discovers roles from files.**
Primary already receives project files for scan. If the SBOM command reuses the scan chunking flow, Primary can discover roles the same way the engine does. This duplicates some engine logic but is self-contained.

Recommendation: Option A. The SBOM request is lightweight -- send structured role metadata, not raw files. This avoids the heavyweight scan chunking flow for a simple inventory operation.

## Patterns to Follow

### Pattern 1: Session Venv Reuse
**What:** SBOM uses the same `--session` flag and session resolution as `scan`/`fix`/`format`. If the user already ran a scan, the venv is warm and SBOM generation is nearly instant.
**When:** Always. SBOM without a venv has nothing to enumerate.
**Why:** Consistency with existing CLI UX. No new venv lifecycle concepts.

### Pattern 2: Stdlib-Only CycloneDX Generation
**What:** Build CycloneDX 1.5 JSON using `json` module from stdlib. No `cyclonedx-python-lib`.
**When:** Per ADR-014 zero-external-dependency constraint.
**Example:**
```python
import json
import uuid

def build_cdx_document(components: list[dict]) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tools": [{"name": "apme", "version": __version__}],
        },
        "components": components,
    }
```

### Pattern 3: importlib.metadata for Venv Introspection
**What:** Use stdlib `importlib.metadata` to read dist-info from venv site-packages without subprocess.
**When:** Enumerating Python packages and collection packages from venv.
**Example:**
```python
import importlib.metadata
import sys

def enumerate_venv_packages(site_packages_path: str) -> list:
    # Point importlib.metadata at the venv's site-packages
    sys.path.insert(0, site_packages_path)
    try:
        return list(importlib.metadata.distributions(path=[site_packages_path]))
    finally:
        sys.path.pop(0)
```

## Anti-Patterns to Avoid

### Anti-Pattern 1: CLI-Local Venv Access
**What:** Having the CLI directly read venv directories to enumerate packages.
**Why bad:** Breaks the architecture -- CLI is a pure gRPC presentation layer. In container mode, CLI cannot access the sessions volume. Creates coupling that will break when deployment topology changes.
**Instead:** Route through Primary, which already owns venv lifecycle.

### Anti-Pattern 2: Running a Full Scan for SBOM
**What:** Invoking the ARI engine scan pipeline just to get dependency information for SBOM.
**Why bad:** Scan is heavyweight (parse AST, build hierarchy, fan out to validators). SBOM only needs venv package metadata and role directory structure.
**Instead:** Add a dedicated `Sbom` RPC that acquires the venv and introspects it directly, skipping the engine entirely.

### Anti-Pattern 3: Separate SBOM Microservice
**What:** Creating a new container/service for SBOM generation.
**Why bad:** SBOM needs direct filesystem access to the sessions volume. Adding another service that mounts this volume increases attack surface and operational complexity for what is a simple read-only introspection.
**Instead:** Keep it as a library module invoked by Primary.

## Suggested Build Order

Dependencies flow top-to-bottom. Each layer depends on the one above it.

```
Phase 1: CycloneDX document builder (stdlib-only)
   └── Pure functions: build_cdx_document(), component_to_cdx(), purl_for_*()
   └── No I/O, no gRPC, no venv access
   └── Fully unit-testable in isolation

Phase 2: Venv introspection collectors
   └── enumerate_collections(site_packages_path) -> list[CollectionInfo]
   └── enumerate_python_deps(site_packages_path) -> list[PythonDepInfo]
   └── Uses importlib.metadata, galaxy_proxy.naming
   └── Depends on: Phase 1 data models

Phase 3: Role discovery from project files
   └── discover_roles(target_path) -> list[RoleInfo]
   └── Reads meta/main.yml, requirements.yml
   └── Can reuse engine's load_role() patterns or be standalone
   └── Depends on: Phase 1 data models

Phase 4: gRPC contract (proto + codegen)
   └── SbomRequest / SbomResponse messages in primary.proto
   └── Sbom RPC on Primary service
   └── Depends on: Phase 1-3 data models to inform message shape

Phase 5: Primary server handler + CLI subcommand
   └── Primary.Sbom() handler: acquire venv, call collectors, build document
   └── CLI sbom.py: parse args, call Primary, write output
   └── Depends on: Phase 1-4
```

**Phase ordering rationale:**
- Phase 1 first because it has zero dependencies and defines the output contract. Every other phase feeds into it.
- Phases 2 and 3 can be parallelized -- they are independent collectors that produce data for Phase 1.
- Phase 4 (proto) should come after the collector data models are finalized, so the gRPC messages accurately reflect what data flows.
- Phase 5 is integration -- wiring everything together through the existing Primary/CLI architecture.

## Proto Message Sketch

```protobuf
// Add to primary.proto

rpc Sbom(SbomRequest) returns (SbomResponse);

message SbomRequest {
  string session_id = 1;
  string ansible_core_version = 2;
  repeated string collection_specs = 3;
  repeated RoleMetadata roles = 4;  // CLI-discovered role info
}

message RoleMetadata {
  string name = 1;
  string version = 2;
  string description = 3;
  string license = 4;
  string path = 5;
}

message SbomResponse {
  bytes cdx_json = 1;           // CycloneDX 1.5 JSON document
  int32 component_count = 2;
  string session_id = 3;
}
```

## Scalability Considerations

| Concern | Typical project | Large enterprise |
|---------|----------------|-----------------|
| Collection count | 5-20 collections | 50-100+ collections |
| Python deps | 30-50 packages | 100-200 packages |
| Roles | 5-10 roles | 50-100 roles |
| Venv introspection time | <100ms | <500ms |
| SBOM document size | 10-50 KB | 200-500 KB |
| Memory | Negligible | Negligible |

SBOM generation is inherently lightweight -- it reads metadata files, not content. No performance concerns at any realistic scale.

## Sources

- APME codebase: `src/apme_engine/venv_manager/session.py` -- venv storage layout, meta.json structure, VenvSession dataclass
- APME codebase: `src/galaxy_proxy/naming.py` -- collection package naming conventions, `is_collection_package()`
- APME codebase: `src/galaxy_proxy/metadata.py` -- PEP 566 METADATA generation for collections
- APME codebase: `src/apme_engine/daemon/primary_server.py` -- scan pipeline, venv acquire flow, site-packages access
- APME codebase: `src/apme_engine/engine/model_loader.py` -- role loading, meta/main.yml parsing
- APME codebase: `proto/apme/v1/primary.proto` -- existing RPC patterns
- [CycloneDX 1.5 JSON Reference](https://cyclonedx.org/docs/1.5/json/) -- specification
- [PURL Types Registry](https://github.com/package-url/purl-spec/blob/main/PURL-TYPES.rst) -- no registered Ansible type; use `generic` or `pypi`
- [PURL Specification](https://github.com/package-url/purl-spec/blob/main/PURL-SPECIFICATION.rst) -- format rules

---

*Architecture analysis: 2026-03-25*
