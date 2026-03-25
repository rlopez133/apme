# Technology Stack: SBOM Generation for APME

**Project:** APME SBOM Generation (`apme-scan sbom`)
**Researched:** 2026-03-25
**Mode:** Ecosystem (stack dimension)

## Recommended Stack

### Core: Python stdlib-only CycloneDX 1.5 JSON Generator

No external libraries. The generator is a hand-rolled module that emits CycloneDX 1.5 JSON using only Python's standard library.

| Module | stdlib | Purpose | Why |
|--------|--------|---------|-----|
| `json` | Yes | Serialize BOM to JSON | Native, zero-config, handles all JSON types |
| `uuid` | Yes | Generate `serialNumber` (RFC 4122 UUID v4) | `uuid.uuid4().urn` produces `urn:uuid:...` format directly |
| `datetime` | Yes | Generate `metadata.timestamp` in ISO 8601 | `datetime.datetime.now(datetime.timezone.utc).isoformat()` |
| `dataclasses` | Yes | Structured BOM/Component models | Clean data modeling, `asdict()` for serialization |
| `pathlib` | Yes | File discovery (collections, roles, requirements) | Modern path handling |
| `importlib.metadata` | Yes | Read installed Python package metadata from venv | Available since Python 3.8 |

**Confidence: HIGH** -- all stdlib modules, no version concerns.

### What NOT to Use

| Library | Why Excluded |
|---------|-------------|
| `cyclonedx-python-lib` | Violates ADR-014 (stdlib-only constraint). Pulls in `sortedcontainers`, `license-expression`, `py-serializable`. Overkill for inventory-only BOM generation. |
| `jsonschema` | Not needed at runtime. Schema validation belongs in tests only, and even there, vendor the schema file rather than adding a pip dependency. |
| `packageurl-python` | PURL construction is trivial string formatting. This library adds a dependency for `f"pkg:pypi/{name}@{version}"`. Not worth it. |
| `requests` / `httpx` | No network calls needed. Collection/role metadata comes from the local venv and Galaxy Proxy (already accessible via gRPC). |

**Confidence: HIGH** -- constraint is explicit in ADR-014 and PROJECT.md.

## CycloneDX 1.5 JSON Schema Reference

### Top-Level BOM Structure (Required Fields)

Per the [official schema](https://github.com/CycloneDX/specification/blob/1.5/schema/bom-1.5.schema.json), a valid CycloneDX 1.5 BOM requires:

| Field | Type | Required | Value |
|-------|------|----------|-------|
| `$schema` | string | No (recommended) | `"http://cyclonedx.org/schema/bom-1.5.schema.json"` |
| `bomFormat` | string | **YES** | Must be `"CycloneDX"` (exact string) |
| `specVersion` | string | **YES** | Must be `"1.5"` |
| `version` | integer | **YES** | BOM version, minimum 1, default 1 |
| `serialNumber` | string | No (SHOULD) | `urn:uuid:<uuid4>` matching `^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$` |
| `metadata` | object | No (recommended) | Timestamp, tools, component info |
| `components` | array | No | Array of component objects |

**Confidence: HIGH** -- verified against the [1.5 branch schema](https://github.com/CycloneDX/specification/blob/1.5/schema/bom-1.5.schema.json) and [CycloneDX 1.5 JSON Reference](https://cyclonedx.org/docs/1.5/json/).

### Metadata Object Structure

```json
{
  "metadata": {
    "timestamp": "2026-03-25T14:30:00+00:00",
    "tools": {
      "components": [
        {
          "type": "application",
          "name": "apme-scan",
          "version": "0.5.0"
        }
      ]
    }
  }
}
```

Key metadata fields for APME:
- `timestamp` -- ISO 8601 datetime (use `datetime.timezone.utc`)
- `tools.components[]` -- identifies the tool that generated the BOM (APME itself)
- `component` -- optional, describes the top-level thing being scanned

### Component Object Structure

Only `type` and `name` are required. All other fields are optional but strongly recommended for useful SBOMs.

| Field | Type | Required | Purpose |
|-------|------|----------|---------|
| `type` | enum | **YES** | Component classification |
| `name` | string | **YES** | Component name |
| `version` | string | No | Component version (ideally semver) |
| `group` | string | No | Namespace/organization grouping |
| `purl` | string | No | Package URL identifier |
| `bom-ref` | string | No | Unique reference within BOM (use PURL as value) |
| `description` | string | No | Component description |
| `scope` | enum | No | `required`, `optional`, `excluded` |

### Component Type Values (enum)

Use these CycloneDX component types for APME inventory:

| APME Content | CycloneDX `type` | Rationale |
|--------------|-------------------|-----------|
| Ansible collection | `library` | Collections are reusable libraries of modules/roles |
| Ansible role | `library` | Roles are reusable automation units |
| Python package | `library` | Standard for pip-installed packages |
| The scanned project itself | `application` | Top-level application being inventoried |

Use `library` for all inventory items. Some downstream tools (GitLab, Mend) only process `library` type components.

**Confidence: HIGH** -- verified against official schema.

## PURL Formats for APME Content Types

### PyPI Packages

**Format:** `pkg:pypi/<lowercased-name>@<version>`

Rules:
- Type is `pypi` (not `pip`)
- Name MUST be lowercased (PyPI normalization)
- Replace underscores and hyphens consistently: use `-` (e.g., `ansible-core` not `ansible_core`)
- No namespace component

Examples:
```
pkg:pypi/ansible-core@2.16.3
pkg:pypi/jinja2@3.1.2
pkg:pypi/pyyaml@6.0.1
pkg:pypi/cryptography@42.0.5
```

**Confidence: HIGH** -- `pkg:pypi` is a registered PURL type with clear [spec rules](https://github.com/package-url/purl-spec).

### Ansible Collections

**There is no registered `pkg:ansible` or `pkg:galaxy` PURL type.** Use `pkg:generic` with qualifiers.

**Format:** `pkg:generic/<namespace>/<collection-name>@<version>?download_url=<source_url>`

Rules:
- Type is `generic` (catch-all for unregistered ecosystems)
- Namespace is the Galaxy namespace (e.g., `amazon`, `community`)
- Name is the collection name (e.g., `aws`, `general`)
- `download_url` qualifier points to the source (Galaxy URL or private Automation Hub)

Examples:
```
pkg:generic/amazon/aws@7.0.0?download_url=https://galaxy.ansible.com
pkg:generic/community/general@9.0.0?download_url=https://galaxy.ansible.com
pkg:generic/ansible/netcommon@6.1.0?download_url=https://galaxy.ansible.com
```

Alternative with `repository_url` qualifier (also valid):
```
pkg:generic/amazon/aws@7.0.0?repository_url=https://galaxy.ansible.com
```

**Confidence: MEDIUM** -- `pkg:generic` is the correct fallback per the PURL spec, but there is no established convention for Ansible content in PURLs. The namespace/name split mirrors Galaxy's `namespace.collection` convention. Downstream scanners (Grype, Snyk) may not recognize these PURLs for vulnerability matching, which is acceptable since APME's SBOM is inventory-only.

### Ansible Roles

**Format:** `pkg:generic/<namespace>/<role-name>@<version>?download_url=<source_url>`

Same pattern as collections. For roles without a Galaxy namespace (local roles), omit namespace:

```
pkg:generic/geerlingguy/docker@7.1.0?download_url=https://galaxy.ansible.com
pkg:generic/local-role@0.0.0
```

For roles discovered in the target directory without version info, use `"0.0.0"` or omit the version qualifier.

**Confidence: MEDIUM** -- same rationale as collections.

## Generating Valid UUIDs and Serial Numbers

### Serial Number Generation

```python
import uuid

serial_number = uuid.uuid4().urn
# Produces: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
```

The `.urn` property on Python's `uuid.UUID` object directly outputs the `urn:uuid:...` format that CycloneDX requires. No string formatting needed.

**Pattern requirement:** `^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`

Python's `uuid4().urn` produces lowercase hex, which matches this pattern.

### bom-ref Generation

Use the PURL string as `bom-ref` for components (it is both unique and human-readable). For components without a PURL, fall back to `str(uuid.uuid4())`.

**Confidence: HIGH** -- Python stdlib `uuid` module behavior is well-documented.

## Minimal Valid BOM Template

```json
{
  "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "metadata": {
    "timestamp": "2026-03-25T14:30:00+00:00",
    "tools": {
      "components": [
        {
          "type": "application",
          "name": "apme-scan",
          "version": "0.5.0"
        }
      ]
    }
  },
  "components": [
    {
      "type": "library",
      "name": "aws",
      "group": "amazon",
      "version": "7.0.0",
      "purl": "pkg:generic/amazon/aws@7.0.0?download_url=https://galaxy.ansible.com",
      "bom-ref": "pkg:generic/amazon/aws@7.0.0?download_url=https://galaxy.ansible.com"
    },
    {
      "type": "library",
      "name": "ansible-core",
      "version": "2.16.3",
      "purl": "pkg:pypi/ansible-core@2.16.3",
      "bom-ref": "pkg:pypi/ansible-core@2.16.3"
    }
  ]
}
```

## Schema Validation Strategy (Tests Only)

Download the schema once into the test fixtures, do not add `jsonschema` as a runtime dependency.

**Schema URL:** `https://raw.githubusercontent.com/CycloneDX/specification/1.5/schema/bom-1.5.schema.json`

For testing, use the CycloneDX CLI tool (`cyclonedx-cli validate`) or embed the schema JSON file and use Python's `jsonschema` as a dev dependency.

```bash
# Download schema for test fixtures (one-time)
curl -o tests/fixtures/bom-1.5.schema.json \
  https://raw.githubusercontent.com/CycloneDX/specification/1.5/schema/bom-1.5.schema.json
```

**Confidence: HIGH** -- schema is published under Apache 2.0, safe to vendor in test fixtures.

## Python Data Model Approach

Use `dataclasses` with a `to_dict()` method that feeds into `json.dumps()`:

```python
from dataclasses import dataclass, field, asdict
from typing import Optional
import json
import uuid
import datetime

@dataclass
class Component:
    type: str  # "library", "application"
    name: str
    version: Optional[str] = None
    group: Optional[str] = None
    purl: Optional[str] = None
    bom_ref: Optional[str] = None
    description: Optional[str] = None

    def to_dict(self) -> dict:
        d = {}
        d["type"] = self.type
        d["name"] = self.name
        if self.version:
            d["version"] = self.version
        if self.group:
            d["group"] = self.group
        if self.purl:
            d["purl"] = self.purl
        if self.bom_ref:
            d["bom-ref"] = self.bom_ref  # Note: hyphen in JSON key
        if self.description:
            d["description"] = self.description
        return d

@dataclass
class Bom:
    components: list[Component] = field(default_factory=list)
    serial_number: str = field(default_factory=lambda: uuid.uuid4().urn)
    version: int = 1

    def to_dict(self) -> dict:
        return {
            "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": self.version,
            "serialNumber": self.serial_number,
            "metadata": {
                "timestamp": datetime.datetime.now(
                    datetime.timezone.utc
                ).isoformat(),
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "apme-scan",
                            "version": _get_version(),
                        }
                    ]
                },
            },
            "components": [c.to_dict() for c in self.components],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)
```

**Why `to_dict()` over `asdict()`:** The JSON keys use hyphens (`bom-ref`, `specVersion`) which differ from Python attribute names. Custom serialization avoids post-processing `asdict()` output.

**Confidence: HIGH** -- standard Python patterns.

## PURL Construction Helpers

```python
from urllib.parse import quote

def pypi_purl(name: str, version: str) -> str:
    """Generate PURL for a PyPI package. Name is lowercased per spec."""
    normalized = name.lower().replace("_", "-")
    return f"pkg:pypi/{quote(normalized, safe='')}@{quote(version, safe='')}"

def collection_purl(
    namespace: str, name: str, version: str, source_url: str = ""
) -> str:
    """Generate PURL for an Ansible collection using pkg:generic."""
    base = f"pkg:generic/{quote(namespace, safe='')}/{quote(name, safe='')}@{quote(version, safe='')}"
    if source_url:
        base += f"?download_url={quote(source_url, safe='')}"
    return base

def role_purl(
    namespace: str | None, name: str, version: str, source_url: str = ""
) -> str:
    """Generate PURL for an Ansible role using pkg:generic."""
    if namespace:
        base = f"pkg:generic/{quote(namespace, safe='')}/{quote(name, safe='')}@{quote(version, safe='')}"
    else:
        base = f"pkg:generic/{quote(name, safe='')}@{quote(version, safe='')}"
    if source_url:
        base += f"?download_url={quote(source_url, safe='')}"
    return base
```

**Confidence: HIGH** -- `urllib.parse.quote` is stdlib, PURL is just string construction.

## Alternatives Considered

| Category | Recommended | Alternative | Why Not |
|----------|-------------|-------------|---------|
| BOM format | CycloneDX 1.5 JSON | SPDX 2.3 | CycloneDX has better vuln-tooling ecosystem (Grype, Snyk, Trivy all consume it natively). Simpler schema for inventory-only use case. DR-002 already recommends this. |
| BOM library | Stdlib-only hand-roll | `cyclonedx-python-lib` | ADR-014 mandates zero new dependencies. The lib is well-designed but brings 3+ transitive deps. |
| PURL library | Stdlib string formatting | `packageurl-python` | Adds a dependency for what is 3 lines of f-string. Not worth it. |
| Spec version | CycloneDX 1.5 | CycloneDX 1.6 | 1.5 is the current stable ECMA-424 standard. 1.6 adds crypto/attestation fields we don't need. 1.5 has widest tooling support. |
| UUID version | UUID v4 (random) | UUID v5 (name-based) | UUID v4 is simpler, CycloneDX examples use it, and serial numbers should be unique per generation (not deterministic). |

## Sources

- [CycloneDX 1.5 JSON Reference](https://cyclonedx.org/docs/1.5/json/) -- official spec reference
- [CycloneDX 1.5 JSON Schema (GitHub)](https://github.com/CycloneDX/specification/blob/1.5/schema/bom-1.5.schema.json) -- authoritative JSON schema
- [PURL Specification](https://github.com/package-url/purl-spec) -- Package URL standard
- [PURL Known Types](https://github.com/package-url/purl-spec/blob/main/PURL-TYPES.rst) -- registered type list (confirms no `pkg:ansible`)
- [Python uuid module](https://docs.python.org/3/library/uuid.html) -- stdlib UUID generation
- [CycloneDX BOM Examples](https://github.com/CycloneDX/bom-examples) -- reference BOM structures
- [FOSSA PURL Guide](https://fossa.com/blog/understanding-purl-specification-package-url/) -- PURL format explanation
