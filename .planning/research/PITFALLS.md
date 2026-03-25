# Pitfalls Research

**Domain:** CycloneDX SBOM generation for Ansible content (stdlib-only Python)
**Researched:** 2026-03-25
**Confidence:** MEDIUM-HIGH

## Critical Pitfalls

### Pitfall 1: No registered PURL type for Ansible Galaxy collections

**What goes wrong:**
Ansible Galaxy collections have no official PURL type in the package-url specification. If you invent a type like `pkg:ansible/namespace/collection@1.0.0`, downstream vulnerability scanners (Snyk, Grype, Dependency-Track) will not recognize it, silently dropping the component from matching. The SBOM passes schema validation but produces zero actionable security value for collection components.

**Why it happens:**
The PURL spec maintains a finite list of known types (pypi, npm, maven, etc.) and "ansible" is not among them. Developers assume they can use any string as the type field because the spec allows it, but tooling only matches against known types.

**How to avoid:**
Use `pkg:generic/namespace/collection_name@version?repository_url=https://galaxy.ansible.com` for collections. The `generic` type is explicitly designed as a catch-all and is recognized by most scanners. For Python dependencies from the venv, use the standard `pkg:pypi/package@version`. For Ansible roles (which lack a centralized registry), use `pkg:generic/role_name@version` with a qualifier pointing to the source. Document this decision in an ADR so the team does not revisit it.

**Warning signs:**
- SBOM validates against schema but scanners report zero findings for known-vulnerable collections
- Downstream consumers complain that components are "unmatched" or "unknown ecosystem"

**Phase to address:**
Phase 1 (core data model / PURL strategy) -- this is a foundational decision that affects every component in the SBOM. Get it wrong and every generated SBOM is structurally valid but practically useless.

---

### Pitfall 2: Schema-valid but semantically empty SBOMs

**What goes wrong:**
CycloneDX 1.5 requires almost nothing -- a valid BOM is just `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}`. Developers validate against the JSON schema, see "valid," and ship. But the SBOM is missing NTIA minimum elements (supplier, unique identifiers, dependency relationships, timestamp) that regulators and downstream tools expect. The result passes CI checks but is rejected by customers or compliance audits.

**Why it happens:**
The CycloneDX schema is permissive by design -- nearly everything is optional. Without the `cyclonedx-python-lib` doing guardrails for you, the stdlib-only approach means you must self-enforce completeness. There is no library to tell you "you forgot the PURL."

**How to avoid:**
Define and enforce an internal "minimum viable component" contract that goes beyond schema validation:
- Every component MUST have: `type`, `name`, `version`, `purl`, `bom-ref`
- Top-level BOM MUST have: `serialNumber` (UUID v4), `metadata.timestamp`, `metadata.tools`, `metadata.component` (the subject of the SBOM)
- Write a validation function that checks these fields exist and are non-empty before serialization
- Add integration tests that assert field presence, not just schema validity

**Warning signs:**
- Tests only check "is valid JSON" or "passes schema validation"
- No tests asserting specific field values on components
- PURL fields are empty strings or missing

**Phase to address:**
Phase 2 (serialization / output) -- after the data model exists, enforce completeness at the serialization boundary.

---

### Pitfall 3: Incorrect CycloneDX component type classification for Ansible content

**What goes wrong:**
CycloneDX defines component types: `application`, `library`, `framework`, `file`, etc. Ansible collections and roles do not map cleanly to any of these. Developers pick inconsistently -- some use `library`, others `framework`, some `application`. Downstream tools like Trivy and Dependency-Track filter or skip components with unexpected types. Using `framework` specifically is known to cause Trivy to log "Skipping the component with the unsupported type."

**Why it happens:**
CycloneDX was designed for traditional software ecosystems. Ansible content is infrastructure-as-code, not a library or framework in the conventional sense. The spec says "use application if no more specific classification is available" but that feels wrong for a reusable collection.

**How to avoid:**
Use `library` for all Ansible collections and roles. Rationale: `library` is the most universally supported type across downstream tooling, and the CycloneDX docs recommend it when a component is reusable but you are unsure whether it qualifies as a `framework`. Use `library` for Python dependencies too (standard practice). Document this in the ADR alongside the PURL decision.

**Warning signs:**
- Different component types used for similar content (collections vs roles)
- Downstream scanner logs showing "unsupported type" or "skipped component"

**Phase to address:**
Phase 1 (data model) -- component type is part of the core data structure.

---

### Pitfall 4: `bom-ref` collisions breaking dependency graphs

**What goes wrong:**
Every `bom-ref` in a CycloneDX BOM MUST be unique. If two components share a `bom-ref`, the dependency graph becomes ambiguous and validators reject the BOM. This happens when using predictable schemes like component name without version, or when the same package appears at different versions.

**Why it happens:**
Without the `cyclonedx-python-lib` managing references, developers must generate unique refs manually. Simple approaches like using the package name fail when the same package appears in multiple contexts or when collections share a base name across namespaces.

**How to avoid:**
Use the PURL as the `bom-ref` value. PURLs are inherently unique (they include type, namespace, name, and version) and human-readable. This is the approach recommended by the CycloneDX authoritative guide. For components without a PURL (which should not happen if Pitfall 2 is addressed), fall back to `uuid.uuid4()` from Python stdlib. Never start a `bom-ref` with `urn:cdx:` (reserved for BOM-Links in v1.6+, and avoiding it now is forward-compatible).

**Warning signs:**
- `bom-ref` values that are just component names without versions
- Tests that don't assert `bom-ref` uniqueness across the full BOM
- No dependency graph in the output (flat component list only)

**Phase to address:**
Phase 1 (data model) -- `bom-ref` generation strategy is core to the data model.

---

### Pitfall 5: Stdlib JSON serialization producing non-conformant output

**What goes wrong:**
Python's `json.dumps()` can produce output that violates CycloneDX schema constraints: `None` becomes `null` (where the schema expects a field to be absent, not null), empty strings where the schema expects the field to be omitted, boolean values where strings are expected, or unescaped characters in URLs. The `cyclonedx-python-lib` handles these edge cases; stdlib does not.

**Why it happens:**
Python dict-to-JSON serialization is naive. A data model that uses `None` as "not set" will serialize `None` to `null`, but CycloneDX schemas use `required` + absence to indicate optionality, not null values. Additionally, `json.dumps()` does not validate hash lengths, SPDX license identifiers, or UUID formats.

**How to avoid:**
- Build a serialization layer that strips `None`/empty values before calling `json.dumps()`
- Use a recursive dict-cleaning function: `{k: v for k, v in d.items() if v is not None and v != [] and v != {}}`
- Validate the `serialNumber` field matches the RFC 4122 UUID pattern before output
- Validate hash values match expected lengths (32, 40, 64, 96, or 128 hex chars) if hashes are included
- Write golden-file tests comparing output against known-good CycloneDX 1.5 BOMs from the spec repo

**Warning signs:**
- `null` values appearing anywhere in the JSON output
- Empty arrays `[]` or objects `{}` in the output (usually invalid per schema)
- Tests that check Python dict structure but never validate the serialized JSON

**Phase to address:**
Phase 2 (serialization) -- this is purely a serialization concern, not a data model issue.

---

### Pitfall 6: Extracting wrong version info from venv-installed collections

**What goes wrong:**
Collection metadata in a venv can be stale, incomplete, or formatted differently depending on how the collection was installed (Galaxy, git, local tarball). Version strings may not follow semver. Some collections installed from git have no version at all, or version is `0.0.0-dev`. The SBOM reports incorrect versions, and downstream scanners match against wrong CVEs or match nothing.

**Why it happens:**
Ansible collections store metadata in `MANIFEST.json` inside the collection directory, but the format and completeness varies. Collections installed from Galaxy have full metadata; those installed from git or local paths may have partial metadata. The `galaxy.yml` vs `MANIFEST.json` distinction adds confusion.

**How to avoid:**
- Read `MANIFEST.json` as the primary source (it is generated during collection build)
- Fall back to `galaxy.yml` if `MANIFEST.json` is absent
- If version is missing or `null`, use `"0.0.0"` and add a `property` to the component noting `"cdx:sbom:version-source": "unknown"`
- Never silently skip a component due to missing version -- include it with a marker
- For Python packages, use `importlib.metadata` (stdlib since Python 3.8) to read installed package metadata from the venv

**Warning signs:**
- Unit tests only cover Galaxy-installed collections, not git-installed ones
- Version field contains `null`, empty string, or `*`
- Integration tests use a single collection with perfect metadata

**Phase to address:**
Phase 1 (inventory/discovery) -- this is the data collection step where version accuracy matters most.

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|----------------|-----------------|
| Hardcoding `specVersion: "1.5"` | No version negotiation needed | Cannot upgrade to 1.6/1.7 without code changes | MVP only -- extract to config before v2 |
| Skipping `dependencies` array | Simpler output, no graph building | Flat component list limits scanner effectiveness | MVP if dependency graph is truly out of scope |
| No schema validation at all | Faster development, no schema bundling | Silent regressions ship invalid BOMs | Never -- at minimum validate in CI with the CycloneDX CLI |
| Using `uuid.uuid4()` for all `bom-ref` | Simple, guaranteed unique | Non-human-readable refs make debugging hard | Never -- use PURLs as primary strategy |
| Bundling the JSON schema in-repo | Enables offline validation | Schema drifts from upstream | Acceptable if pinned to exact spec version (1.5) and noted in comments |

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|-------------|----------------|------------------|
| Galaxy Proxy metadata | Trusting proxy-cached metadata as authoritative for version | Cross-reference with `MANIFEST.json` in the installed collection directory |
| Session venv Python packages | Using `pip list --format json` (requires subprocess) | Use `importlib.metadata.distributions()` (stdlib, no subprocess needed) |
| Downstream scanners (Grype, Snyk) | Assuming all scanners handle CycloneDX 1.5 identically | Test with at least two scanners; PURL matching behavior varies |
| gRPC service boundary | Putting SBOM generation in a validator service | SBOM generation is CLI-side or orchestrator-side; it reads from the venv, not from a validator |

## Performance Traps

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|----------------|
| Walking entire venv filesystem for collection discovery | CLI hangs for 10+ seconds on large venvs | Use known paths: `<venv>/lib/python*/site-packages/ansible_collections/` | Venvs with 50+ collections |
| Reading every `MANIFEST.json` synchronously | Slow on network filesystems | Use `pathlib.Path.glob()` to batch-discover, read in parallel with `concurrent.futures` if needed | Network-mounted venvs |
| Generating UUIDs for `serialNumber` | No issue | Use `uuid.uuid4()` from stdlib -- fast and correct | Never breaks |
| JSON serialization of large BOMs | Memory spike on BOMs with 500+ components | Not a real concern for Ansible content scale -- collections rarely exceed 100 | N/A for this domain |

## Security Mistakes

| Mistake | Risk | Prevention |
|---------|------|------------|
| Including file paths in SBOM component metadata | Leaks internal directory structure, usernames from paths | Normalize paths or omit them; use PURLs as identifiers instead |
| Logging raw SBOM contents at DEBUG level | SBOM may contain internal package names considered sensitive | Log component counts, not full SBOM content |
| Not validating SBOM output before writing to file | Malformed JSON could be fed into downstream tooling causing parser exploits | Always `json.dumps()` with `ensure_ascii=True` default; validate before write |

## UX Pitfalls

| Pitfall | User Impact | Better Approach |
|---------|-------------|-----------------|
| Silent empty output when no collections found | User thinks command succeeded but gets empty BOM | Print warning to stderr: "No collections found in session venv. SBOM will contain only Python dependencies." |
| No progress indication for large inventories | User thinks CLI is hung | Print component count to stderr as discovery proceeds |
| Defaulting to file output instead of stdout | Breaks piping to `grype` or `snyk` | Default to stdout (pipe-friendly), use `--output/-o` for file (already planned) |
| Pretty-printing JSON by default | Wastes bandwidth in CI pipelines | Default to compact JSON; add `--pretty` flag for human inspection |

## "Looks Done But Isn't" Checklist

- [ ] **PURL format:** Verify PURLs are parseable by `packageurl-python` -- hand-constructed PURLs often have encoding errors in namespace separators
- [ ] **serialNumber:** Verify it matches RFC 4122 UUID v4 pattern (`^urn:uuid:[0-9a-f]{8}-...`), not just "is a string"
- [ ] **metadata.timestamp:** Verify ISO 8601 format with timezone (UTC), not just `datetime.now().isoformat()` which omits timezone
- [ ] **metadata.tools:** Verify the tools array contains at least one entry identifying APME as the generator (name + version)
- [ ] **Component completeness:** Verify every component has `type`, `name`, `version`, `purl`, `bom-ref` -- not just "components array is non-empty"
- [ ] **Dependency graph:** If included, verify every `ref` in `dependencies` matches a `bom-ref` in `components` -- orphan refs cause validator failures
- [ ] **Schema validation:** Validate output against the official `bom-1.5.schema.json` in CI, not just "it parses as JSON"
- [ ] **Downstream consumption:** Test the output with at least one real scanner (e.g., `grype sbom:output.json`) to verify it is actually consumable

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|----------------|
| Wrong PURL type for collections | LOW | Search-and-replace `pkg:ansible/` to `pkg:generic/` in serializer; update tests |
| Missing NTIA fields | LOW | Add fields to data model and serializer; no schema change needed |
| `bom-ref` collisions | MEDIUM | Regenerate all refs using PURL strategy; update dependency graph refs; re-run all tests |
| Incorrect component types | LOW | Change type enum in data model; update tests |
| Null values in JSON output | LOW | Add dict-cleaning function before serialization; add golden-file tests |
| Wrong version extraction | MEDIUM | Fix metadata reading logic; requires re-testing with multiple installation methods |

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---------|------------------|--------------|
| No registered PURL type for Ansible | Phase 1 (data model) | PURLs parse correctly with `packageurl-python`; at least one scanner matches components |
| Schema-valid but semantically empty | Phase 2 (serialization) | Integration test asserts NTIA minimum elements present on all components |
| Wrong component type classification | Phase 1 (data model) | All components use `library` type; no scanner warnings about unsupported types |
| `bom-ref` collisions | Phase 1 (data model) | Unit test asserts all `bom-ref` values unique across a BOM with 50+ components |
| Stdlib JSON non-conformance | Phase 2 (serialization) | Golden-file test against official CycloneDX examples; CI validates with `cyclonedx-cli validate` |
| Wrong version from venv metadata | Phase 1 (inventory) | Tests cover Galaxy-installed, git-installed, and local-installed collections |

## Sources

- [CycloneDX 1.5 JSON Reference](https://cyclonedx.org/docs/1.5/json/)
- [CycloneDX Specification GitHub (bom-1.5.schema.json)](https://github.com/CycloneDX/specification/blob/1.5/schema/bom-1.5.schema.json)
- [PURL Specification](https://github.com/package-url/purl-spec)
- [PURL Known Types](https://github.com/package-url/purl-spec/blob/main/PURL-TYPES.rst) (redirects to types.md)
- [CycloneDX Authoritative Guide to SBOM](https://cyclonedx.org/guides/sbom/relationships/)
- [5 Common SBOM Mistakes to Avoid](https://finitestate.io/blog/sbom-mistakes)
- [Top 5 Things People Get Wrong About SBOM Generation](https://www.medcrypt.com/blog/top-5-things-people-get-wrong-about-sbom-generation)
- [Common SBOM Mistakes You Should Avoid](https://www.cybernx.com/sbom-mistakes/)
- [OpenSSF: Choosing an SBOM Generation Tool](https://openssf.org/blog/2025/06/05/choosing-an-sbom-generation-tool/)
- [CycloneDX Validation fails for valid JSON BOMs (Issue #202)](https://github.com/CycloneDX/cyclonedx-cli/issues/202)
- [CycloneDX BOM validation fails with %-encoded URLs (Issue #3831)](https://github.com/DependencyTrack/dependency-track/issues/3831)
- [Trivy unsupported framework component type (Discussion #7418)](https://github.com/aquasecurity/trivy/discussions/7418)

---
*Pitfalls research for: CycloneDX SBOM generation (stdlib-only Python, Ansible content domain)*
*Researched: 2026-03-25*
