"""The single authoritative offline T07 evaluator and full-file probes."""

from __future__ import annotations

import errno
import hashlib
import os
import re
import stat
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
from typing import Iterable

from ._candidate_contract import (
    COMPATIBILITY_EVIDENCE_SCHEMA,
    CONVERSION_EVIDENCE_SCHEMA,
    CORRUPT,
    HASH_CHUNK_BYTES,
    INCOMPATIBLE,
    LICENSE_EVIDENCE_SCHEMA,
    MISSING,
    PROVENANCE_EVIDENCE_SCHEMA,
    READY,
    SCHEMA_VERSION,
    UNVERIFIED,
    ArtifactPin,
    CandidateDeclaration,
    CandidateEvaluation,
    CandidateValidationError,
    CompatibilityEvidence,
    ComponentDeclaration,
    LicenseDeclaration,
    ObservedArtifact,
    Provenance,
    StatusItem,
    TrustedEvidence,
    _STATUS_RANK,
    _load_strict_bytes,
    digest_value,
    parse_candidate,
)
from .inventory.contract import validate_inventory_report
from .inventory.probes import LocalObservationSource
from .inventory.schema import (
    SCHEMA_NAME as INVENTORY_SCHEMA_NAME,
    SCHEMA_VERSION as INVENTORY_SCHEMA_VERSION,
    InventoryValidationError,
    require_list,
    require_mapping,
    require_string,
)


_QWEN_IMAGE_EDIT = re.compile(
    r"qwen(?:[._\s-]*image)?[._\s-]*edit", re.IGNORECASE
)
_QWEN_2511_VERSION = re.compile(r"(?<!\d)2511(?!\d)")
_QWEN_ZERO_CONDITIONING_FLAG = "qwen_image_zero_cond_t"


def _declared_policy_identity_strings(declaration: CandidateDeclaration) -> list[str]:
    """Return declared IDs and provenance values that can select model policy."""
    values = [
        declaration.engine.id,
        declaration.engine.version,
        declaration.engine.build,
        declaration.recipe.id,
        declaration.recipe.engine_id,
        declaration.recipe.engine_version,
        declaration.recipe.pipeline_version,
        declaration.recipe.template_version,
        *(component.id for component in declaration.components),
    ]
    provenances = (
        declaration.engine.provenance,
        *(component.provenance for component in declaration.components),
    )
    for provenance in provenances:
        values.extend(
            (
                provenance.publisher,
                provenance.revision,
                provenance.canonical_url,
            )
        )
    return values


def _declares_qwen_image_edit_2511(declaration: CandidateDeclaration) -> bool:
    """Return whether declared identity fields bind Qwen Image Edit 2511."""
    values = _declared_policy_identity_strings(declaration)
    return any(_QWEN_IMAGE_EDIT.search(value) for value in values) and any(
        _QWEN_2511_VERSION.search(value) for value in values
    )


class _Evaluator:
    """Cache file metadata without retaining complete evidence documents."""

    def __init__(
        self,
        declaration: CandidateDeclaration,
        *,
        trusted_evidence: Iterable[TrustedEvidence] = (),
    ) -> None:
        self.declaration = declaration
        self.roots = declaration.root_index
        self.trusted_evidence = tuple(trusted_evidence)
        authority_ids = [record.authority_id for record in self.trusted_evidence]
        if len(authority_ids) != len(set(authority_ids)):
            raise CandidateValidationError("trusted evidence authority ids must be unique")
        self._cache: dict[
            tuple[str, str, int, str, bool, bool], ObservedArtifact
        ] = {}
        self.observations: dict[str, ObservedArtifact] = {}
        self.items: list[StatusItem] = []

    def _observe(
        self,
        key: str,
        pin: ArtifactPin,
        *,
        require_executable: bool = False,
        capture_content: bool = False,
    ) -> ObservedArtifact:
        cache_key = (
            pin.root,
            pin.path,
            pin.size_bytes,
            pin.sha256,
            require_executable,
            capture_content,
        )
        cached = self._cache.get(cache_key)
        if cached is not None and not capture_content:
            self.observations[key] = cached
            return cached
        root = self.roots.get(pin.root)
        if root is None:
            observation = ObservedArtifact(UNVERIFIED, "root_not_declared", None, None)
        else:
            path = root.path / Path(pin.path)
            observation = _observe_file(
                path,
                root.path,
                maximum=pin.size_bytes + 1,
                require_executable=require_executable,
                capture_content=capture_content,
            )
        # Captured bytes belong only to the current caller. Keep no content in
        # either persistent collection, including the returned evaluation's
        # observations. Content requests always reread the complete file through
        # the descriptor and path checks rather than reusing stale bytes.
        metadata = (
            replace(observation, content=None)
            if observation.content is not None
            else observation
        )
        self._cache[cache_key] = metadata
        self.observations[key] = metadata
        return observation

    def _add_artifact(
        self,
        key: str,
        pin: ArtifactPin,
        *,
        require_executable: bool = False,
        capture_content: bool = False,
    ) -> ObservedArtifact:
        observation = self._observe(
            key,
            pin,
            require_executable=require_executable,
            capture_content=capture_content,
        )
        expected = pin.identity()
        status = observation.status
        code = observation.code
        if status == READY and observation.size_bytes != pin.size_bytes:
            status, code = CORRUPT, "size_mismatch"
        elif status == READY and observation.sha256 != pin.sha256:
            status, code = CORRUPT, "sha256_mismatch"
        messages = {
            READY: "complete file size and SHA-256 match independently declared values",
            MISSING: "declared file is missing",
            CORRUPT: "declared file is not an unchanged regular file with exact bytes",
            UNVERIFIED: "declared file could not be verified safely",
        }
        self.items.append(
            StatusItem(
                artifact=key,
                status=status,
                code=code,
                message=messages[status],
                expected=expected,
                observed=observation.to_dict(),
            )
        )
        return observation

    def _check_contract_document(
        self,
        key: str,
        pin: ArtifactPin,
        *,
        expected: dict[str, object],
        label: str,
    ) -> bool:
        """Validate one evidence file against its contract and host authority.

        Matching candidate-authored JSON does not establish that an upstream
        claim is true. The aggregate item becomes ready only when an
        independently supplied ``TrustedEvidence`` record also matches the
        exact file pin and expected contract.
        """
        observation = self._add_artifact(key, pin, capture_content=True)
        artifact_status = self.items[-1]
        if artifact_status.status != READY:
            return False
        self.items.pop()
        if observation.content is None:
            self.items.append(
                StatusItem(
                    artifact=key,
                    status=UNVERIFIED,
                    code="evidence_bytes_unavailable",
                    message=f"{label} bytes were not retained for contract validation",
                )
            )
            return False
        try:
            value = _load_strict_bytes(observation.content, label=label)
        except CandidateValidationError:
            self.items.append(
                StatusItem(
                    artifact=key,
                    status=UNVERIFIED,
                    code="evidence_contract_invalid",
                    message=f"{label} is not valid strict JSON",
                )
            )
            return False
        if not _strict_json_equal(value, expected):
            self.items.append(
                StatusItem(
                    artifact=key,
                    status=UNVERIFIED,
                    code="evidence_contract_mismatch",
                    message=(
                        f"{label} does not match its versioned candidate evidence contract"
                    ),
                    expected=expected,
                )
            )
            return False
        authorities = tuple(
            record
            for record in self.trusted_evidence
            if record.document_size_bytes == pin.size_bytes
            and record.document_sha256 == pin.sha256
        )
        matching_authorities = tuple(
            record
            for record in authorities
            if _strict_json_equal(record.expected, expected)
        )
        if matching_authorities:
            authority_ids = sorted(
                {record.authority_id for record in matching_authorities}
            )
            self.items.append(
                StatusItem(
                    artifact=key,
                    status=READY,
                    code="evidence_contract_match",
                    message=(
                        f"{label} matches an independently supplied pinned authority"
                    ),
                    observed={"authority_ids": authority_ids},
                )
            )
            return True
        if authorities:
            self.items.append(
                StatusItem(
                    artifact=key,
                    status=UNVERIFIED,
                    code="evidence_authority_mismatch",
                    message=(
                        f"{label} exists in host authority with different expectations"
                    ),
                    observed={
                        "authority_ids": sorted(
                            {record.authority_id for record in authorities}
                        )
                    },
                )
            )
        else:
            self.items.append(
                StatusItem(
                    artifact=key,
                    status=UNVERIFIED,
                    code="evidence_authority_unavailable",
                    message=(
                        f"{label} has no independent pinned host authority; "
                        "matching declaration evidence is insufficient"
                    ),
                )
            )
        return False

    def _check_provenance(
        self,
        key: str,
        provenance: Provenance,
        artifact: ArtifactPin,
        *,
        kind: str,
        identifier: str,
        role: str,
    ) -> None:
        expected = {
            "schema": PROVENANCE_EVIDENCE_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "publisher": provenance.publisher,
            "revision": provenance.revision,
            "source_url": provenance.canonical_url,
            "subject": _artifact_subject(
                kind=kind,
                identifier=identifier,
                role=role,
                artifact=artifact,
            ),
        }
        self._check_contract_document(
            f"{key}.provenance.evidence",
            provenance.evidence,
            expected=expected,
            label="provenance evidence",
        )

    def _check_license(
        self,
        key: str,
        license: LicenseDeclaration,
        artifact: ArtifactPin,
        *,
        kind: str,
        identifier: str,
        role: str,
    ) -> None:
        expected = {
            "schema": LICENSE_EVIDENCE_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "subject": _artifact_subject(
                kind=kind,
                identifier=identifier,
                role=role,
                artifact=artifact,
            ),
            "license": {
                "name": license.name,
                "spdx": license.spdx,
                "terms_url": license.terms_url,
            },
        }
        self._check_contract_document(
            f"{key}.license.evidence",
            license.evidence,
            expected=expected,
            label="license evidence",
        )

    def _check_conversion(
        self,
        key: str,
        component: ComponentDeclaration,
    ) -> None:
        conversion = component.conversion
        expected = {
            "schema": CONVERSION_EVIDENCE_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "subject": _artifact_subject(
                kind="component",
                identifier=component.id,
                role=component.role,
                artifact=component.artifact,
            ),
            "conversion": {
                "lineage": conversion.lineage,
                "tool": (
                    None
                    if conversion.tool_name is None
                    else {
                        "name": conversion.tool_name,
                        "version": conversion.tool_version,
                    }
                ),
            },
        }
        self._check_contract_document(
            f"{key}.conversion.evidence",
            conversion.evidence,
            expected=expected,
            label="conversion evidence",
        )

    def _check_compatibility(self) -> None:
        declaration = self.declaration
        if declaration.recipe.engine_id != declaration.engine.id:
            self.items.append(
                StatusItem(
                    artifact="recipe.compatibility.engine",
                    status=INCOMPATIBLE,
                    code="engine_id_mismatch",
                    message="recipe evidence names a different engine",
                    expected={"engine_id": declaration.recipe.engine_id},
                    observed={"engine_id": declaration.engine.id},
                )
            )
        if declaration.recipe.engine_version != declaration.engine.version:
            self.items.append(
                StatusItem(
                    artifact="recipe.compatibility.version",
                    status=INCOMPATIBLE,
                    code="engine_version_mismatch",
                    message="recipe evidence names a different engine version",
                    expected={"engine_version": declaration.recipe.engine_version},
                    observed={"engine_version": declaration.engine.version},
                )
            )
        engine_flags = dict(declaration.engine.architecture_flags)
        for name, required_value in declaration.recipe.architecture_flags:
            if name not in engine_flags:
                status = INCOMPATIBLE
                code = "architecture_flag_missing"
            elif not _same_scalar(engine_flags[name], required_value):
                status = INCOMPATIBLE
                code = "architecture_flag_mismatch"
            else:
                status = READY
                code = "architecture_flag_match"
            self.items.append(
                StatusItem(
                    artifact=f"recipe.compatibility.flag:{name}",
                    status=status,
                    code=code,
                    message=(
                        "engine architecture flag matches the pinned recipe"
                        if status == READY
                        else "engine architecture flag does not satisfy the pinned recipe"
                    ),
                    expected={"value": required_value},
                    observed={"value": engine_flags.get(name)},
                )
            )
        if _declares_qwen_image_edit_2511(declaration):
            declared_flags = dict(declaration.recipe.architecture_flags)
            policy_value = declared_flags.get(_QWEN_ZERO_CONDITIONING_FLAG)
            engine_value = engine_flags.get(_QWEN_ZERO_CONDITIONING_FLAG)
            policy_ready = policy_value is True and engine_value is True
            self.items.append(
                StatusItem(
                    artifact=(
                        "recipe.compatibility.policy:"
                        "qwen-image-edit-2511-zero-conditioning"
                    ),
                    status=READY if policy_ready else INCOMPATIBLE,
                    code=(
                        "qwen_2511_zero_conditioning_enabled"
                        if policy_ready
                        else "qwen_2511_zero_conditioning_required"
                    ),
                    message=(
                        "Qwen Image Edit 2511 explicitly enables zero conditioning"
                        if policy_ready
                        else (
                            "Qwen Image Edit 2511 requires recipe and engine "
                            f"{_QWEN_ZERO_CONDITIONING_FLAG}=true"
                        )
                    ),
                    expected={_QWEN_ZERO_CONDITIONING_FLAG: True},
                    observed={
                        "recipe": policy_value,
                        "engine": engine_value,
                    },
                )
            )

        actual_roles = {component.role for component in declaration.components}
        for role in declaration.recipe.required_roles:
            status = READY if role in actual_roles else INCOMPATIBLE
            self.items.append(
                StatusItem(
                    artifact=f"recipe.role:{role}",
                    status=status,
                    code="required_role_present" if status == READY else "required_role_missing",
                    message=(
                        "declared bundle contains the required role"
                        if status == READY
                        else "declared bundle is missing a required role"
                    ),
                )
            )

    def _compatibility_contract(
        self,
        evidence: CompatibilityEvidence,
    ) -> dict[str, object]:
        """Return the exact versioned compatibility document for one claim set."""
        declaration = self.declaration
        components = sorted(
            (
                {
                    "id": component.id,
                    "role": component.role,
                    "size_bytes": component.artifact.size_bytes,
                    "sha256": component.artifact.sha256,
                    "precision": component.precision,
                    "quantization": component.quantization,
                }
                for component in declaration.components
            ),
            key=lambda item: str(item["id"]),
        )
        roles = []
        for role in declaration.recipe.required_roles:
            role_components = sorted(
                (
                    {
                        "id": component.id,
                        "size_bytes": component.artifact.size_bytes,
                        "sha256": component.artifact.sha256,
                        "precision": component.precision,
                        "quantization": component.quantization,
                    }
                    for component in declaration.components
                    if component.role == role
                ),
                key=lambda item: str(item["id"]),
            )
            roles.append({"role": role, "components": role_components})
        return {
            "schema": COMPATIBILITY_EVIDENCE_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "claims": sorted(evidence.claims),
            "engine": {
                "id": declaration.engine.id,
                "version": declaration.engine.version,
                "build": declaration.engine.build,
                # Evidence must also bind switches that the recipe does not repeat.
                "architecture_flags": dict(declaration.engine.architecture_flags),
                "executable": {
                    "size_bytes": declaration.engine.executable.size_bytes,
                    "sha256": declaration.engine.executable.sha256,
                },
            },
            "recipe": {
                "id": declaration.recipe.id,
                "document": {
                    "size_bytes": declaration.recipe.document.size_bytes,
                    "sha256": declaration.recipe.document.sha256,
                },
                "pipeline_version": declaration.recipe.pipeline_version,
                "template_version": declaration.recipe.template_version,
            },
            "required_roles": roles,
            "components": components,
            "architecture_flags": dict(declaration.recipe.architecture_flags),
            "adapters": [adapter.to_dict() for adapter in declaration.adapters],
        }

    def _check_compatibility_evidence(self) -> set[str]:
        declaration = self.declaration
        covered: set[str] = set()
        for index, evidence in enumerate(declaration.recipe.evidence):
            key = f"recipe.compatibility.evidence[{index}]"
            valid = self._check_contract_document(
                key,
                evidence.document,
                expected=self._compatibility_contract(evidence),
                label="compatibility evidence",
            )
            if valid:
                covered.update(evidence.claims)
        return covered

    def _check_inventory_evidence(self) -> None:
        declaration = self.declaration
        evidence = declaration.inventory_evidence
        if evidence is None:
            self.items.append(
                StatusItem(
                    artifact="inventory.evidence",
                    status=READY,
                    code="inventory_not_supplied",
                    message="optional T02 inventory evidence was not declared",
                )
            )
            return
        observation = self._add_artifact(
            "inventory.evidence",
            evidence.document,
            capture_content=True,
        )
        artifact_item = observation
        if artifact_item.status != READY:
            return
        try:
            if observation.content is None:
                raise CandidateValidationError("T02 evidence bytes are unavailable")
            value = _load_strict_bytes(
                observation.content,
                label="T02 inventory evidence",
            )
            item = require_mapping(value, label="T02 inventory evidence")
            if (
                item.get("schema") != INVENTORY_SCHEMA_NAME
                or item.get("schema_version") != INVENTORY_SCHEMA_VERSION
            ):
                raise CandidateValidationError(
                    "T02 inventory evidence has an unsupported schema"
                )
            validate_inventory_report(item)
            bundles = require_list(item.get("bundles"), label="T02 bundles")
            matches = [
                bundle
                for bundle in bundles
                if isinstance(bundle, dict)
                and bundle.get("id") == evidence.bundle_id
            ]
            if len(matches) != 1:
                raise CandidateValidationError(
                    "T02 evidence does not name exactly one declared bundle"
                )
            bundle = matches[0]
            if bundle.get("engine") != declaration.engine.id:
                raise CandidateValidationError(
                    "T02 evidence engine contradicts the candidate declaration"
                )
            recipe = require_mapping(bundle.get("recipe"), label="T02 bundle recipe")
            if recipe.get("id") != declaration.recipe.id:
                raise CandidateValidationError(
                    "T02 evidence recipe id contradicts the candidate declaration"
                )
            expected_recipe_digest = f"sha256:{declaration.recipe.document.sha256}"
            if (
                recipe.get("status") != "observed"
                or recipe.get("digest_source") != "file"
                or recipe.get("digest") != expected_recipe_digest
            ):
                raise CandidateValidationError(
                    "T02 evidence recipe content identity is incomplete or contradictory"
                )
            raw_components = require_list(
                bundle.get("components"), label="T02 bundle components"
            )
            by_path: dict[str, list[dict[str, object]]] = {}
            for raw_component in raw_components:
                component_record = require_mapping(
                    raw_component, label="T02 bundle component"
                )
                component_path = require_string(
                    component_record.get("path"),
                    label="T02 bundle component.path",
                )
                by_path.setdefault(
                    str(Path(os.path.abspath(component_path))), []
                ).append(component_record)
            if len(by_path) != len(declaration.components):
                raise CandidateValidationError(
                    "T02 evidence component set contradicts the candidate declaration"
                )
            correlated: list[dict[str, object]] = []
            for component in declaration.components:
                path = str(component.artifact.resolved_path(self.roots))
                records = by_path.get(path, [])
                if len(records) != 1:
                    raise CandidateValidationError(
                        "T02 evidence has no unique component for a candidate artifact"
                    )
                record = records[0]
                digest = record.get("digest")
                expected_digest = f"sha256:{component.artifact.sha256}"
                if (
                    record.get("role") != component.role
                    or record.get("status") != "observed"
                    or record.get("size_bytes") != component.artifact.size_bytes
                    or not isinstance(digest, dict)
                    or digest.get("status") != "computed"
                    or digest.get("value") != expected_digest
                ):
                    raise CandidateValidationError(
                        "T02 evidence component role or content identity contradicts "
                        "the candidate declaration"
                    )
                correlated.append(
                    {
                        "id": record.get("id"),
                        "role": component.role,
                        "size_bytes": component.artifact.size_bytes,
                        "sha256": component.artifact.sha256,
                    }
                )
        except (InventoryValidationError, CandidateValidationError):
            self.items.append(
                StatusItem(
                    artifact="inventory.evidence.schema",
                    status=UNVERIFIED,
                    code="inventory_evidence_invalid",
                    message="optional evidence is not a supported T02 inventory report",
                )
            )
            return
        after = _observe_target(
            declaration, "inventory.evidence", evidence.document
        )
        if after.status != READY:
            self.items.append(
                StatusItem(
                    artifact="inventory.evidence.stability",
                    status=after.status,
                    code="inventory_evidence_changed",
                    message="optional T02 inventory evidence changed during validation",
                    observed=after.to_dict(),
                )
            )
            return
        self.items.append(
            StatusItem(
                artifact="inventory.evidence.correlation",
                status=READY,
                code="inventory_evidence_correlated",
                message=(
                    "pinned T02 bundle, recipe, component roles, and full digests "
                    "match the candidate declaration"
                ),
                observed={
                    "bundle_id": evidence.bundle_id,
                    "engine": declaration.engine.id,
                    "recipe_digest": expected_recipe_digest,
                    "components": sorted(
                        correlated, key=lambda item: str(item["id"])
                    ),
                },
            )
        )

    def _check_physical_aliases(self) -> None:
        """Reject declared artifacts observed through the same physical file."""
        artifact_keys = (
            "engine.executable",
            "recipe.document",
            *(
                f"component:{component.id}"
                for component in self.declaration.components
            ),
        )
        by_identity: dict[tuple[int, int], list[str]] = {}
        for key in artifact_keys:
            observation = self.observations[key]
            if observation.status != READY or observation.physical_identity is None:
                continue
            by_identity.setdefault(observation.physical_identity, []).append(key)
        aliases = [keys for keys in by_identity.values() if len(keys) > 1]
        if not aliases:
            return
        self.items.append(
            StatusItem(
                artifact="candidate.physical_identity",
                status=CORRUPT,
                code="physical_alias",
                message=(
                    "engine, recipe, and component files must reference "
                    "distinct physical files"
                ),
                expected={"distinct_physical_files": True},
                observed={"aliases": aliases},
            )
        )

    def evaluate(self) -> CandidateEvaluation:
        declaration = self.declaration
        self._add_artifact(
            "engine.executable",
            declaration.engine.executable,
            require_executable=True,
        )
        self._check_provenance(
            "engine",
            declaration.engine.provenance,
            declaration.engine.executable,
            kind="engine",
            identifier=declaration.engine.id,
            role="engine",
        )
        self._check_license(
            "engine",
            declaration.engine.license,
            declaration.engine.executable,
            kind="engine",
            identifier=declaration.engine.id,
            role="engine",
        )
        self._add_artifact("recipe.document", declaration.recipe.document)
        self._check_compatibility()
        required_claims = {
            "engine",
            "version",
            "recipe",
            *(
                f"role:{role}" for role in declaration.recipe.required_roles
            ),
            *(f"flag:{name}" for name, _ in declaration.recipe.architecture_flags),
        }
        covered_claims = self._check_compatibility_evidence()
        missing_claims = sorted(required_claims - covered_claims)
        if missing_claims:
            self.items.append(
                StatusItem(
                    artifact="recipe.compatibility.evidence",
                    status=UNVERIFIED,
                    code="compatibility_evidence_incomplete",
                    message="pinned compatibility evidence does not cover every claim",
                    expected={"claims": sorted(required_claims)},
                    observed={"claims": sorted(covered_claims)},
                )
            )
        else:
            self.items.append(
                StatusItem(
                    artifact="recipe.compatibility.evidence",
                    status=READY,
                    code="compatibility_evidence_complete",
                    message="pinned evidence covers every declared compatibility claim",
                    expected={"claims": sorted(required_claims)},
                    observed={"claims": sorted(covered_claims)},
                )
            )
        for component in declaration.components:
            prefix = f"component:{component.id}"
            self._add_artifact(prefix, component.artifact)
            self._check_provenance(
                prefix,
                component.provenance,
                component.artifact,
                kind="component",
                identifier=component.id,
                role=component.role,
            )
            self._check_license(
                prefix,
                component.license,
                component.artifact,
                kind="component",
                identifier=component.id,
                role=component.role,
            )
            self._check_conversion(prefix, component)
        self._check_physical_aliases()
        self._check_inventory_evidence()
        for adapter in declaration.adapters:
            self.items.append(
                StatusItem(
                    artifact=f"adapter:{adapter.component_id}",
                    status=READY,
                    code="adapter_order_pinned",
                    message="adapter order and strength are explicitly pinned",
                    observed=adapter.to_dict(),
                )
            )
        items = tuple(sorted(self.items, key=lambda item: item.artifact))
        artifact_keys = [item.artifact for item in items]
        if len(artifact_keys) != len(set(artifact_keys)):
            raise CandidateValidationError(
                "candidate evaluation produced duplicate status keys"
            )
        candidate_id = declaration.stable_candidate_id()
        verification_id = digest_value(
            {
                "candidate_id": candidate_id,
                "status": max(
                    (item.status for item in self.items),
                    key=_STATUS_RANK.__getitem__,
                ),
                "items": [item.to_dict() for item in items],
                "observations": {
                    key: value.to_dict()
                    for key, value in sorted(self.observations.items())
                },
            }
        )
        return CandidateEvaluation(
            declaration=declaration,
            items=items,
            candidate_id=candidate_id,
            verification_id=verification_id,
            observations=dict(sorted(self.observations.items())),
        )
def _same_scalar(left: object, right: object) -> bool:
    return type(left) is type(right) and left == right
def _strict_json_equal(left: object, right: object) -> bool:
    """Compare JSON values without treating booleans as integers."""
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(
            _strict_json_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(
            _strict_json_equal(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    return _same_scalar(left, right)
def _artifact_subject(
    *,
    kind: str,
    identifier: str,
    role: str,
    artifact: ArtifactPin,
) -> dict[str, object]:
    """Return the artifact-bound subject required in evidence documents."""
    return {
        "kind": kind,
        "id": identifier,
        "role": role,
        "size_bytes": artifact.size_bytes,
        "sha256": artifact.sha256,
    }
def _observe_file(
    path: Path,
    root: Path,
    *,
    maximum: int,
    require_executable: bool = False,
    capture_content: bool = False,
) -> ObservedArtifact:
    """Hash a file while binding its descriptor to the declared directory entry.

    Keep the parent open throughout the read. No-follow entry snapshots before
    and after hashing must match the opened inode and its metadata, so replacing
    the name cannot make displaced valid bytes qualify the current artifact.
    The final traversal retains every directory descriptor and rechecks each
    entry back to the declared root after observing the file. Otherwise an
    ancestor replaced during that traversal could leave both parent descriptors
    pointing into the same displaced tree. These checks cannot prevent mutation
    after the final observation; consumers must revalidate before using a file.
    """
    parent_fd: int | None = None
    descriptor: int | None = None
    try:
        parent_fd = LocalObservationSource._open_beneath_fd(
            path.parent, root, directory=True
        )
        descriptor = os.open(
            path.name,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=parent_fd,
        )
        facts = os.fstat(descriptor)
        if not stat.S_ISREG(facts.st_mode):
            return ObservedArtifact(CORRUPT, "not_regular_file", None, None)
        if require_executable and facts.st_mode & 0o111 == 0:
            return ObservedArtifact(
                CORRUPT, "executable_bit_missing", facts.st_size, None
            )
        if facts.st_size > maximum:
            return ObservedArtifact(CORRUPT, "declared_size_exceeded", facts.st_size, None)
        before_identity = _file_identity(facts)
        entry = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if _file_identity(entry) != before_identity:
            return ObservedArtifact(CORRUPT, "file_changed_during_hash", None, None)
        hasher = hashlib.sha256()
        captured = bytearray() if capture_content else None
        total = 0
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            while True:
                chunk = handle.read(min(HASH_CHUNK_BYTES, maximum - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum:
                    return ObservedArtifact(CORRUPT, "declared_size_exceeded", total, None)
                hasher.update(chunk)
                if captured is not None:
                    captured.extend(chunk)
        after = os.fstat(descriptor)
        with ExitStack() as directories:
            parts = path.parent.relative_to(root).parts
            nofollow = getattr(os, "O_NOFOLLOW", 0)
            directory_flag = getattr(os, "O_DIRECTORY", 0)
            if parts and (
                not nofollow
                or not directory_flag
                or os.open not in getattr(os, "supports_dir_fd", set())
            ):
                raise OSError(errno.ENOTSUP, "directory identity chain unavailable")
            current_parent_fd = LocalObservationSource._open_beneath_fd(
                root, root, directory=True
            )
            directories.callback(os.close, current_parent_fd)
            chain = [(root, current_parent_fd)]
            for part in parts:
                current_parent_fd = os.open(
                    part,
                    os.O_RDONLY | nofollow | directory_flag,
                    dir_fd=current_parent_fd,
                )
                directories.callback(os.close, current_parent_fd)
                chain.append((Path(part), current_parent_fd))
            retained_parent = os.fstat(parent_fd)
            current_parent = os.fstat(current_parent_fd)
            entry = os.stat(path.name, dir_fd=current_parent_fd, follow_symlinks=False)
            if (
                (current_parent.st_dev, current_parent.st_ino)
                != (retained_parent.st_dev, retained_parent.st_ino)
                or _file_identity(after) != before_identity
                or _file_identity(entry) != before_identity
                or total != after.st_size
            ):
                return ObservedArtifact(CORRUPT, "file_changed_during_hash", total, None)
            for index in range(len(chain) - 1, -1, -1):
                name, directory_fd = chain[index]
                retained = os.fstat(directory_fd)
                current = (
                    os.stat(name)
                    if index == 0
                    else os.stat(
                        name, dir_fd=chain[index - 1][1], follow_symlinks=False
                    )
                )
                if (current.st_dev, current.st_ino) != (retained.st_dev, retained.st_ino):
                    return ObservedArtifact(CORRUPT, "file_changed_during_hash", total, None)
        return ObservedArtifact(
            READY,
            "hash_complete",
            total,
            hasher.hexdigest(),
            bytes(captured) if captured is not None else None,
        (facts.st_dev, facts.st_ino),
        )
    except FileNotFoundError:
        return ObservedArtifact(MISSING, "file_missing", None, None)
    except OSError as error:
        if error.errno == errno.ENOENT:
            return ObservedArtifact(MISSING, "file_missing", None, None)
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            return ObservedArtifact(CORRUPT, "symlink_or_unsafe_path", None, None)
        return ObservedArtifact(UNVERIFIED, "descriptor_containment_unavailable", None, None)
    finally:
        try:
            if descriptor is not None:
                os.close(descriptor)
        finally:
            if parent_fd is not None:
                os.close(parent_fd)
def _file_identity(facts: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        facts.st_dev,
        facts.st_ino,
        facts.st_size,
        facts.st_mtime_ns,
        facts.st_ctime_ns,
    )
def _observe_target(
    declaration: CandidateDeclaration, target: str, pin: ArtifactPin
) -> ObservedArtifact:
    """Observe one declared acquisition target against its full-file pin."""
    root = declaration.root_index[pin.root]
    observed = _observe_file(
        root.path / Path(pin.path),
        root.path,
        maximum=pin.size_bytes + 1,
        require_executable=target == "engine",
    )
    if observed.status == READY and observed.size_bytes != pin.size_bytes:
        return ObservedArtifact(
            CORRUPT, "size_mismatch", observed.size_bytes, observed.sha256
        )
    if observed.status == READY and observed.sha256 != pin.sha256:
        return ObservedArtifact(
            CORRUPT, "sha256_mismatch", observed.size_bytes, observed.sha256
        )
    return observed


def evaluate_candidate(
    declaration: CandidateDeclaration,
    *,
    trusted_evidence: Iterable[TrustedEvidence] = (),
) -> CandidateEvaluation:
    """Run the authoritative offline static evaluation."""
    return _Evaluator(
        declaration, trusted_evidence=trusted_evidence
    ).evaluate()
def inspect_candidate(
    declaration_path: Path,
    *,
    trusted_evidence: Iterable[TrustedEvidence] = (),
) -> dict[str, object]:
    """Inspect and statically verify a candidate without writing anything."""
    declaration = parse_candidate(declaration_path)
    return evaluate_candidate(
        declaration, trusted_evidence=trusted_evidence
    ).report("inspect")
def verify_candidate(
    declaration_path: Path,
    *,
    trusted_evidence: Iterable[TrustedEvidence] = (),
) -> dict[str, object]:
    """Repeat offline verification without writing candidate artifacts."""
    declaration = parse_candidate(declaration_path)
    return evaluate_candidate(
        declaration, trusted_evidence=trusted_evidence
    ).report("verify")
def candidate_exit_code(status: str) -> int:
    """Map a static result to a stable CLI exit code."""
    return {
        READY: 0,
        MISSING: 5,
        CORRUPT: 6,
        INCOMPATIBLE: 3,
        UNVERIFIED: 4,
    }[status]

__all__ = [name for name in globals() if not name.startswith("__")]
