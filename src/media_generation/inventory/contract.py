"""Validation for the versioned host inventory report contract.

Inventory producers and consumers use this module to interpret the same
versioned document. Admission callers can require complete memory evidence;
ordinary inventory reports remain valid when host probes could not observe it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .fingerprint import build_environment_fingerprint
from .schema import (
    InventoryValidationError,
    SCHEMA_NAME,
    SCHEMA_VERSION,
    digest_value,
    require_list,
    require_mapping,
    require_string,
    reject_unknown_keys as _reject_unknown,
)


_REPORT_KEYS = frozenset(
    {
        "schema",
        "schema_version",
        "run",
        "model_inventory",
        "host",
        "environment_fingerprint",
        "runtimes",
        "bundles",
        "probes",
        "findings",
        "evidence_gate",
    }
)
_TOPOLOGY_CLASSES = frozenset({"unified_shared", "discrete", "unknown", "ambiguous"})
_POOL_KINDS = frozenset({"system_ram", "dedicated_vram"})
_SHARING_RELATIONSHIPS = frozenset(
    {
        "shared_system_aperture",
        "carveout_within_system_ram",
        "duplicate_alias_not_additive",
        "unknown_sharing",
    }
)


@dataclass(frozen=True, slots=True)
class ValidatedInventoryReport:
    """A T02 v1 document whose envelope and host evidence are consistent."""

    document: dict[str, Any]
    host: dict[str, Any]
    fingerprint: dict[str, Any]
    mode: str
    origin: str
    sharing_issues: tuple[str, ...]


def require_positive_int(
    value: object,
    *,
    label: str,
    diagnostic: str = "must be a positive integer",
) -> int:
    """Validate a positive integer with an optional compatibility diagnostic.

    Callers use `diagnostic` when an established public error message
    predates this shared validator and must remain stable for compatibility.
    The accepted values are always positive integers; only the displayed
    message changes.
    """
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise InventoryValidationError(f"{label} {diagnostic}")
    return value


def validate_inventory_report(
    payload: object, *, require_capacity_evidence: bool = False
) -> ValidatedInventoryReport:
    """Validate a T02 v1 report and bind its fingerprint to its host facts.

    ``require_capacity_evidence`` adds the consistency checks needed before
    inventory memory measurements can be used to admit a workload. Reports
    that could not observe memory remain valid inventory documents, but cannot
    produce an admission profile.
    """
    document = require_mapping(payload, label="inventory report")
    _reject_unknown(document, set(_REPORT_KEYS), label="inventory report")
    if document.get("schema") != SCHEMA_NAME:
        raise InventoryValidationError(f"inventory report schema must be {SCHEMA_NAME!r}")
    if (
        type(document.get("schema_version")) is not int
        or document["schema_version"] != SCHEMA_VERSION
    ):
        raise InventoryValidationError("unsupported inventory report schema_version")

    run = require_mapping(document.get("run"), label="inventory report.run")
    mode = require_string(run.get("mode"), label="inventory report.run.mode")
    if mode not in {"local", "replay"}:
        raise InventoryValidationError("inventory report.run.mode must be local or replay")
    evidence = require_mapping(
        document.get("evidence_gate"), label="inventory report.evidence_gate"
    )
    origin = require_string(
        evidence.get("evidence_origin"),
        label="inventory report.evidence_gate.evidence_origin",
    )
    expected_origin = "synthetic_replay" if mode == "replay" else "local_host"
    if origin != expected_origin:
        raise InventoryValidationError(
            "inventory evidence_origin does not match collection mode"
        )
    if evidence.get("apex_verification") != "unverified":
        raise InventoryValidationError("inventory report cannot establish APEX verification")

    require_mapping(document.get("model_inventory"), label="inventory report.model_inventory")
    host = require_mapping(document.get("host"), label="inventory report.host")
    runtimes = require_list(document.get("runtimes"), label="inventory report.runtimes")
    require_list(document.get("bundles"), label="inventory report.bundles")
    require_list(document.get("probes"), label="inventory report.probes")
    require_list(document.get("findings"), label="inventory report.findings")
    fingerprint = require_mapping(
        document.get("environment_fingerprint"),
        label="inventory report.environment_fingerprint",
    )
    fingerprint_digest = require_string(
        fingerprint.get("digest"),
        label="inventory report.environment_fingerprint.digest",
    )
    fingerprint_inputs = require_mapping(
        fingerprint.get("inputs"),
        label="inventory report.environment_fingerprint.inputs",
    )
    if fingerprint_digest != digest_value(fingerprint_inputs):
        raise InventoryValidationError(
            "inventory environment fingerprint digest does not match inputs"
        )
    expected_fingerprint = build_environment_fingerprint(host, runtimes)
    if fingerprint != expected_fingerprint:
        raise InventoryValidationError(
            "inventory environment fingerprint does not match report contents"
        )

    memory = host.get("memory")
    sharing_issues: list[str] = []
    if require_capacity_evidence or memory is not None:
        memory = require_mapping(memory, label="inventory report.host.memory")
        system = memory.get("system")
        if require_capacity_evidence or system is not None:
            system = require_mapping(
                system, label="inventory report.host.memory.system"
            )
            raw_system_total = system.get("total_bytes")
            if raw_system_total is None and not require_capacity_evidence:
                system_total_bytes = None
            else:
                system_total_bytes = require_positive_int(
                    raw_system_total,
                    label="inventory report.host.memory.system.total_bytes",
                )
        else:
            system_total_bytes = None

        topology = memory.get("topology")
        if require_capacity_evidence or topology is not None:
            topology = require_mapping(
                topology, label="inventory report.host.memory.topology"
            )
            topology_class = require_string(
                topology.get("class"),
                label="inventory report.host.memory.topology.class",
            )
            if topology_class not in _TOPOLOGY_CLASSES:
                raise InventoryValidationError("unsupported memory topology class")
            if topology.get("reported_total_is_allocatable_pool") is not False:
                raise InventoryValidationError(
                    "inventory report topology summary is not an allocatable pool"
                )
            if topology.get("confidence") not in {"high", "medium", "low"}:
                raise InventoryValidationError(
                    "inventory topology confidence is malformed"
                )
            for warning in require_list(
                topology.get("warnings"), label="inventory report topology warnings"
            ):
                require_string(warning, label="inventory report topology warning")
            require_list(topology.get("evidence"), label="inventory report topology evidence")
            pools = require_list(
                topology.get("allocatable_pools"),
                label="inventory report.host.memory.topology.allocatable_pools",
            )
            for index, raw_pool in enumerate(pools):
                label = f"allocatable_pools[{index}]"
                pool = require_mapping(raw_pool, label=label)
                _reject_unknown(
                    pool,
                    {"id", "kind", "total_bytes", "source"},
                    label=label,
                )
                require_string(pool.get("id"), label=f"{label}.id")
                kind = require_string(pool.get("kind"), label=f"{label}.kind")
                if kind not in _POOL_KINDS:
                    raise InventoryValidationError(f"{label}.kind is unsupported")
                require_positive_int(
                    pool.get("total_bytes"), label=f"{label}.total_bytes"
                )
                require_string(pool.get("source"), label=f"{label}.source")

            reported_total = topology.get("reported_total_bytes")
            if topology_class == "ambiguous":
                if reported_total is not None:
                    raise InventoryValidationError(
                        "ambiguous topology reported total must be null"
                    )
            else:
                if topology_class == "discrete":
                    reported_total = require_positive_int(
                        reported_total, label="inventory topology reported total"
                    )
                    expected_total = sum(int(pool["total_bytes"]) for pool in pools)
                elif system_total_bytes is None:
                    if reported_total is not None:
                        raise InventoryValidationError(
                            "inventory topology total must be null when system memory is unknown"
                        )
                    expected_total = None
                else:
                    reported_total = require_positive_int(
                        reported_total, label="inventory topology reported total"
                    )
                    expected_total = system_total_bytes
                if reported_total != expected_total:
                    raise InventoryValidationError(
                        "inventory topology reported total does not match its allocatable pools"
                    )
            if topology.get("system_total_bytes") != system_total_bytes:
                raise InventoryValidationError(
                    "inventory topology system total does not match observed system memory"
                )
            relationships = require_list(
                topology.get("sharing_relationships"),
                label="inventory report.host.memory.topology.sharing_relationships",
            )
            for index, raw_relationship in enumerate(relationships):
                label = f"sharing_relationships[{index}]"
                relation = require_mapping(raw_relationship, label=label)
                _reject_unknown(
                    relation,
                    {"accelerator_id", "pool", "relationship"},
                    label=label,
                )
                require_string(relation.get("accelerator_id"), label=f"{label}.accelerator_id")
                require_string(relation.get("pool"), label=f"{label}.pool")
                relationship = require_string(
                    relation.get("relationship"), label=f"{label}.relationship"
                )
                if relationship not in _SHARING_RELATIONSHIPS:
                    raise InventoryValidationError(
                        f"{label}.relationship is unsupported"
                    )
                accelerator_id = str(relation["accelerator_id"])
                pool_id = str(relation["pool"])
                if relationship == "unknown_sharing":
                    sharing_issues.append(
                        f"unknown_sharing:{accelerator_id}:{pool_id}"
                    )
                elif (
                    topology_class == "discrete"
                    and relationship
                    in {"shared_system_aperture", "carveout_within_system_ram"}
                ):
                    sharing_issues.append(
                        f"discrete_topology_has_shared_pool:{accelerator_id}:{pool_id}"
                    )

    return ValidatedInventoryReport(
        document=document,
        host=host,
        fingerprint=fingerprint,
        mode=mode,
        origin=origin,
        sharing_issues=tuple(sorted(set(sharing_issues))),
    )
