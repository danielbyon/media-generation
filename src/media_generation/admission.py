"""Versioned capacity profiles and workload-demand decisions.

The admission layer converts the stable parts of a validated version-1 host
inventory report into capacity pools.  Inventory totals describe observed
hardware, not currently free memory, so a separate operator policy supplies
the headroom reserved from every pool.  A pinned copy of the resulting profile
travels with each queued execution; later workers do not need to reconstruct it
from mutable host state.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .adapters import DeterministicCpuAdapter
from .inventory import validate_inventory_report
from .inventory.contract import require_positive_int
from .inventory.schema import (
    InventoryValidationError,
    digest_value,
    load_strict_json,
    reject_unknown_keys as _reject_unknown,
    require_list as _list,
    require_mapping as _mapping,
    require_string as _string,
)


POLICY_SCHEMA = "media-generation.admission-policy"
PROFILE_SCHEMA = "media-generation.admission-profile"
DEMAND_SCHEMA = "media-generation.workload-demand"
ADMISSION_SCHEMA_VERSION = 1
WORKLOAD_KINDS = frozenset({"image", "text", "vision", "scoring", "model_loading"})
_MAX_SQLITE_BYTE_COUNT = (1 << 63) - 1


@dataclass(frozen=True, slots=True)
class AdmissionPolicy:
    """Explicit operator headroom reserved from each allocatable pool."""

    schema_version: int
    pool_headroom_bytes: dict[str, int]


@dataclass(frozen=True, slots=True)
class CapacityPool:
    """One conservatively usable pool derived from inventory evidence."""

    id: str
    kind: str
    total_bytes: int
    headroom_bytes: int | None
    available_bytes: int | None

    def to_dict(self) -> dict[str, object]:
        """Return stable JSON suitable for durable profile evidence."""
        return {
            "id": self.id,
            "kind": self.kind,
            "total_bytes": self.total_bytes,
            "headroom_bytes": self.headroom_bytes,
            "available_bytes": self.available_bytes,
        }


@dataclass(frozen=True, slots=True)
class AdmissionProfile:
    """Versioned capacity evidence pinned to a queued execution."""

    status: str
    origin: str
    environment_fingerprint: str
    topology: str
    pools: tuple[CapacityPool, ...]
    shared_pool_ids: tuple[str, ...]
    unknown_reasons: tuple[str, ...]
    fingerprint: str
    apex_qualification: str = "unverified"
    apex_evidence: bool = False

    def to_dict(self) -> dict[str, object]:
        """Return a complete immutable profile snapshot."""
        return {
            "schema": PROFILE_SCHEMA,
            "schema_version": ADMISSION_SCHEMA_VERSION,
            "status": self.status,
            "origin": self.origin,
            "environment_fingerprint": self.environment_fingerprint,
            "topology": self.topology,
            "pools": [pool.to_dict() for pool in self.pools],
            "shared_pool_ids": list(self.shared_pool_ids),
            "unknown_reasons": list(self.unknown_reasons),
            "apex_qualification": self.apex_qualification,
            "apex_evidence": self.apex_evidence,
            "fingerprint": self.fingerprint,
        }


def parse_admission_profile(payload: object) -> AdmissionProfile:
    """Validate one complete version-1 capacity profile.

    The embedded fingerprint covers every profile field except the fingerprint
    itself. A persisted profile is accepted only when the current schema,
    typed field values, canonical evidence lists, and that fingerprint all
    agree.
    """
    profile = _mapping(payload, label="admission profile")
    _reject_unknown(
        profile,
        {
            "schema",
            "schema_version",
            "status",
            "origin",
            "environment_fingerprint",
            "topology",
            "pools",
            "shared_pool_ids",
            "unknown_reasons",
            "apex_qualification",
            "apex_evidence",
            "fingerprint",
        },
        label="admission profile",
    )
    if profile.get("schema") != PROFILE_SCHEMA:
        raise InventoryValidationError(
            f"admission profile schema must be {PROFILE_SCHEMA!r}"
        )
    if (
        type(profile.get("schema_version")) is not int
        or profile["schema_version"] != ADMISSION_SCHEMA_VERSION
    ):
        raise InventoryValidationError(
            "unsupported admission profile schema_version"
        )

    status = _string(profile.get("status"), label="admission profile.status")
    if status not in {"ready", "unknown"}:
        raise InventoryValidationError(
            "admission profile.status must be ready or unknown"
        )
    origin = _string(profile.get("origin"), label="admission profile.origin")
    environment_fingerprint = _string(
        profile.get("environment_fingerprint"),
        label="admission profile.environment_fingerprint",
    )
    topology = _string(profile.get("topology"), label="admission profile.topology")

    raw_pools = _list(profile.get("pools"), label="admission profile.pools")
    pools = tuple(
        _parse_capacity_pool(raw_pool, index=index)
        for index, raw_pool in enumerate(raw_pools)
    )
    raw_shared_pool_ids = _list(
        profile.get("shared_pool_ids"),
        label="admission profile.shared_pool_ids",
    )
    shared_pool_ids = tuple(
        _string(value, label="admission profile.shared_pool_ids item")
        for value in raw_shared_pool_ids
    )
    if shared_pool_ids != tuple(sorted(set(shared_pool_ids))):
        raise InventoryValidationError(
            "admission profile.shared_pool_ids must be sorted and unique"
        )

    raw_unknown_reasons = _list(
        profile.get("unknown_reasons"),
        label="admission profile.unknown_reasons",
    )
    unknown_reasons = tuple(
        _string(value, label="admission profile.unknown_reasons item")
        for value in raw_unknown_reasons
    )
    if unknown_reasons != tuple(sorted(set(unknown_reasons))):
        raise InventoryValidationError(
            "admission profile.unknown_reasons must be sorted and unique"
        )
    if (status == "unknown") != bool(unknown_reasons):
        raise InventoryValidationError(
            "admission profile.status contradicts unknown_reasons"
        )

    apex_qualification = _string(
        profile.get("apex_qualification"),
        label="admission profile.apex_qualification",
    )
    apex_evidence = profile.get("apex_evidence")
    if apex_qualification != "unverified" or apex_evidence is not False:
        raise InventoryValidationError(
            "admission profile APEX qualification must remain unverified"
        )
    fingerprint = _string(
        profile.get("fingerprint"), label="admission profile.fingerprint"
    )
    stable_body = {
        key: value for key, value in profile.items() if key != "fingerprint"
    }
    if fingerprint != digest_value(stable_body):
        raise InventoryValidationError(
            "admission profile fingerprint does not match its canonical evidence"
        )

    return AdmissionProfile(
        status=status,
        origin=origin,
        environment_fingerprint=environment_fingerprint,
        topology=topology,
        pools=pools,
        shared_pool_ids=shared_pool_ids,
        unknown_reasons=unknown_reasons,
        fingerprint=fingerprint,
        apex_qualification=apex_qualification,
        apex_evidence=apex_evidence,
    )


def _parse_capacity_pool(payload: object, *, index: int) -> CapacityPool:
    """Validate one capacity pool nested in a persisted admission profile."""
    label = f"admission profile.pools[{index}]"
    pool = _mapping(payload, label=label)
    _reject_unknown(
        pool,
        {"id", "kind", "total_bytes", "headroom_bytes", "available_bytes"},
        label=label,
    )
    pool_id = _string(pool.get("id"), label=f"{label}.id")
    if pool_id != pool_id.strip():
        raise InventoryValidationError(f"{label}.id must not have surrounding whitespace")
    kind = _string(pool.get("kind"), label=f"{label}.kind")
    total_bytes = _nonnegative_byte_count(
        pool.get("total_bytes"), label=f"{label}.total_bytes"
    )
    raw_headroom = pool.get("headroom_bytes")
    raw_available = pool.get("available_bytes")
    if raw_headroom is None:
        headroom_bytes = None
    else:
        headroom_bytes = _nonnegative_byte_count(
            raw_headroom, label=f"{label}.headroom_bytes"
        )
    if raw_available is None:
        available_bytes = None
    else:
        available_bytes = _nonnegative_byte_count(
            raw_available, label=f"{label}.available_bytes"
        )
    if (headroom_bytes is None) != (available_bytes is None):
        raise InventoryValidationError(
            f"{label} headroom_bytes and available_bytes must both be known or unknown"
        )
    if headroom_bytes is not None and available_bytes != max(
        0, total_bytes - headroom_bytes
    ):
        raise InventoryValidationError(
            f"{label}.available_bytes contradicts total_bytes and headroom_bytes"
        )
    return CapacityPool(
        id=pool_id,
        kind=kind,
        total_bytes=total_bytes,
        headroom_bytes=headroom_bytes,
        available_bytes=available_bytes,
    )


@dataclass(frozen=True, slots=True)
class DemandRequirement:
    """Explicit known, not-applicable, or unknown workload requirement."""

    status: str
    value: str | int | None = None
    reason: str | None = None

    def to_dict(self, *, known_key: str) -> dict[str, object]:
        """Return the canonical input representation for one known-value key."""
        result: dict[str, object] = {"status": self.status}
        if self.value is not None:
            result[known_key] = self.value
        if self.reason is not None:
            result["reason"] = self.reason
        return result


@dataclass(frozen=True, slots=True)
class WorkloadDemand:
    """Versioned resource demand independent of immutable generation input."""

    kind: str
    memory_status: str
    system_ram_bytes: int
    accelerator_memory_bytes: int
    accelerator_pool_id: str | None
    memory_reason: str | None
    context: DemandRequirement
    offload: DemandRequirement
    residency: DemandRequirement

    @property
    def unknown_reasons(self) -> tuple[str, ...]:
        """List every explicitly unknown dimension that prevents dispatch."""
        reasons: list[str] = []
        if self.memory_status == "unknown":
            reasons.append(f"memory:{self.memory_reason or 'unknown'}")
        for name, requirement in (
            ("context", self.context),
            ("offload", self.offload),
            ("residency", self.residency),
        ):
            if requirement.status == "unknown":
                reasons.append(f"{name}:{requirement.reason or 'unknown'}")
        return tuple(reasons)

    def to_dict(self) -> dict[str, object]:
        """Return stable JSON evidence stored with one queued execution."""
        memory: dict[str, object] = {"status": self.memory_status}
        if self.memory_status == "known":
            memory.update(
                {
                    "system_ram_bytes": self.system_ram_bytes,
                    "accelerator_memory_bytes": self.accelerator_memory_bytes,
                }
            )
            if self.accelerator_pool_id is not None:
                memory["accelerator_pool_id"] = self.accelerator_pool_id
        elif self.memory_reason is not None:
            memory["reason"] = self.memory_reason
        return {
            "schema": DEMAND_SCHEMA,
            "schema_version": ADMISSION_SCHEMA_VERSION,
            "kind": self.kind,
            "memory": memory,
            "context": self.context.to_dict(known_key="tokens"),
            "offload": self.offload.to_dict(known_key="mode"),
            "residency": self.residency.to_dict(known_key="mode"),
        }


@dataclass(frozen=True, slots=True)
class AdmissionDecision:
    """Persistable capacity outcome for one execution."""

    status: str
    reason: str
    required_bytes: dict[str, int]
    profile_fingerprint: str | None
    unknown_reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return stable JSON ready for admission or resource inspection."""
        return {
            "status": self.status,
            "reason": self.reason,
            "required_bytes": dict(self.required_bytes),
            "profile_fingerprint": self.profile_fingerprint,
            "unknown_reasons": list(self.unknown_reasons),
        }


def _nonnegative_int(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InventoryValidationError(f"{label} must be a non-negative integer")
    return value


def _nonnegative_byte_count(value: object, *, label: str) -> int:
    """Validate a byte count representable by SQLite's signed integer type."""
    result = _nonnegative_int(value, label=label)
    if result > _MAX_SQLITE_BYTE_COUNT:
        raise InventoryValidationError(
            f"{label} must fit the SQLite signed 64-bit integer range"
        )
    return result


def parse_admission_policy(payload: object) -> AdmissionPolicy:
    """Validate one versioned policy before it can influence capacity."""
    policy = _mapping(payload, label="admission policy")
    _reject_unknown(
        policy,
        {"schema", "schema_version", "pool_headroom_bytes"},
        label="admission policy",
    )
    if policy.get("schema") != POLICY_SCHEMA:
        raise InventoryValidationError(f"admission policy schema must be {POLICY_SCHEMA!r}")
    if (
        type(policy.get("schema_version")) is not int
        or policy["schema_version"] != ADMISSION_SCHEMA_VERSION
    ):
        raise InventoryValidationError("unsupported admission policy schema_version")
    raw_headroom = _mapping(
        policy.get("pool_headroom_bytes"),
        label="admission policy.pool_headroom_bytes",
    )
    headroom: dict[str, int] = {}
    for pool_id, raw_bytes in raw_headroom.items():
        validated_pool_id = _string(pool_id, label="pool_headroom_bytes key")
        if validated_pool_id != validated_pool_id.strip():
            raise InventoryValidationError(
                "pool_headroom_bytes key must not contain surrounding whitespace"
            )
        headroom[validated_pool_id] = _nonnegative_byte_count(
            raw_bytes,
            label=f"pool_headroom_bytes.{pool_id}",
        )
    return AdmissionPolicy(
        schema_version=ADMISSION_SCHEMA_VERSION,
        pool_headroom_bytes=headroom,
    )


def load_admission_policy(path: Path) -> AdmissionPolicy:
    """Load a strict policy document from disk."""
    return parse_admission_policy(
        load_strict_json(Path(path), label="admission policy", max_bytes=256 * 1024)
    )


def _parse_requirement(
    value: object,
    *,
    label: str,
    known_key: str,
    known_value: int | None = None,
    choices: frozenset[str] | None = None,
) -> DemandRequirement:
    """Validate one demand dimension without inventing missing values."""
    raw = _mapping(value, label=label)
    status = _string(raw.get("status"), label=f"{label}.status")
    if status == "not_applicable":
        _reject_unknown(raw, {"status"}, label=label)
        return DemandRequirement(status=status)
    if status == "unknown":
        _reject_unknown(raw, {"status", "reason"}, label=label)
        reason = _string(raw.get("reason"), label=f"{label}.reason")
        return DemandRequirement(status=status, reason=reason)
    if status != "known":
        raise InventoryValidationError(f"{label}.status must be known, not_applicable, or unknown")
    if choices is not None:
        _reject_unknown(raw, {"status", known_key}, label=label)
        selected = _string(raw.get(known_key), label=f"{label}.{known_key}")
        if selected not in choices:
            raise InventoryValidationError(
                f"{label}.{known_key} must be one of {sorted(choices)}"
            )
        return DemandRequirement(status=status, value=selected)
    _reject_unknown(raw, {"status", known_key}, label=label)
    parsed = require_positive_int(
        raw.get(known_key),
        label=f"{label}.{known_key}",
        diagnostic="must be non-negative integer",
    )
    return DemandRequirement(status=status, value=parsed)


def parse_workload_demand(payload: object) -> WorkloadDemand:
    """Validate one versioned demand for a supported heavyweight workload."""
    demand = _mapping(payload, label="workload demand")
    _reject_unknown(
        demand,
        {
            "schema",
            "schema_version",
            "kind",
            "memory",
            "context",
            "offload",
            "residency",
        },
        label="workload demand",
    )
    if demand.get("schema") != DEMAND_SCHEMA:
        raise InventoryValidationError(f"workload demand schema must be {DEMAND_SCHEMA!r}")
    if (
        type(demand.get("schema_version")) is not int
        or demand["schema_version"] != ADMISSION_SCHEMA_VERSION
    ):
        raise InventoryValidationError("unsupported workload demand schema_version")
    kind = _string(demand.get("kind"), label="workload demand.kind")
    if kind not in WORKLOAD_KINDS:
        raise InventoryValidationError(
            f"workload demand.kind must be one of {sorted(WORKLOAD_KINDS)}"
        )

    memory = _mapping(demand.get("memory"), label="workload demand.memory")
    memory_status = _string(memory.get("status"), label="workload demand.memory.status")
    system_ram_bytes = 0
    accelerator_memory_bytes = 0
    accelerator_pool_id: str | None = None
    memory_reason: str | None = None
    if memory_status == "known":
        _reject_unknown(
            memory,
            {
                "status",
                "system_ram_bytes",
                "accelerator_memory_bytes",
                "accelerator_pool_id",
            },
            label="workload demand.memory",
        )
        system_ram_bytes = _nonnegative_byte_count(
            memory.get("system_ram_bytes"),
            label="workload demand.memory.system_ram_bytes",
        )
        accelerator_memory_bytes = _nonnegative_byte_count(
            memory.get("accelerator_memory_bytes"),
            label="workload demand.memory.accelerator_memory_bytes",
        )
        raw_pool_id = memory.get("accelerator_pool_id")
        if raw_pool_id is not None:
            accelerator_pool_id = _string(
                raw_pool_id,
                label="workload demand.memory.accelerator_pool_id",
            )
    elif memory_status == "unknown":
        _reject_unknown(
            memory,
            {"status", "reason"},
            label="workload demand.memory",
        )
        memory_reason = _string(
            memory.get("reason"),
            label="workload demand.memory.reason",
        )
    else:
        raise InventoryValidationError("workload demand.memory.status must be known or unknown")

    return WorkloadDemand(
        kind=kind,
        memory_status=memory_status,
        system_ram_bytes=system_ram_bytes,
        accelerator_memory_bytes=accelerator_memory_bytes,
        accelerator_pool_id=accelerator_pool_id,
        memory_reason=memory_reason,
        context=_parse_requirement(
            demand.get("context"),
            label="workload demand.context",
            known_key="tokens",
        ),
        offload=_parse_requirement(
            demand.get("offload"),
            label="workload demand.offload",
            known_key="mode",
            choices=frozenset({"none", "partial", "full"}),
        ),
        residency=_parse_requirement(
            demand.get("residency"),
            label="workload demand.residency",
            known_key="mode",
            choices=frozenset({"transient", "resident"}),
        ),
    )


def load_workload_demand(path: Path) -> WorkloadDemand:
    """Load one strict workload demand document from disk."""
    return parse_workload_demand(
        load_strict_json(Path(path), label="workload demand", max_bytes=256 * 1024)
    )


def _pool_capacity_issue(pool: CapacityPool, *, expected_kind: str) -> str | None:
    """Return why a required pool's persisted capacity cannot be trusted."""
    if pool.kind != expected_kind:
        return "kind_mismatch"
    if pool.headroom_bytes is None or pool.available_bytes is None:
        return "capacity_unknown"
    if (
        type(pool.total_bytes) is not int
        or pool.total_bytes <= 0
        or type(pool.headroom_bytes) is not int
        or pool.headroom_bytes < 0
        or type(pool.available_bytes) is not int
        or pool.available_bytes < 0
    ):
        return "capacity_invalid"
    if any(
        value > _MAX_SQLITE_BYTE_COUNT
        for value in (pool.total_bytes, pool.headroom_bytes, pool.available_bytes)
    ):
        return "capacity_out_of_range"
    if pool.available_bytes != max(0, pool.total_bytes - pool.headroom_bytes):
        return "capacity_inconsistent"
    return None


def _workload_demand_out_of_range_field(demand: WorkloadDemand) -> str | None:
    """Return the first demand byte field outside SQLite's integer range."""
    for name in ("system_ram_bytes", "accelerator_memory_bytes"):
        value = getattr(demand, name)
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            or value > _MAX_SQLITE_BYTE_COUNT
        ):
            return name
    return None


def is_lightweight_cpu_adapter(adapter: object) -> bool:
    """Return whether an adapter is the exact bundled lightweight CPU adapter.

    Exact type comparison deliberately excludes subclasses. A subclass can
    inherit the adapter ID and implementation behavior, but admission treats
    only the bundled concrete class as trusted to run without capacity evidence.
    """
    return type(adapter) is DeterministicCpuAdapter


def is_lightweight_cpu_adapter_id(adapter_id: object) -> bool:
    """Return whether a persisted adapter ID names the lightweight CPU adapter.

    Admission persistence stores ``adapter_id`` rather than an adapter instance.
    This predicate keeps persisted boundary checks aligned with the identity
    declared by the bundled adapter class.
    """
    return adapter_id == DeterministicCpuAdapter.adapter_id


def evaluate_admission(
    profile: AdmissionProfile | None,
    demand: WorkloadDemand | None,
    *,
    allow_not_required: bool = False,
) -> AdmissionDecision:
    """Decide whether one demand fits the pinned capacity profile.

    Unknown evidence is blocked. A known demand that exceeds a required pool
    is denied. Fitting demand remains queued until the singleton SQLite claim
    atomically reserves the resource. The omission exemption is available only
    for the trusted deterministic CPU adapter; every heavyweight caller must
    supply explicit capacity evidence.
    """
    if not isinstance(allow_not_required, bool):
        raise InventoryValidationError("allow_not_required must be boolean")
    if profile is None and demand is None:
        if allow_not_required:
            return AdmissionDecision(
                status="not_required",
                reason="lightweight_deterministic_cpu",
                required_bytes={},
                profile_fingerprint=None,
            )
        return AdmissionDecision(
            status="blocked",
            reason="resource_admission_required",
            required_bytes={},
            profile_fingerprint=None,
            unknown_reasons=("admission:required",),
        )
    if profile is None:
        return AdmissionDecision(
            status="blocked",
            reason="admission_profile_not_configured",
            required_bytes={},
            profile_fingerprint=None,
            unknown_reasons=("profile:not_configured",),
        )
    if demand is None:
        return AdmissionDecision(
            status="blocked",
            reason="workload_demand_not_configured",
            required_bytes={},
            profile_fingerprint=profile.fingerprint,
            unknown_reasons=("demand:not_configured",),
        )
    if profile.status != "ready":
        return AdmissionDecision(
            status="blocked",
            reason="admission_profile_unknown",
            required_bytes={},
            profile_fingerprint=profile.fingerprint,
            unknown_reasons=profile.unknown_reasons,
        )
    if demand.unknown_reasons:
        return AdmissionDecision(
            status="blocked",
            reason=f"workload_demand_unknown:{demand.unknown_reasons[0]}",
            required_bytes={},
            profile_fingerprint=profile.fingerprint,
            unknown_reasons=demand.unknown_reasons,
        )
    out_of_range_field = _workload_demand_out_of_range_field(demand)
    if out_of_range_field is not None:
        issue = f"workload_demand_out_of_range:{out_of_range_field}"
        return AdmissionDecision(
            status="blocked",
            reason=issue,
            required_bytes={},
            profile_fingerprint=profile.fingerprint,
            unknown_reasons=(issue,),
        )

    required: dict[str, int] = {}
    required_kinds = {"system_ram": "system_ram"}
    if profile.topology == "unified_shared":
        required["system_ram"] = demand.system_ram_bytes + demand.accelerator_memory_bytes
        if demand.accelerator_pool_id is not None:
            return AdmissionDecision(
                status="blocked",
                reason=(
                    "accelerator_pool_not_applicable:"
                    f"{profile.topology}"
                ),
                required_bytes=required,
                profile_fingerprint=profile.fingerprint,
                unknown_reasons=(f"accelerator_pool:{demand.accelerator_pool_id}",),
            )
    elif profile.topology == "discrete":
        required["system_ram"] = demand.system_ram_bytes
        if demand.accelerator_memory_bytes > 0:
            if demand.accelerator_pool_id is None:
                return AdmissionDecision(
                    status="blocked",
                    reason="accelerator_pool_not_specified",
                    required_bytes=required,
                    profile_fingerprint=profile.fingerprint,
                    unknown_reasons=("accelerator_pool:not_specified",),
                )
            pool = next(
                (item for item in profile.pools if item.id == demand.accelerator_pool_id),
                None,
            )
            if pool is None or pool.kind != "dedicated_vram":
                return AdmissionDecision(
                    status="blocked",
                    reason=f"accelerator_pool_unknown:{demand.accelerator_pool_id}",
                    required_bytes=required,
                    profile_fingerprint=profile.fingerprint,
                    unknown_reasons=(f"accelerator_pool:{demand.accelerator_pool_id}",),
                )
            required[pool.id] = demand.accelerator_memory_bytes
            required_kinds[pool.id] = "dedicated_vram"
    else:
        return AdmissionDecision(
            status="blocked",
            reason=f"topology_unsupported:{profile.topology}",
            required_bytes={},
            profile_fingerprint=profile.fingerprint,
            unknown_reasons=(f"topology:{profile.topology}",),
        )

    out_of_range_pool = next(
        (
            pool_id
            for pool_id in sorted(required)
            if required[pool_id] > _MAX_SQLITE_BYTE_COUNT
        ),
        None,
    )
    if out_of_range_pool is not None:
        issue = f"required_bytes_out_of_range:{out_of_range_pool}"
        return AdmissionDecision(
            status="blocked",
            reason=issue,
            required_bytes={},
            profile_fingerprint=profile.fingerprint,
            unknown_reasons=(issue,),
        )

    pools_by_id: dict[str, list[CapacityPool]] = {}
    for pool in profile.pools:
        pools_by_id.setdefault(pool.id, []).append(pool)

    selected_pools: dict[str, CapacityPool] = {}
    for pool_id in sorted(required):
        candidates = pools_by_id.get(pool_id, [])
        if not candidates:
            issue = f"pool_missing:{pool_id}"
        elif len(candidates) != 1:
            issue = f"pool_ambiguous:{pool_id}"
        else:
            pool = candidates[0]
            capacity_issue = _pool_capacity_issue(
                pool, expected_kind=required_kinds[pool_id]
            )
            issue = (
                f"pool_{capacity_issue}:{pool_id}"
                if capacity_issue is not None
                else ""
            )
            if not issue:
                selected_pools[pool_id] = pool
        if issue:
            return AdmissionDecision(
                status="blocked",
                reason=f"admission_profile_invalid:{issue}",
                required_bytes={},
                profile_fingerprint=profile.fingerprint,
                unknown_reasons=(issue,),
            )

    over_budget = sorted(
        pool_id
        for pool_id, bytes_required in required.items()
        if bytes_required > int(selected_pools[pool_id].available_bytes)
    )
    if over_budget:
        return AdmissionDecision(
            status="denied",
            reason=f"over_budget:{over_budget[0]}",
            required_bytes=required,
            profile_fingerprint=profile.fingerprint,
        )
    return AdmissionDecision(
        status="queued",
        reason="capacity_fit",
        required_bytes=required,
        profile_fingerprint=profile.fingerprint,
    )


def build_admission_profile(
    inventory_report: object,
    policy: AdmissionPolicy,
) -> AdmissionProfile:
    """Derive conservative capacity pools from validated T02 evidence."""
    validated = validate_inventory_report(
        inventory_report, require_capacity_evidence=True
    )
    inventory = validated.document
    fingerprint = validated.fingerprint
    host = _mapping(inventory["host"], label="inventory report.host")
    memory = _mapping(host["memory"], label="inventory report.host.memory")
    topology = _mapping(memory["topology"], label="inventory report.host.memory.topology")
    topology_class = str(topology["class"])
    unknown_reasons: list[str] = list(validated.sharing_issues)
    relationships = _list(topology["sharing_relationships"], label="sharing_relationships")
    relationship_types = {
        str(_mapping(relation, label="sharing relationship")["relationship"])
        for relation in relationships
    }
    if topology_class not in {"unified_shared", "discrete"}:
        unknown_reasons.append(f"topology_{topology_class}")
    if topology_class == "unified_shared" and not relationship_types.intersection(
        {"shared_system_aperture", "carveout_within_system_ram"}
    ):
        unknown_reasons.append("unified_shared_relationship_evidence_missing")

    raw_pools = _list(topology["allocatable_pools"], label="allocatable_pools")
    by_id: dict[str, list[dict[str, Any]]] = {}
    for raw_pool in raw_pools:
        pool = _mapping(raw_pool, label="allocatable pool")
        pool_id = str(pool["id"])
        by_id.setdefault(pool_id, []).append(pool)
    for pool_id, observations in by_id.items():
        if len(observations) > 1:
            unknown_reasons.append(f"duplicate_pool_id:{pool_id}")
    if "system_ram" not in by_id:
        unknown_reasons.append("system_ram_pool_missing")
    system_pools = by_id.get("system_ram", [])
    system_pool = system_pools[0] if len(system_pools) == 1 else None
    observed_system_total = int(
        _mapping(memory["system"], label="inventory report.host.memory.system")[
            "total_bytes"
        ]
    )
    if system_pool is not None and (
        str(system_pool["kind"]) != "system_ram"
        or int(system_pool["total_bytes"]) != observed_system_total
    ):
        unknown_reasons.append("system_ram_total_mismatch")
    if topology_class == "unified_shared" and any(
        str(pool["kind"]) == "dedicated_vram"
        for observations in by_id.values()
        for pool in observations
    ):
        unknown_reasons.append("unified_topology_contains_dedicated_pool")
    if topology_class == "discrete" and not any(
        str(pool["kind"]) == "dedicated_vram"
        for observations in by_id.values()
        for pool in observations
    ):
        unknown_reasons.append("dedicated_vram_pool_missing")

    extra_headroom = sorted(set(policy.pool_headroom_bytes) - set(by_id))
    for pool_id in extra_headroom:
        unknown_reasons.append(f"policy_headroom_unknown_pool:{pool_id}")

    pools: list[CapacityPool] = []
    for pool_id in sorted(by_id, key=lambda item: (item != "system_ram", item)):
        headroom = policy.pool_headroom_bytes.get(pool_id)
        if headroom is None:
            unknown_reasons.append(f"policy_headroom_missing:{pool_id}")
        for pool in by_id[pool_id]:
            total = int(pool["total_bytes"])
            available = None if headroom is None else max(0, total - headroom)
            pools.append(
                CapacityPool(
                    id=pool_id,
                    kind=str(pool["kind"]),
                    total_bytes=total,
                    headroom_bytes=headroom,
                    available_bytes=available,
                )
            )

    shared_pool_ids = sorted(
        {
            f"{_mapping(relation, label='sharing relationship')['accelerator_id']}:"
            f"{_mapping(relation, label='sharing relationship')['pool']}"
            for relation in relationships
        }
    )
    stable_body: dict[str, object] = {
        "schema": PROFILE_SCHEMA,
        "schema_version": ADMISSION_SCHEMA_VERSION,
        "status": "unknown" if unknown_reasons else "ready",
        "origin": str(_mapping(inventory["evidence_gate"], label="evidence_gate")["evidence_origin"]),
        "environment_fingerprint": str(fingerprint["digest"]),
        "topology": topology_class,
        "pools": [pool.to_dict() for pool in pools],
        "shared_pool_ids": shared_pool_ids,
        "unknown_reasons": sorted(set(unknown_reasons)),
        "apex_qualification": "unverified",
        "apex_evidence": False,
    }
    return AdmissionProfile(
        status=str(stable_body["status"]),
        origin=str(stable_body["origin"]),
        environment_fingerprint=str(stable_body["environment_fingerprint"]),
        topology=topology_class,
        pools=tuple(pools),
        shared_pool_ids=tuple(shared_pool_ids),
        unknown_reasons=tuple(sorted(set(unknown_reasons))),
        fingerprint=digest_value(stable_body),
    )


def load_admission_profile(inventory_path: Path, policy_path: Path) -> AdmissionProfile:
    """Load one strict T02 report and policy, then derive a pinned profile."""
    report = load_strict_json(
        Path(inventory_path),
        label="inventory report",
        max_bytes=32 * 1024 * 1024,
    )
    return build_admission_profile(report, load_admission_policy(policy_path))

