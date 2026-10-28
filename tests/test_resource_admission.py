"""Resource-admission contracts derived from observed inventory evidence."""

from __future__ import annotations

from copy import deepcopy

from media_generation.inventory.fingerprint import build_environment_fingerprint


GIB = 1024**3


def inventory_report(
    *,
    topology_class: str = "unified_shared",
    system_total_bytes: int = 64 * GIB,
    allocatable_pools: list[dict[str, object]] | None = None,
    sharing_relationships: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    """Return a minimal complete T02 v1 report with deterministic evidence."""
    pools = deepcopy(allocatable_pools)
    if pools is None:
        pools = [
            {
                "id": "system_ram",
                "kind": "system_ram",
                "total_bytes": system_total_bytes,
                "source": "system",
            }
        ]
    relationships = deepcopy(sharing_relationships)
    if relationships is None:
        relationships = [
            {
                "accelerator_id": "drm:card1",
                "pool": "gtt",
                "relationship": "shared_system_aperture",
            },
            {
                "accelerator_id": "drm:card1",
                "pool": "vis_vram",
                "relationship": "duplicate_alias_not_additive",
            },
        ]
    if topology_class == "discrete":
        reported_total_bytes = sum(int(pool["total_bytes"]) for pool in pools)
    elif topology_class == "ambiguous":
        reported_total_bytes = None
    else:
        reported_total_bytes = system_total_bytes
    report = {
        "schema": "media-generation.inventory",
        "schema_version": 1,
        "run": {
            "run_id": "inv_fixture",
            "mode": "replay",
            "configuration": "configured",
            "status_reasons": [],
        },
        "model_inventory": {},
        "host": {
            "identity": {"hostname": "fixture", "platform": "Linux"},
            "os": {"id": "linux", "version_id": "1"},
            "kernel": {"release": "fixture", "machine": "aarch64"},
            "cpu": {
                "model": "APEX CPU",
                "architecture": "arm64",
                "logical_cores": 12,
                "source": "fixture",
            },
            "memory": {
                "system": {
                    "total_bytes": system_total_bytes,
                    "available_bytes": None,
                    "source": "fixture",
                },
                "topology": {
                    "class": topology_class,
            "reported_total_bytes": reported_total_bytes,
                    "reported_total_is_allocatable_pool": False,
                    "system_total_bytes": system_total_bytes,
                    "confidence": "high",
                    "allocatable_pools": pools,
                    "sharing_relationships": relationships,
                    "evidence": [],
                    "warnings": [],
                },
            },
            "accelerators": [],
            "accelerator_enumeration": {"status": "ok"},
            "runtime_toolchain": {},
            "python": {"implementation": "CPython", "version": "3.14.4"},
        },
        "environment_fingerprint": {},
        "runtimes": [],
        "bundles": [],
        "probes": [],
        "findings": [],
        "evidence_gate": {
            "report_written": True,
            "host_inventory_status": "ok",
            "configuration_inspection": "configured",
            "evidence_origin": "synthetic_replay",
            "apex_verification": "unverified",
            "apex_verification_reason": "live_apex_inventory_not_performed",
            "capability_qualification": "unverified",
            "capability_qualification_reason": "no_execution_or_qualification",
        },
    }
    report["environment_fingerprint"] = build_environment_fingerprint(
        report["host"], report["runtimes"]
    )
    return report


def test_synthetic_unified_profile_preserves_origin_and_applies_headroom() -> None:
    """A unified profile keeps replay provenance and subtracts explicit headroom."""
    from media_generation.admission import build_admission_profile, parse_admission_policy

    policy = parse_admission_policy(
        {
            "schema": "media-generation.admission-policy",
            "schema_version": 1,
            "pool_headroom_bytes": {"system_ram": 8 * GIB},
        }
    )

    profile = build_admission_profile(inventory_report(), policy)

    assert profile.status == "ready"
    assert profile.origin == "synthetic_replay"
    assert profile.apex_evidence is False
    assert profile.apex_qualification == "unverified"
    assert profile.topology == "unified_shared"
    assert profile.environment_fingerprint.startswith("sha256:")
    assert profile.to_dict()["fingerprint"].startswith("sha256:")
    assert profile.to_dict()["pools"] == [
        {
            "id": "system_ram",
            "kind": "system_ram",
            "total_bytes": 64 * GIB,
            "headroom_bytes": 8 * GIB,
            "available_bytes": 56 * GIB,
        }
    ]
    assert profile.to_dict()["shared_pool_ids"] == ["drm:card1:gtt", "drm:card1:vis_vram"]


def test_admission_policy_rejects_boolean_schema_version() -> None:
    """Boolean JSON values cannot impersonate the integer policy version."""
    import pytest

    from media_generation.admission import parse_admission_policy
    from media_generation.inventory.schema import InventoryValidationError

    with pytest.raises(InventoryValidationError, match="schema_version"):
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": True,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        )


def test_admission_policy_rejects_pool_id_surrounding_whitespace() -> None:
    """Pool identifiers must match observed IDs without normalization."""
    import pytest

    from media_generation.admission import parse_admission_policy
    from media_generation.inventory.schema import InventoryValidationError

    with pytest.raises(InventoryValidationError, match="surrounding whitespace"):
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {" system_ram ": 8 * GIB},
            }
        )


def test_workload_demand_rejects_boolean_schema_version() -> None:
    """Boolean JSON values cannot impersonate the integer demand version."""
    import pytest

    from media_generation.admission import parse_workload_demand
    from media_generation.inventory.schema import InventoryValidationError

    demand = workload_demand()
    demand["schema_version"] = True

    with pytest.raises(InventoryValidationError, match="schema_version"):
        parse_workload_demand(demand)


def test_workload_demand_context_tokens_preserves_legacy_diagnostic() -> None:
    """Invalid context token counts retain the established public diagnostic."""
    import pytest

    from media_generation.admission import parse_workload_demand
    from media_generation.inventory.schema import InventoryValidationError

    demand = workload_demand()
    demand["context"] = {"status": "known", "tokens": -1}

    with pytest.raises(InventoryValidationError) as captured:
        parse_workload_demand(demand)

    assert str(captured.value) == (
        "workload demand.context.tokens must be non-negative integer"
    )


def workload_demand(
    *,
    kind: str = "image",
    system_ram_bytes: int = 16 * GIB,
    accelerator_memory_bytes: int = 32 * GIB,
    accelerator_pool_id: str | None = None,
) -> dict[str, object]:
    """Return an explicit demand with known memory and non-applicable context."""
    memory: dict[str, object] = {
        "status": "known",
        "system_ram_bytes": system_ram_bytes,
        "accelerator_memory_bytes": accelerator_memory_bytes,
    }
    if accelerator_pool_id is not None:
        memory["accelerator_pool_id"] = accelerator_pool_id
    return {
        "schema": "media-generation.workload-demand",
        "schema_version": 1,
        "kind": kind,
        "memory": memory,
        "context": {"status": "not_applicable"},
        "offload": {"status": "known", "mode": "none"},
        "residency": {"status": "known", "mode": "resident"},
    }


def admission_record(service, job_id: str):
    """Return the typed admission record from one consistent inspection."""
    inspection = service.inspect_admission(job_id)
    assert inspection is not None
    return inspection.admission


def test_zero_byte_demand_is_persisted_as_queued(tmp_path) -> None:
    """Known zero-byte demand is valid and remains claimable after persistence."""
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.service import GenerationService
    from test_durable_execution import request

    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        admission_profile=profile,
    )

    queued = service.enqueue(
        "zero-byte-demand",
        request(),
        workload_demand=parse_workload_demand(
            workload_demand(system_ram_bytes=0, accelerator_memory_bytes=0)
        ),
    )

    assert queued.status == "queued"
    assert service.get_provenance(queued.job_id)["status"] == "queued"
    admission = admission_record(service, queued.job_id)
    assert admission.decision == "queued"
    assert admission.required_bytes == {"system_ram": 0}


def test_zero_byte_demand_reserves_zero_bytes_on_claim(tmp_path) -> None:
    """The atomic claim records zero bytes instead of treating the pool as missing."""
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.adapters import PROCESS_CONTAINED_CONTRACT
    from media_generation.service import GenerationService
    from test_durable_execution import request

    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        admission_profile=profile,
    )
    queued = service.enqueue(
        "zero-byte-claim",
        request(),
        workload_demand=parse_workload_demand(
            workload_demand(system_ram_bytes=0, accelerator_memory_bytes=0)
        ),
    )
    _, adapter_configuration_json, _, privacy_compliance_json = (
        service._current_privacy_snapshot()
    )

    claim = service._store.claim_next_execution(
        attempt_id="att_0123456789abcdef0123456789abcdef",
        owner_id="worker_zero",
        adapter_id=service.adapter.adapter_id,
        adapter_configuration_json=adapter_configuration_json,
        privacy_compliance_json=privacy_compliance_json,
        resolved_output_directory=str(tmp_path / "images"),
        process_contained=True,
        containment_contract=PROCESS_CONTAINED_CONTRACT,
        timestamp="2026-10-27T00:00:00Z",
        lease_expires_at="2026-10-27T00:01:00Z",
        job_id=queued.job_id,
    )

    assert claim is not None
    admission = admission_record(service, queued.job_id)
    assert admission.decision == "reserved"
    assert admission.reserved_bytes == {"system_ram": 0}


def test_unified_accelerator_memory_is_additional_system_memory() -> None:
    """Unified shared memory is charged to system RAM without a second pool."""
    from media_generation.admission import (
        build_admission_profile,
        evaluate_admission,
        parse_admission_policy,
        parse_workload_demand,
    )

    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )

    accepted = evaluate_admission(
        profile,
        parse_workload_demand(
            workload_demand(system_ram_bytes=20 * GIB, accelerator_memory_bytes=36 * GIB)
        ),
    )
    denied = evaluate_admission(
        profile,
        parse_workload_demand(
            workload_demand(system_ram_bytes=20 * GIB, accelerator_memory_bytes=37 * GIB)
        ),
    )

    assert accepted.status == "queued"
    assert accepted.reason == "capacity_fit"
    assert accepted.required_bytes == {"system_ram": 56 * GIB}
    assert denied.status == "denied"
    assert denied.reason == "over_budget:system_ram"
    assert denied.required_bytes == {"system_ram": 57 * GIB}


def test_unified_required_bytes_outside_sqlite_range_are_blocked() -> None:
    """An unsafe addition cannot become a queued, dispatchable decision."""
    from media_generation.admission import (
        build_admission_profile,
        evaluate_admission,
        parse_admission_policy,
        parse_workload_demand,
    )

    maximum = (1 << 63) - 1
    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )

    demand = parse_workload_demand(
        workload_demand(system_ram_bytes=maximum, accelerator_memory_bytes=1)
    )
    assert demand.system_ram_bytes == maximum
    assert demand.accelerator_memory_bytes == 1
    decision = evaluate_admission(profile, demand)

    assert decision.status == "blocked"
    assert decision.reason == "required_bytes_out_of_range:system_ram"
    assert decision.required_bytes == {}
    assert decision.unknown_reasons == ("required_bytes_out_of_range:system_ram",)


def test_direct_out_of_range_workload_bytes_are_blocked() -> None:
    """Directly constructed invalid demand cannot bypass input validation."""
    from dataclasses import replace

    from media_generation.admission import (
        build_admission_profile,
        evaluate_admission,
        parse_admission_policy,
        parse_workload_demand,
    )

    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    demand = replace(
        parse_workload_demand(workload_demand()),
        system_ram_bytes=1 << 63,
    )

    decision = evaluate_admission(profile, demand)

    assert decision.status == "blocked"
    assert decision.reason == "workload_demand_out_of_range:system_ram_bytes"
    assert decision.required_bytes == {}
    assert decision.unknown_reasons == (
        "workload_demand_out_of_range:system_ram_bytes",
    )


def test_unified_topology_rejects_an_accelerator_pool_selector() -> None:
    """Unified demand charges system RAM and cannot name an independent pool."""
    from media_generation.admission import (
        build_admission_profile,
        evaluate_admission,
        parse_admission_policy,
        parse_workload_demand,
    )

    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )

    decision = evaluate_admission(
        profile,
        parse_workload_demand(
            workload_demand(accelerator_pool_id="drm:card1:gtt")
        ),
    )

    assert decision.status == "blocked"
    assert decision.reason == "accelerator_pool_not_applicable:unified_shared"
    assert decision.required_bytes == {"system_ram": 48 * GIB}
    assert decision.unknown_reasons == ("accelerator_pool:drm:card1:gtt",)


def test_unified_topology_requires_observed_shared_memory_evidence() -> None:
    """A unified label or duplicate alias alone cannot prove shared memory."""
    from media_generation.admission import (
        build_admission_profile,
        evaluate_admission,
        parse_admission_policy,
        parse_workload_demand,
    )

    policy = parse_admission_policy(
        {
            "schema": "media-generation.admission-policy",
            "schema_version": 1,
            "pool_headroom_bytes": {"system_ram": 8 * GIB},
        }
    )
    reports = {
        "empty": inventory_report(sharing_relationships=[]),
        "alias_only": inventory_report(
            sharing_relationships=[
                {
                    "accelerator_id": "drm:card1",
                    "pool": "vis_vram",
                    "relationship": "duplicate_alias_not_additive",
                }
            ]
        ),
    }

    observed: dict[str, tuple[str, tuple[str, ...], str]] = {}
    for name, report in reports.items():
        profile = build_admission_profile(report, policy)
        decision = evaluate_admission(
            profile, parse_workload_demand(workload_demand())
        )
        observed[name] = (
            profile.status,
            profile.unknown_reasons,
            decision.status,
        )

    expected = (
        "unknown",
        ("unified_shared_relationship_evidence_missing",),
        "blocked",
    )
    assert observed == {"empty": expected, "alias_only": expected}


def test_unified_carveout_evidence_is_valid_and_not_additive() -> None:
    """A T02-reported APU carveout supports unified accounting in system RAM."""
    from media_generation.admission import (
        build_admission_profile,
        evaluate_admission,
        parse_admission_policy,
        parse_workload_demand,
    )

    profile = build_admission_profile(
        inventory_report(
            sharing_relationships=[
                {
                    "accelerator_id": "drm:card1",
                    "pool": "apu_memory",
                    "relationship": "carveout_within_system_ram",
                }
            ]
        ),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    decision = evaluate_admission(
        profile,
        parse_workload_demand(
            workload_demand(system_ram_bytes=20 * GIB, accelerator_memory_bytes=36 * GIB)
        ),
    )

    assert profile.status == "ready"
    assert profile.shared_pool_ids == ("drm:card1:apu_memory",)
    assert decision.status == "queued"
    assert decision.required_bytes == {"system_ram": 56 * GIB}


def test_discrete_topology_rejects_unified_carveout_evidence() -> None:
    """A system-RAM carveout contradicts a discrete topology classification."""
    from media_generation.admission import (
        build_admission_profile,
        evaluate_admission,
        parse_admission_policy,
        parse_workload_demand,
    )

    profile = build_admission_profile(
        inventory_report(
            topology_class="discrete",
            allocatable_pools=[
                {
                    "id": "system_ram",
                    "kind": "system_ram",
                    "total_bytes": 64 * GIB,
                    "source": "system",
                },
                {
                    "id": "drm:card1:vram",
                    "kind": "dedicated_vram",
                    "total_bytes": 8 * GIB,
                    "source": "nvidia-smi",
                },
            ],
            sharing_relationships=[
                {
                    "accelerator_id": "drm:card1",
                    "pool": "apu_memory",
                    "relationship": "carveout_within_system_ram",
                }
            ],
        ),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {
                    "system_ram": 8 * GIB,
                    "drm:card1:vram": 2 * GIB,
                },
            }
        ),
    )
    decision = evaluate_admission(
        profile,
        parse_workload_demand(
            workload_demand(accelerator_pool_id="drm:card1:vram")
        ),
    )

    assert profile.status == "unknown"
    assert "discrete_topology_has_shared_pool:drm:card1:apu_memory" in (
        profile.unknown_reasons
    )
    assert decision.status == "blocked"


def test_unified_admission_requires_a_valid_system_ram_pool() -> None:
    """A ready profile cannot select a missing or unproven unified pool."""
    from dataclasses import replace

    from media_generation.admission import (
        build_admission_profile,
        evaluate_admission,
        parse_admission_policy,
        parse_workload_demand,
    )

    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    system_pool = profile.pools[0]
    invalid_profiles = (
        ((), "pool_missing:system_ram"),
        (
            (replace(system_pool, kind="dedicated_vram"),),
            "pool_kind_mismatch:system_ram",
        ),
        (
            (replace(system_pool, headroom_bytes=None, available_bytes=None),),
            "pool_capacity_unknown:system_ram",
        ),
        (
            (replace(system_pool, available_bytes=64 * GIB),),
            "pool_capacity_inconsistent:system_ram",
        ),
    )

    observed = []
    for pools, issue in invalid_profiles:
        decision = evaluate_admission(
            replace(profile, pools=pools),
            parse_workload_demand(workload_demand()),
        )
        observed.append((decision.status, decision.reason, decision.unknown_reasons))
    expected = [
        ("blocked", f"admission_profile_invalid:{issue}", (issue,))
        for _, issue in invalid_profiles
    ]
    assert observed == expected


def test_discrete_vram_is_checked_in_its_own_explicit_pool() -> None:
    """Dedicated device memory has an independent pool and refuses ambiguity."""
    from media_generation.admission import (
        build_admission_profile,
        evaluate_admission,
        parse_admission_policy,
        parse_workload_demand,
    )

    profile = build_admission_profile(
        inventory_report(
            topology_class="discrete",
            system_total_bytes=32 * GIB,
            allocatable_pools=[
                {
                    "id": "system_ram",
                    "kind": "system_ram",
                    "total_bytes": 32 * GIB,
                    "source": "system",
                },
                {
                    "id": "nvidia:0:vram",
                    "kind": "dedicated_vram",
                    "total_bytes": 24 * GIB,
                    "source": "nvidia-smi",
                },
            ],
                sharing_relationships=[],
        ),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {
                    "system_ram": 4 * GIB,
                    "nvidia:0:vram": 4 * GIB,
                },
            }
        ),
    )

    accepted = evaluate_admission(
        profile,
        parse_workload_demand(
            workload_demand(
                system_ram_bytes=16 * GIB,
                accelerator_memory_bytes=20 * GIB,
                accelerator_pool_id="nvidia:0:vram",
            )
        ),
    )
    denied = evaluate_admission(
        profile,
        parse_workload_demand(
            workload_demand(
                system_ram_bytes=16 * GIB,
                accelerator_memory_bytes=21 * GIB,
                accelerator_pool_id="nvidia:0:vram",
            )
        ),
    )
    unknown_pool = evaluate_admission(
        profile,
        parse_workload_demand(
            workload_demand(
                system_ram_bytes=16 * GIB,
                accelerator_memory_bytes=20 * GIB,
            )
        ),
    )

    assert accepted.status == "queued"
    assert accepted.required_bytes == {
        "system_ram": 16 * GIB,
        "nvidia:0:vram": 20 * GIB,
    }
    assert denied.status == "denied"
    assert denied.reason == "over_budget:nvidia:0:vram"
    assert unknown_pool.status == "blocked"
    assert unknown_pool.reason == "accelerator_pool_not_specified"


def test_discrete_admission_rejects_inconsistent_pool_capacity_evidence() -> None:
    """Forged VRAM capacity cannot exceed its observed total or ignore headroom."""
    from dataclasses import replace

    from media_generation.admission import (
        build_admission_profile,
        evaluate_admission,
        parse_admission_policy,
        parse_workload_demand,
    )

    profile = build_admission_profile(
        inventory_report(
            topology_class="discrete",
            allocatable_pools=[
                {
                    "id": "system_ram",
                    "kind": "system_ram",
                    "total_bytes": 64 * GIB,
                    "source": "system",
                },
                {
                    "id": "drm:card1:vram",
                    "kind": "dedicated_vram",
                    "total_bytes": 8 * GIB,
                    "source": "nvidia-smi",
                },
            ],
            sharing_relationships=[],
        ),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {
                    "system_ram": 8 * GIB,
                    "drm:card1:vram": 2 * GIB,
                },
            }
        ),
    )
    vram_pool = next(pool for pool in profile.pools if pool.id == "drm:card1:vram")
    invalid_pools = (
        (
            replace(vram_pool, headroom_bytes=-1, available_bytes=9 * GIB),
            "pool_capacity_invalid:drm:card1:vram",
        ),
        (
            replace(vram_pool, headroom_bytes=0, available_bytes=9 * GIB),
            "pool_capacity_inconsistent:drm:card1:vram",
        ),
    )

    observed = []
    for invalid_pool, issue in invalid_pools:
        invalid_profile = replace(
            profile,
            pools=tuple(
                invalid_pool if pool.id == invalid_pool.id else pool
                for pool in profile.pools
            ),
        )
        decision = evaluate_admission(
            invalid_profile,
            parse_workload_demand(
                workload_demand(
                    system_ram_bytes=1 * GIB,
                    accelerator_memory_bytes=8 * GIB,
                    accelerator_pool_id="drm:card1:vram",
                )
            ),
        )
        observed.append((decision.status, decision.reason, decision.unknown_reasons))
    expected = [
        ("blocked", f"admission_profile_invalid:{issue}", (issue,))
        for _, issue in invalid_pools
    ]
    assert observed == expected


def test_unknown_topology_and_unknown_demand_fail_closed_with_reasons() -> None:
    """Unknown topology or demand dimensions produce explicit blocked decisions."""
    from media_generation.admission import (
        build_admission_profile,
        evaluate_admission,
        parse_admission_policy,
        parse_workload_demand,
    )

    unknown_profile = build_admission_profile(
        inventory_report(topology_class="unknown"),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    profile_decision = evaluate_admission(
        unknown_profile,
        parse_workload_demand(workload_demand()),
    )

    ready_profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    payload = workload_demand()
    payload["memory"] = {"status": "unknown", "reason": "peak_memory_not_measured"}
    demand_decision = evaluate_admission(
        ready_profile,
        parse_workload_demand(payload),
    )

    assert unknown_profile.status == "unknown"
    assert "topology_unknown" in unknown_profile.unknown_reasons
    assert profile_decision.status == "blocked"
    assert profile_decision.reason == "admission_profile_unknown"
    assert demand_decision.status == "blocked"
    assert demand_decision.reason == "workload_demand_unknown:memory:peak_memory_not_measured"


def test_all_supported_workload_kinds_share_the_same_capacity_decision() -> None:
    """Image, text, vision, scoring, and loading use one admission interface."""
    import pytest

    from media_generation.admission import (
        build_admission_profile,
        evaluate_admission,
        parse_admission_policy,
        parse_workload_demand,
    )

    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )

    for kind in ("image", "text", "vision", "scoring", "model_loading"):
        decision = evaluate_admission(
            profile,
            parse_workload_demand(workload_demand(kind=kind)),
        )
        assert decision.status == "queued", kind
        assert decision.reason == "capacity_fit"


def test_blocked_admission_is_pinned_and_never_dispatched(tmp_path) -> None:
    """An unknown demand remains durable and cannot create an attempt."""
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.service import GenerationService
    from test_durable_execution import request

    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    payload = workload_demand()
    payload["memory"] = {"status": "unknown", "reason": "peak_memory_not_measured"}
    demand = parse_workload_demand(payload)
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        admission_profile=profile,
    )

    queued = service.enqueue("blocked-demand", request(), workload_demand=demand)
    snapshot = admission_record(service, queued.job_id)

    assert snapshot.decision == "blocked"
    assert snapshot.reason == "workload_demand_unknown:memory:peak_memory_not_measured"
    assert snapshot.demand == demand.to_dict()
    assert service.work() == {"status": "idle", "processed": 0}
    assert service.get_provenance(queued.job_id)["attempts"] == []
    assert service._store.resource_snapshot()["state"] == "available"


def test_reserved_demand_is_visible_on_the_singleton_resource(tmp_path) -> None:
    """A fitting job reserves its pinned bytes under the existing claim owner."""
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from media_generation.adapters import (
        PROCESS_CONTAINED_CONTRACT,
        DeterministicCpuAdapter,
    )
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.service import GenerationService
    from test_durable_execution import request

    entered = threading.Event()
    resume = threading.Event()

    class PausedAdapter(DeterministicCpuAdapter):
        containment_contract = PROCESS_CONTAINED_CONTRACT

        def generate(self, plan, destination):
            entered.set()
            assert resume.wait(5)
            return super().generate(plan, destination)

    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    demand = parse_workload_demand(
        workload_demand(system_ram_bytes=20 * GIB, accelerator_memory_bytes=20 * GIB)
    )
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        adapter=PausedAdapter(),
        admission_profile=profile,
    )
    first = service.enqueue("first-admitted", request(), workload_demand=demand)

    with ThreadPoolExecutor(max_workers=1) as pool:
        running = pool.submit(service.work)
        assert entered.wait(5)
        resource = service._store.resource_snapshot()
        reserved = admission_record(service, first.job_id)
        inspection = service.inspect_admission(first.job_id)
        assert inspection is not None
        assert resource["state"] == "claimed"
        assert resource["job_id"] == first.job_id
        assert resource["owner_id"] is not None
        assert resource["admission_decision"] == "reserved"
        assert resource["admission_reserved_bytes_json"] == '{"system_ram":42949672960}'
        assert reserved.decision == "reserved"
        assert reserved.reserved_bytes == {"system_ram": 40 * GIB}
        assert inspection.to_dict() == {
            "admission": reserved.to_dict(),
            "resource": resource,
        }

        second = service.enqueue("second-queued", request(), workload_demand=demand)
        busy = admission_record(service, second.job_id)
        assert busy.decision == "queued"
        assert busy.reason == "capacity_fit"
        assert service.get_resource_reservation(first.job_id)["state"] == "claimed"
        assert service.get_resource_reservation(second.job_id) is None
        second_inspection = service.inspect_admission(second.job_id)
        assert second_inspection is not None
        assert second_inspection.resource is None
        resume.set()
        assert running.result(timeout=10)["status"] == "complete"

    released = admission_record(service, first.job_id)
    assert released.decision == "released"
    assert released.reason == "termination_and_publication_reconciled"
    assert service._store.resource_snapshot()["state"] == "available"


def test_claim_rejects_pinned_resource_busy_admission_without_side_effects(
    tmp_path,
) -> None:
    """A resource-busy admission reason cannot create or reserve an attempt."""
    from media_generation.adapters import PROCESS_CONTAINED_CONTRACT
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.service import GenerationService
    from test_durable_execution import request

    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    database = tmp_path / "studio.sqlite3"
    service = GenerationService(
        database,
        tmp_path / "images",
        admission_profile=profile,
    )
    queued = service.enqueue(
        "resource-busy-pinned",
        request(),
        workload_demand=parse_workload_demand(workload_demand()),
    )
    with service._store._connection(transaction=True) as connection:
        connection.execute(
            """UPDATE execution_admissions
               SET decision_reason = 'resource_busy'
               WHERE job_id = ?""",
            (queued.job_id,),
        )
    _, adapter_configuration_json, _, privacy_compliance_json = (
        service._current_privacy_snapshot()
    )

    claim = service._store.claim_next_execution(
        attempt_id="att_0123456789abcdef0123456789abcdef",
        owner_id="worker_resource_busy",
        adapter_id=service.adapter.adapter_id,
        adapter_configuration_json=adapter_configuration_json,
        privacy_compliance_json=privacy_compliance_json,
        resolved_output_directory=str(tmp_path / "images"),
        process_contained=True,
        containment_contract=PROCESS_CONTAINED_CONTRACT,
        timestamp="2026-10-27T00:00:00Z",
        lease_expires_at="2026-10-27T00:01:00Z",
        job_id=queued.job_id,
    )

    assert claim is None
    snapshot = service.get_provenance(queued.job_id)
    assert snapshot["status"] == "queued"
    assert snapshot["attempts"] == []
    assert snapshot["admission"]["reason"] == "resource_busy"
    assert snapshot["admission"]["reserved_bytes"] is None
    assert snapshot["execution"]["resource_state"] == "available"

    with service._store._connection(transaction=True) as connection:
        connection.execute(
            """UPDATE execution_admissions
               SET decision_reason = 'capacity_fit'
               WHERE job_id = ?""",
            (queued.job_id,),
        )
    claim = service._store.claim_next_execution(
        attempt_id="att_fedcba9876543210fedcba9876543210",
        owner_id="worker_capacity_fit",
        adapter_id=service.adapter.adapter_id,
        adapter_configuration_json=adapter_configuration_json,
        privacy_compliance_json=privacy_compliance_json,
        resolved_output_directory=str(tmp_path / "images"),
        process_contained=True,
        containment_contract=PROCESS_CONTAINED_CONTRACT,
        timestamp="2026-10-27T00:00:01Z",
        lease_expires_at="2026-10-27T00:01:01Z",
        job_id=queued.job_id,
    )
    assert claim is not None
    admission = admission_record(service, queued.job_id)
    assert admission.decision == "reserved"
    assert admission.reserved_bytes == {"system_ram": 48 * GIB}


def test_profile_rejects_fingerprint_evidence_not_derived_from_host() -> None:
    """A self-consistent unrelated fingerprint block cannot admit capacity."""
    import pytest

    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
    )
    from media_generation.inventory.schema import (
        InventoryValidationError,
        digest_value,
    )

    report = inventory_report()
    fingerprint = report["environment_fingerprint"]
    assert isinstance(fingerprint, dict)
    inputs = fingerprint["inputs"]
    assert isinstance(inputs, dict)
    cpu = inputs["cpu"]
    assert isinstance(cpu, dict)
    cpu["model"] = "unrelated host"
    fingerprint["digest"] = digest_value(inputs)

    with pytest.raises(InventoryValidationError, match="fingerprint"):
        build_admission_profile(
            report,
            parse_admission_policy(
                {
                    "schema": "media-generation.admission-policy",
                    "schema_version": 1,
                    "pool_headroom_bytes": {"system_ram": GIB},
                }
            ),
        )


def test_reported_total_cannot_be_treated_as_allocatable_memory() -> None:
    """Summary topology totals are evidence, not capacity pools."""
    import pytest

    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
    )
    from media_generation.inventory.schema import InventoryValidationError

    report = inventory_report()
    host = report["host"]
    assert isinstance(host, dict)
    memory = host["memory"]
    assert isinstance(memory, dict)
    topology = memory["topology"]
    assert isinstance(topology, dict)
    topology["reported_total_is_allocatable_pool"] = True

    with pytest.raises(InventoryValidationError, match="allocatable pool"):
        build_admission_profile(
            report,
            parse_admission_policy(
                {
                    "schema": "media-generation.admission-policy",
                    "schema_version": 1,
                    "pool_headroom_bytes": {"system_ram": GIB},
                }
            ),
        )


def test_duplicate_shared_memory_aliases_are_not_additive_pools() -> None:
    """Repeated aperture and VRAM aliases remain observations, not capacity."""
    from media_generation.admission import (
        build_admission_profile,
        evaluate_admission,
        parse_admission_policy,
        parse_workload_demand,
    )

    relationships = [
        {
            "accelerator_id": "drm:card1",
            "pool": "gtt",
            "relationship": "shared_system_aperture",
        }
    ] * 2 + [
        {
            "accelerator_id": "drm:card1",
            "pool": "vis_vram",
            "relationship": "duplicate_alias_not_additive",
        }
    ] * 2
    profile = build_admission_profile(
        inventory_report(sharing_relationships=relationships),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )

    assert [pool.id for pool in profile.pools] == ["system_ram"]
    assert profile.shared_pool_ids == ("drm:card1:gtt", "drm:card1:vis_vram")
    decision = evaluate_admission(
        profile,
        parse_workload_demand(
            workload_demand(system_ram_bytes=2 * GIB, accelerator_memory_bytes=54 * GIB)
        ),
    )
    assert decision.status == "queued"
    assert decision.required_bytes == {"system_ram": 56 * GIB}


def test_duplicate_canonical_pool_ids_preserve_conflicting_unknown_evidence() -> None:
    """Duplicate pool IDs stay visibly conflicting and cannot admit work."""
    from media_generation.admission import (
        build_admission_profile,
        evaluate_admission,
        parse_admission_policy,
        parse_workload_demand,
    )

    policy = parse_admission_policy(
        {
            "schema": "media-generation.admission-policy",
            "schema_version": 1,
            "pool_headroom_bytes": {"system_ram": 8 * GIB},
        }
    )
    first = build_admission_profile(
        inventory_report(
            allocatable_pools=[
                {
                    "id": "system_ram",
                    "kind": "system_ram",
                    "total_bytes": 64 * GIB,
                    "source": "fixture-a",
                },
                {
                    "id": "system_ram",
                    "kind": "system_ram",
                    "total_bytes": 32 * GIB,
                    "source": "fixture-b",
                },
            ]
        ),
        policy,
    )
    second = build_admission_profile(
        inventory_report(
            allocatable_pools=[
                {
                    "id": "system_ram",
                    "kind": "system_ram",
                    "total_bytes": 64 * GIB,
                    "source": "fixture-a",
                },
                {
                    "id": "system_ram",
                    "kind": "system_ram",
                    "total_bytes": 16 * GIB,
                    "source": "fixture-c",
                },
            ]
        ),
        policy,
    )

    assert first.status == "unknown"
    assert "duplicate_pool_id:system_ram" in first.unknown_reasons
    assert [pool.total_bytes for pool in first.pools] == [64 * GIB, 32 * GIB]
    assert first.fingerprint != second.fingerprint
    decision = evaluate_admission(
        first,
        parse_workload_demand(
            workload_demand(system_ram_bytes=16 * GIB, accelerator_memory_bytes=16 * GIB)
        ),
    )
    assert decision.status == "blocked"
    assert decision.reason == "admission_profile_unknown"


def test_discrete_topology_requires_an_explicit_dedicated_vram_pool() -> None:
    """A discrete label without observed device memory cannot admit work."""
    from media_generation.admission import (
        build_admission_profile,
        evaluate_admission,
        parse_admission_policy,
        parse_workload_demand,
    )

    profile = build_admission_profile(
        inventory_report(topology_class="discrete", sharing_relationships=[]),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    decision = evaluate_admission(
        profile, parse_workload_demand(workload_demand())
    )

    assert profile.status == "unknown"
    assert "dedicated_vram_pool_missing" in profile.unknown_reasons
    assert decision.status == "blocked"


def test_system_pool_must_match_observed_system_memory_total() -> None:
    """A policy cannot silently widen capacity by changing pool totals."""
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
    )

    profile = build_admission_profile(
        inventory_report(
            allocatable_pools=[
                {
                    "id": "system_ram",
                    "kind": "system_ram",
                    "total_bytes": 128 * GIB,
                    "source": "system",
                }
            ]
        ),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )

    assert profile.status == "unknown"
    assert "system_ram_total_mismatch" in profile.unknown_reasons


def test_topology_summary_must_match_its_allocatable_pools() -> None:
    """A topology summary cannot be detached from the pools it describes."""
    import pytest

    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
    )
    from media_generation.inventory.schema import InventoryValidationError

    report = inventory_report()
    host = report["host"]
    assert isinstance(host, dict)
    memory = host["memory"]
    assert isinstance(memory, dict)
    topology = memory["topology"]
    assert isinstance(topology, dict)
    topology["reported_total_bytes"] = 8 * GIB
    report["environment_fingerprint"] = build_environment_fingerprint(
        host, report["runtimes"]
    )

    with pytest.raises(InventoryValidationError, match="reported total"):
        build_admission_profile(
            report,
            parse_admission_policy(
                {
                    "schema": "media-generation.admission-policy",
                    "schema_version": 1,
                    "pool_headroom_bytes": {"system_ram": GIB},
                }
            ),
        )


def test_restart_uses_pinned_profile_and_preserves_its_evidence(tmp_path) -> None:
    """A later process can dispatch queued work without rebuilding host state."""
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.service import GenerationService
    from test_durable_execution import request

    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    demand = parse_workload_demand(
        workload_demand(system_ram_bytes=20 * GIB, accelerator_memory_bytes=20 * GIB)
    )
    database = tmp_path / "studio.sqlite3"
    first = GenerationService(
        database, tmp_path / "images", admission_profile=profile
    ).enqueue("restart-queued", request(), workload_demand=demand)
    restarted = GenerationService(database, tmp_path / "images")
    pinned = admission_record(restarted, first.job_id)
    assert pinned.profile == profile.to_dict()
    assert pinned.demand == demand.to_dict()

    assert restarted.work()["status"] == "complete"
    assert admission_record(restarted, first.job_id).profile == profile.to_dict()


def test_succeeded_idempotent_reuse_preserves_first_pinned_demand(tmp_path) -> None:
    """A succeeded key never retroactively replaces its original capacity evidence."""
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.service import GenerationService
    from test_durable_execution import request

    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        admission_profile=profile,
    )
    first_demand = parse_workload_demand(
        workload_demand(system_ram_bytes=10 * GIB, accelerator_memory_bytes=10 * GIB)
    )
    changed_demand = parse_workload_demand(
        workload_demand(system_ram_bytes=20 * GIB, accelerator_memory_bytes=20 * GIB)
    )
    first = service.enqueue("stable-demand", request(), workload_demand=first_demand)
    assert service.work()["status"] == "complete"
    reused = service.enqueue("stable-demand", request(), workload_demand=changed_demand)

    reused_admission = admission_record(service, reused.job_id)
    assert reused_admission.demand == first_demand.to_dict()
    assert reused_admission.job_id == first.job_id


def test_unfinished_idempotent_reuse_rejects_changed_demand(tmp_path) -> None:
    """A pinned unfinished job cannot be replayed with different demand."""
    import pytest

    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.errors import IdempotencyConflictError
    from media_generation.service import GenerationService
    from test_durable_execution import request

    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        admission_profile=profile,
    )
    first_demand = parse_workload_demand(
        workload_demand(system_ram_bytes=10 * GIB, accelerator_memory_bytes=10 * GIB)
    )
    changed_demand = parse_workload_demand(
        workload_demand(system_ram_bytes=20 * GIB, accelerator_memory_bytes=20 * GIB)
    )
    service.enqueue("unfinished-demand", request(), workload_demand=first_demand)

    with pytest.raises(IdempotencyConflictError, match="admission"):
        service.enqueue("unfinished-demand", request(), workload_demand=changed_demand)


def test_unfinished_idempotent_reuse_rejects_changed_profile(tmp_path) -> None:
    """A pinned unfinished job cannot be replayed with another capacity profile."""
    import pytest

    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.errors import IdempotencyConflictError
    from media_generation.service import GenerationService
    from test_durable_execution import request

    def profile(headroom: int):
        return build_admission_profile(
            inventory_report(),
            parse_admission_policy(
                {
                    "schema": "media-generation.admission-policy",
                    "schema_version": 1,
                    "pool_headroom_bytes": {"system_ram": headroom},
                }
            ),
        )

    database = tmp_path / "studio.sqlite3"
    first_profile = profile(8 * GIB)
    demand = parse_workload_demand(
        workload_demand(system_ram_bytes=10 * GIB, accelerator_memory_bytes=10 * GIB)
    )
    GenerationService(
        database,
        tmp_path / "images",
        admission_profile=first_profile,
    ).enqueue("unfinished-profile", request(), workload_demand=demand)
    changed_service = GenerationService(
        database,
        tmp_path / "images",
        admission_profile=profile(12 * GIB),
    )

    with pytest.raises(IdempotencyConflictError, match="admission"):
        changed_service.enqueue("unfinished-profile", request(), workload_demand=demand)


def test_legacy_reuse_without_admission_inputs_preserves_pinned_evidence(
    tmp_path,
) -> None:
    """Omitting admission inputs keeps the historical idempotent reuse path."""
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.service import GenerationService
    from test_durable_execution import request

    database = tmp_path / "studio.sqlite3"
    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    demand = parse_workload_demand(
        workload_demand(system_ram_bytes=10 * GIB, accelerator_memory_bytes=10 * GIB)
    )
    first = GenerationService(
        database,
        tmp_path / "images",
        admission_profile=profile,
    ).enqueue("legacy-reuse", request(), workload_demand=demand)
    legacy_service = GenerationService(database, tmp_path / "images")

    reused = legacy_service.enqueue("legacy-reuse", request())

    assert reused.job_id == first.job_id
    pinned = admission_record(legacy_service, first.job_id)
    assert pinned.profile_fingerprint == profile.fingerprint
    assert pinned.demand == demand.to_dict()


def test_over_budget_admission_is_denied_and_never_claimed(tmp_path) -> None:
    """A known demand larger than any fitting pool stays outside dispatch."""
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.service import GenerationService
    from test_durable_execution import request

    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        admission_profile=profile,
    )
    job = service.enqueue(
        "too-large",
        request(),
        workload_demand=parse_workload_demand(
            workload_demand(
                system_ram_bytes=53 * GIB, accelerator_memory_bytes=4 * GIB
            )
        ),
    )

    admission = admission_record(service, job.job_id)
    assert admission.decision == "denied"
    assert admission.reason == "over_budget:system_ram"
    assert service.work() == {"status": "idle", "processed": 0}
    assert service.get_provenance(job.job_id)["attempts"] == []


def test_synchronous_submit_does_not_misreport_denied_work_as_busy(tmp_path) -> None:
    """A capacity denial remains a queued, inspectable decision without an attempt."""
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.service import GenerationService
    from test_durable_execution import request

    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        admission_profile=profile,
    )
    submission = service.submit(
        "denied-submit",
        request(),
        workload_demand=parse_workload_demand(
            workload_demand(
                system_ram_bytes=53 * GIB, accelerator_memory_bytes=4 * GIB
            )
        ),
    )

    assert submission.status == "queued"
    assert admission_record(service, submission.job_id).decision == "denied"
    assert service.get_provenance(submission.job_id)["attempts"] == []


def test_canceled_blocked_admission_records_terminal_decision(tmp_path) -> None:
    """Canceling a blocked job clears it from future operator attention."""
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.service import GenerationService
    from test_durable_execution import request

    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    demand = workload_demand()
    demand["memory"] = {"status": "unknown", "reason": "not_measured"}
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        admission_profile=profile,
    )
    job = service.enqueue(
        "cancel-blocked", request(), workload_demand=parse_workload_demand(demand)
    )
    assert admission_record(service, job.job_id).decision == "blocked"
    service.cancel(job.job_id)
    canceled = admission_record(service, job.job_id)
    assert canceled.decision == "canceled"
    assert canceled.reason == "canceled before dispatch"


def test_retryable_failure_requeues_admission_then_success_releases_it(tmp_path) -> None:
    """Retry keeps evidence queued while final reconciliation releases it."""
    from media_generation.adapters import (
        PROCESS_CONTAINED_CONTRACT,
        DeterministicCpuAdapter,
    )
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.errors import RetryableGenerationError
    from media_generation.service import GenerationService
    from test_durable_execution import request

    class RetryOnce(DeterministicCpuAdapter):
        containment_contract = PROCESS_CONTAINED_CONTRACT

        def __init__(self) -> None:
            self.calls = 0

        def generate(self, plan, stream):
            self.calls += 1
            if self.calls == 1:
                raise RetryableGenerationError("transient")
            return super().generate(plan, stream)

    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        adapter=RetryOnce(),
        admission_profile=profile,
    )
    job = service.enqueue(
        "retry-admission",
        request(),
        max_attempts=2,
        workload_demand=parse_workload_demand(workload_demand()),
    )
    service.work()
    retryable = service.get_provenance(job.job_id)
    assert retryable["status"] == "queued"
    assert retryable["attempts"][0]["failure_class"] == "retryable"
    assert retryable["attempts"][0]["termination_proven"] is True
    assert retryable["execution"]["resource_state"] == "available"
    assert admission_record(service, job.job_id).decision == "queued"
    assert service.retry(job.job_id).status == "queued"
    assert admission_record(service, job.job_id).decision == "queued"
    service.work()
    assert admission_record(service, job.job_id).decision == "released"


def test_submit_reports_safe_retry_without_claiming_publication_incomplete(
    tmp_path,
) -> None:
    """A durably queued contained retry is an execution outcome, not publication."""
    import pytest

    from media_generation.adapters import (
        PROCESS_CONTAINED_CONTRACT,
        DeterministicCpuAdapter,
    )
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.errors import (
        GenerationExecutionError,
        PublicationIncompleteError,
        RetryableGenerationError,
    )
    from media_generation.service import GenerationService
    from test_durable_execution import request

    class RetryOnce(DeterministicCpuAdapter):
        containment_contract = PROCESS_CONTAINED_CONTRACT

        def __init__(self) -> None:
            self.calls = 0

        def generate(self, plan, stream):
            self.calls += 1
            if self.calls == 1:
                raise RetryableGenerationError("transient submit failure")
            return super().generate(plan, stream)

    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        adapter=RetryOnce(),
        admission_profile=profile,
    )
    demand = parse_workload_demand(workload_demand())
    job = service.enqueue(
        "submit-safe-retry",
        request(),
        max_attempts=2,
        workload_demand=demand,
    )

    with pytest.raises(GenerationExecutionError) as raised:
        service.submit("submit-safe-retry", request(), workload_demand=demand)

    assert not isinstance(raised.value, PublicationIncompleteError)
    assert raised.value.safe_message == "execution_retryable"
    cause: BaseException | None = raised.value
    while cause is not None and not isinstance(cause, RetryableGenerationError):
        cause = cause.__cause__
    assert isinstance(cause, RetryableGenerationError)
    snapshot = service.get_provenance(job.job_id)
    assert snapshot["status"] == "queued"
    assert len(snapshot["attempts"]) == 1
    assert snapshot["attempts"][0]["failure_class"] == "retryable"
    assert snapshot["attempts"][0]["termination_proven"] is True
    assert admission_record(service, job.job_id).decision == "queued"


def test_uncertain_external_failure_quarantines_admission(tmp_path) -> None:
    """Lease loss alone never releases a possibly running external device."""
    from media_generation.adapters import DeterministicCpuAdapter
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.service import GenerationService
    from test_durable_execution import request

    class ExternalFailure(DeterministicCpuAdapter):
        containment_contract = None

        def generate(self, plan, stream):
            raise RuntimeError("external response lost")

    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        adapter=ExternalFailure(),
        admission_profile=profile,
    )
    job = service.enqueue(
        "external-uncertain",
        request(),
        workload_demand=parse_workload_demand(workload_demand()),
    )
    service.work()
    admission = admission_record(service, job.job_id)
    assert admission.decision == "quarantined"
    assert service._store.resource_snapshot()["state"] == "quarantined"


def test_running_cancel_expired_lease_and_stale_owner_keep_reserved_admission(
    tmp_path,
) -> None:
    """Only a reconciled, fenced termination permits an admission to release."""
    from concurrent.futures import ThreadPoolExecutor
    import sqlite3
    import threading

    from media_generation.adapters import (
        PROCESS_CONTAINED_CONTRACT,
        DeterministicCpuAdapter,
    )
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.service import GenerationService
    from test_durable_execution import request

    entered = threading.Event()
    resume = threading.Event()

    class PausedAdapter(DeterministicCpuAdapter):
        containment_contract = PROCESS_CONTAINED_CONTRACT

        def generate(self, plan, destination):
            entered.set()
            assert resume.wait(5)
            return super().generate(plan, destination)

    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    database = tmp_path / "studio.sqlite3"
    service = GenerationService(
        database,
        tmp_path / "images",
        adapter=PausedAdapter(),
        admission_profile=profile,
    )
    job = service.enqueue(
        "running-cancel-fence",
        request(),
        workload_demand=parse_workload_demand(workload_demand()),
    )

    with ThreadPoolExecutor(max_workers=1) as pool:
        running = pool.submit(service.work)
        try:
            assert entered.wait(5)
            attempt = service._store.current_attempt(job.job_id)
            assert attempt is not None
            assert service.cancel(job.job_id)["outcome"] == "accepted"
            admitted = admission_record(service, job.job_id)
            reserved = service._store.resource_snapshot()
            assert admitted.decision == "reserved"
            assert admitted.reserved_bytes == {"system_ram": 48 * GIB}
            assert reserved["state"] == "claimed"

            expired = "2000-01-01T00:00:00+00:00"
            with sqlite3.connect(database) as connection:
                connection.execute(
                    "UPDATE execution_attempts SET lease_expires_at = ? WHERE attempt_id = ?",
                    (expired, attempt["attempt_id"]),
                )
            expired_reservation = service._store.resource_snapshot()
            assert expired_reservation["state"] == "claimed"
            assert expired_reservation["lease_expires_at"] == expired
            assert admission_record(service, job.job_id) == admitted

            assert not service._store.fail_execution(
                job.job_id,
                attempt["attempt_id"],
                "stale owner finalization",
                "2026-10-27T00:00:00+00:00",
                attempt_owner_id="worker_wrong",
                claim_epoch=attempt["claim_epoch"],
                failure_class="terminal",
                termination_proven=True,
            )
            assert service._store.resource_snapshot() == expired_reservation
            assert admission_record(service, job.job_id) == admitted
        finally:
            resume.set()
        assert running.result(timeout=10)["status"] == "complete"

    final = admission_record(service, job.job_id)
    assert final.decision == "released"
    assert final.reason == "execution_canceled"
    assert final.reserved_bytes == {"system_ram": 48 * GIB}
    assert service._store.resource_snapshot()["state"] == "available"
    assert service.get_provenance(job.job_id)["artifact"] is None


def test_unknown_or_contradictory_topology_sharing_never_dispatches(tmp_path) -> None:
    """Uncertain or conflicting pool relationships block every workload claim."""
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.service import GenerationService
    from test_durable_execution import request

    discrete_pools = [
        {
            "id": "system_ram",
            "kind": "system_ram",
            "total_bytes": 32 * GIB,
            "source": "system",
        },
        {
            "id": "gpu:0:vram",
            "kind": "dedicated_vram",
            "total_bytes": 16 * GIB,
            "source": "nvidia-smi",
        },
    ]
    cases = [
        (
            "unified-unknown-sharing",
            inventory_report(
                sharing_relationships=[
                    {
                        "accelerator_id": "gpu:0",
                        "pool": "memory",
                        "relationship": "unknown_sharing",
                    }
                ]
            ),
            {"system_ram": 8 * GIB},
            "unknown_sharing:gpu:0:memory",
        ),
        (
            "discrete-unknown-sharing",
            inventory_report(
                topology_class="discrete",
                system_total_bytes=32 * GIB,
                allocatable_pools=discrete_pools,
                sharing_relationships=[
                    {
                        "accelerator_id": "gpu:0",
                        "pool": "memory",
                        "relationship": "unknown_sharing",
                    }
                ],
            ),
            {"system_ram": 4 * GIB, "gpu:0:vram": 2 * GIB},
            "unknown_sharing:gpu:0:memory",
        ),
        (
            "discrete-shared-system-aperture",
            inventory_report(
                topology_class="discrete",
                system_total_bytes=32 * GIB,
                allocatable_pools=discrete_pools,
                sharing_relationships=[
                    {
                        "accelerator_id": "gpu:0",
                        "pool": "gtt",
                        "relationship": "shared_system_aperture",
                    }
                ],
            ),
            {"system_ram": 4 * GIB, "gpu:0:vram": 2 * GIB},
            "discrete_topology_has_shared_pool:gpu:0:gtt",
        ),
    ]

    for index, (name, report, headroom, expected_reason) in enumerate(cases):
        policy = parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": headroom,
            }
        )
        profile = build_admission_profile(report, policy)
        assert profile.status == "unknown", name
        assert expected_reason in profile.unknown_reasons, name

        service = GenerationService(
            tmp_path / f"{index}.sqlite3",
            tmp_path / f"images-{index}",
            admission_profile=profile,
        )
        job = service.enqueue(
            name,
            request(),
            workload_demand=parse_workload_demand(workload_demand()),
        )

        service.work()

        assert service.get_provenance(job.job_id)["attempts"] == [], name
        assert admission_record(service, job.job_id).decision == "blocked", name


def test_workload_demand_persisted_shape_round_trips() -> None:
    """Pinned demand evidence can be strictly reparsed without schema drift."""
    from media_generation.admission import parse_workload_demand

    original = parse_workload_demand(
        {
            **workload_demand(),
            "context": {"status": "known", "tokens": 4096},
            "offload": {"status": "known", "mode": "partial"},
            "residency": {"status": "known", "mode": "resident"},
        }
    )

    assert parse_workload_demand(original.to_dict()) == original


