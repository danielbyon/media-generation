"""Memory topology tests for unified, discrete, and incomplete observations."""

from __future__ import annotations

from media_generation.inventory.host import _classify_vram, resolve_memory_topology


GIB = 1024**3


def _pool(
    name: str, kind: str, total: int | None, *, source: str = "synthetic"
) -> dict[str, object]:
    return {
        "name": name,
        "kind": kind,
        "total_bytes": total,
        "free_bytes": None,
        "additive": kind == "dedicated_vram",
        "source": source,
    }


def _accelerator(
    identifier: str,
    vendor: str,
    pci_class: str,
    pools: list[dict[str, object]],
    *,
    source: str = "sysfs",
) -> dict[str, object]:
    return {
        "id": identifier,
        "vendor_id": vendor,
        "pci_class": pci_class,
        "source": source,
        "pools": pools,
    }


def test_unified_apu_pools_are_reported_but_not_added() -> None:
    """A carve-out plus shared GTT must not be added to system RAM."""
    topology, findings = resolve_memory_topology(
        system_total_bytes=64 * GIB,
        accelerators=[
            _accelerator(
                "drm:card1",
                "0x1234",
                "0x038000",
                [
                    _pool("vram", "shared_carveout", 512 * 1024**2),
                    _pool("vis_vram", "visible_vram_alias", 512 * 1024**2),
                    _pool("gtt", "shared_gtt", 32 * GIB),
                ],
            )
        ],
    )

    assert topology["class"] == "unified_shared"
    assert topology["reported_total_bytes"] == 64 * GIB
    assert topology["reported_total_is_allocatable_pool"] is False
    assert topology["system_total_bytes"] == 64 * GIB
    assert topology["confidence"] == "medium"
    assert topology["warnings"] == []
    assert [pool["id"] for pool in topology["allocatable_pools"]] == ["system_ram"]
    relationships = {item["relationship"] for item in topology["sharing_relationships"]}
    assert "carveout_within_system_ram" in relationships
    assert "shared_system_aperture" in relationships
    assert "duplicate_alias_not_additive" in relationships
    assert findings == []


def test_discrete_pools_are_listed_separately() -> None:
    """Independent VRAM is additive for reporting but remains a separate pool."""
    topology, findings = resolve_memory_topology(
        system_total_bytes=32 * GIB,
        accelerators=[
            _accelerator(
                "drm:card1",
                "0x10de",
                "0x030000",
                [
                    _pool("vram", "dedicated_vram", 24 * GIB, source="nvidia-smi"),
                    _pool("gtt", "shared_gtt", 16 * GIB),
                ],
                source="nvidia-smi",
            )
        ],
    )

    assert topology["class"] == "discrete"
    assert topology["reported_total_bytes"] == 56 * GIB
    assert topology["reported_total_is_allocatable_pool"] is False
    assert topology["confidence"] == "high"
    assert [pool["id"] for pool in topology["allocatable_pools"]] == [
        "system_ram",
        "drm:card1:vram",
    ]
    assert "allocatable_total_bytes" not in topology
    assert findings == []


def test_dedicated_vram_larger_than_system_is_valid() -> None:
    """A discrete GPU can legitimately have more VRAM than system RAM."""
    topology, findings = resolve_memory_topology(
        system_total_bytes=16 * GIB,
        accelerators=[
            _accelerator(
                "nvidia:0",
                "0x10de",
                "0x030000",
                [_pool("vram", "dedicated_vram", 48 * GIB, source="nvidia-smi")],
                source="nvidia-smi",
            )
        ],
    )

    assert topology["class"] == "discrete"
    assert topology["reported_total_bytes"] == 64 * GIB
    assert topology["warnings"] == []
    assert findings == []


def test_shared_pool_larger_than_system_is_a_conflict() -> None:
    """A shared pool larger than system RAM cannot be added or trusted."""
    topology, findings = resolve_memory_topology(
        system_total_bytes=16 * GIB,
        accelerators=[
            _accelerator(
                "drm:card1",
                "0x1234",
                "0x038000",
                [_pool("vram", "shared_carveout", 64 * GIB)],
            )
        ],
    )

    assert topology["class"] == "ambiguous"
    assert topology["reported_total_bytes"] is None
    assert topology["confidence"] == "low"
    assert "shared_pool_exceeds_system_memory" in topology["warnings"]
    assert any(finding.code == "shared_pool_exceeds_system_memory" for finding in findings)


def test_dedicated_and_shared_evidence_is_ambiguous() -> None:
    """Mixed dedicated and shared evidence is not promoted to a total."""
    topology, _ = resolve_memory_topology(
        system_total_bytes=32 * GIB,
        accelerators=[
            _accelerator(
                "drm:card1",
                "0x1234",
                "0x038000",
                [_pool("vram", "shared_carveout", 2 * GIB)],
            ),
            _accelerator(
                "drm:card2",
                "0x10de",
                "0x030000",
                [_pool("vram", "dedicated_vram", 8 * GIB)],
            ),
        ],
    )

    assert topology["class"] == "ambiguous"
    assert topology["reported_total_bytes"] is None


def test_dedicated_and_unknown_memory_evidence_is_ambiguous() -> None:
    """A dedicated GPU plus unknown GPU evidence is not promoted to discrete."""
    topology, _ = resolve_memory_topology(
        system_total_bytes=32 * GIB,
        accelerators=[
            _accelerator(
                "drm:card1",
                "0x10de",
                "0x030000",
                [_pool("vram", "dedicated_vram", 8 * GIB, source="nvidia-smi")],
            ),
            _accelerator(
                "drm:card2",
                "0x1002",
                "0x030000",
                [_pool("vram", "unknown_vram", 512 * 1024**2)],
            ),
        ],
    )

    assert topology["class"] == "ambiguous"
    assert topology["reported_total_bytes"] is None
    assert topology["confidence"] == "low"


def test_no_accelerators_reports_system_only_and_unknown_topology() -> None:
    """Absence of GPU pools does not invent an acceleration topology."""
    topology, findings = resolve_memory_topology(
        system_total_bytes=48 * GIB,
        accelerators=[],
    )

    assert topology["class"] == "unknown"
    assert topology["reported_total_bytes"] == 48 * GIB
    assert topology["warnings"] == []
    assert findings == []


def test_missing_system_memory_remains_unknown() -> None:
    """Without system memory or a classified GPU pool no total is emitted."""
    topology, _ = resolve_memory_topology(
        system_total_bytes=None,
        accelerators=[
            _accelerator(
                "drm:card1",
                "0x1234",
                "0x038000",
                [_pool("vram", "shared_carveout", 512 * 1024**2)],
            )
        ],
    )

    assert topology["class"] == "unknown"
    assert topology["reported_total_bytes"] is None


def test_amd_integrated_vga_class_does_not_imply_shared_or_dedicated() -> None:
    """PCI display class alone leaves an APU memory relationship unknown."""
    accelerator = _accelerator(
        "drm:card1",
        "0x1002",
        "0x030000",
        [
            _pool("vram", "unknown_vram", 512 * 1024**2),
            _pool("vis_vram", "visible_vram_alias", 512 * 1024**2),
            _pool("gtt", "shared_gtt", 32 * GIB),
        ],
    )

    assert _classify_vram(accelerator) == "unknown_vram"

    topology, _ = resolve_memory_topology(
        system_total_bytes=64 * GIB,
        accelerators=[accelerator],
    )

    assert topology["class"] == "unknown"
    assert topology["reported_total_bytes"] == 64 * GIB
    assert [pool["id"] for pool in topology["allocatable_pools"]] == ["system_ram"]
    relationships = {
        item["relationship"] for item in topology["sharing_relationships"]
    }
    assert "unknown_sharing" in relationships
    assert "carveout_within_system_ram" not in relationships


def test_discrete_tool_evidence_marks_vram_dedicated_and_additive() -> None:
    """An explicit device-query total is treated as discrete device memory."""
    accelerator = _accelerator(
        "nvidia:00000000:01:00.0",
        "0x10de",
        "0x030000",
        [_pool("vram", "dedicated_vram", 8 * GIB, source="nvidia-smi")],
        source="nvidia-smi",
    )

    assert _classify_vram(accelerator) == "dedicated_vram"

    topology, _ = resolve_memory_topology(
        system_total_bytes=32 * GIB,
        accelerators=[accelerator],
    )

    assert topology["class"] == "discrete"
    assert topology["reported_total_bytes"] == 40 * GIB
    assert [pool["id"] for pool in topology["allocatable_pools"]] == [
        "system_ram",
        "nvidia:00000000:01:00.0:vram",
    ]


def test_conflicting_pools_on_one_accelerator_are_ambiguous() -> None:
    """A device cannot be promoted to a single memory class when evidence conflicts."""
    topology, _ = resolve_memory_topology(
        system_total_bytes=32 * GIB,
        accelerators=[
            _accelerator(
                "drm:card1",
                "0x10de",
                "0x030000",
                [
                    _pool("vram", "dedicated_vram", 8 * GIB, source="nvidia-smi"),
                    _pool("vram", "shared_carveout", 4 * GIB),
                ],
                source="nvidia-smi",
            )
        ],
    )

    assert topology["class"] == "ambiguous"
    assert topology["reported_total_bytes"] is None
    assert topology["confidence"] == "low"


def test_incomplete_gpu_memory_evidence_stays_unknown() -> None:
    """A card without memory totals produces unknown topology, not a total."""
    topology, findings = resolve_memory_topology(
        system_total_bytes=48 * GIB,
        accelerators=[
            _accelerator("drm:card1", "0x1002", "0x030000", []),
        ],
    )

    assert topology["class"] == "unknown"
    assert topology["reported_total_bytes"] == 48 * GIB
    assert "no_gpu_memory_pools_observed" in topology["warnings"]
    assert any(
        finding.code == "no_gpu_memory_pools_observed" for finding in findings
    )
