"""Linux DRM sysfs enumeration tests with real symlinked fixtures."""
from __future__ import annotations

from pathlib import Path

import pytest

from media_generation.inventory import host
from media_generation.inventory.probes import LocalObservationSource, ProbeLedger


def _sysfs_tree(tmp_path: Path, *, trusted: bool = True) -> tuple[Path, Path]:
    class_dir = tmp_path / "sys" / "class" / "drm"
    class_dir.mkdir(parents=True)
    devices = tmp_path / "sys" / "devices"
    device_dir = (
        devices / "pci0000:00" / "0000:00:01.0" / "0000:01:00.0"
        if trusted
        else tmp_path / "outside" / "device"
    )
    card_dir = device_dir / "drm" / "card1"
    card_dir.mkdir(parents=True)
    (device_dir / "vendor").write_text("0x1002\n", encoding="utf-8")
    (device_dir / "device").write_text("0x164e\n", encoding="utf-8")
    (device_dir / "class").write_text("0x030000\n", encoding="utf-8")
    (device_dir / "uevent").write_text(
        "DRIVER=amdgpu\nPCI_CLASS=30000\nPCI_SLOT_NAME=0000:01:00.0\n",
        encoding="utf-8",
    )
    (device_dir / "mem_info_vram_total").write_text("536870912\n", encoding="utf-8")
    (device_dir / "mem_info_gtt_total").write_text("34359738368\n", encoding="utf-8")
    driver = devices / "bus" / "pci" / "drivers" / "amdgpu"
    driver.mkdir(parents=True)
    (device_dir / "driver").symlink_to(driver, target_is_directory=True)
    (card_dir / "device").symlink_to(device_dir, target_is_directory=True)
    (class_dir / "card1").symlink_to(card_dir, target_is_directory=True)
    return class_dir, devices


def test_local_sysfs_symlinked_card_and_device_are_inspected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Common Linux layouts link both the card and its device directory."""
    class_dir, devices = _sysfs_tree(tmp_path)
    monkeypatch.setattr(host, "DRM_ROOT", class_dir)
    monkeypatch.setattr(host, "SYS_DEVICES_ROOT", devices)

    ledger = ProbeLedger(LocalObservationSource())
    accelerators, findings, degraded, enumeration = host._collect_accelerators(
        ledger, system="Linux"
    )

    assert degraded is False
    assert findings == []
    assert len(accelerators) == 1
    accelerator = accelerators[0]
    assert accelerator["id"] == "drm:card1"
    assert accelerator["driver"] == "amdgpu"
    assert accelerator["pools"][0]["kind"] == "unknown_vram"  # type: ignore[index]
    assert enumeration == {
        "status": "observed",
        "candidate_count": 1,
        "inspected_count": 1,
        "inspection_failures": 0,
        "listing_truncated": False,
        "card_limit_reached": False,
    }


def test_non_display_card_is_inspected_but_not_reported_as_accelerator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A successfully inspected non-VGA card still counts toward coverage."""
    class_dir, devices = _sysfs_tree(tmp_path)
    device_dir = devices / "pci0000:00" / "0000:00:01.0" / "0000:01:00.0"
    (device_dir / "class").write_text("0x020000\n", encoding="utf-8")
    monkeypatch.setattr(host, "DRM_ROOT", class_dir)
    monkeypatch.setattr(host, "SYS_DEVICES_ROOT", devices)

    accelerators, findings, degraded, enumeration = host._collect_accelerators(
        ProbeLedger(LocalObservationSource()), system="Linux"
    )

    assert accelerators == []
    assert findings == []
    assert degraded is False
    assert enumeration == {
        "status": "observed",
        "candidate_count": 1,
        "inspected_count": 1,
        "inspection_failures": 0,
        "listing_truncated": False,
        "card_limit_reached": False,
    }


def test_local_sysfs_untrusted_device_link_is_degraded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A device link outside /sys/devices is rejected without an absence claim."""
    class_dir, devices = _sysfs_tree(tmp_path, trusted=False)
    monkeypatch.setattr(host, "DRM_ROOT", class_dir)
    monkeypatch.setattr(host, "SYS_DEVICES_ROOT", devices)

    ledger = ProbeLedger(LocalObservationSource())
    accelerators, findings, degraded, enumeration = host._collect_accelerators(
        ledger, system="Linux"
    )

    assert accelerators == []
    assert degraded is True
    assert any(finding.code == "gpu_card_unavailable" for finding in findings)
    result = next(
        record for record in ledger.records if record.probe_id == "gpu:enumeration-result"
    )
    assert result.status == "unavailable"
    assert result.reason == "accelerator_metadata_unavailable"
    assert enumeration["candidate_count"] == 1
    assert enumeration["inspected_count"] == 0
    assert enumeration["inspection_failures"] == 1


def test_device_replacement_after_validation_is_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A device directory swapped for a link cannot redirect attribute reads."""
    class_dir, devices = _sysfs_tree(tmp_path)
    monkeypatch.setattr(host, "DRM_ROOT", class_dir)
    monkeypatch.setattr(host, "SYS_DEVICES_ROOT", devices)
    device_dir = devices / "pci0000:00" / "0000:00:01.0" / "0000:01:00.0"
    outside = tmp_path / "outside-device"
    outside.mkdir()
    (outside / "vendor").write_text("0xdead\n", encoding="utf-8")
    (outside / "class").write_text("0x030000\n", encoding="utf-8")
    (outside / "uevent").write_text("PCI_CLASS=30000\n", encoding="utf-8")
    source = LocalObservationSource()
    real_read = source.read_text
    swapped = {"done": False}

    def swapping_read(path: Path, **kwargs: object):
        if path.name == "vendor" and not swapped["done"]:
            swapped["done"] = True
            device_dir.rename(device_dir.with_name("0000:01:00.0.old"))
            device_dir.symlink_to(outside, target_is_directory=True)
        return real_read(path, **kwargs)  # type: ignore[arg-type]

    source.read_text = swapping_read  # type: ignore[method-assign]

    accelerators, _, _, _ = host._collect_accelerators(
        ProbeLedger(source), system="Linux"
    )

    assert len(accelerators) == 1
    assert accelerators[0]["vendor_id"] is None
    assert accelerators[0]["pools"] == []


def test_accelerator_limit_marks_enumeration_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Inspecting fewer cards than discovered is incomplete, not successful."""
    class_dir = tmp_path / "sys" / "class" / "drm"
    class_dir.mkdir(parents=True)
    devices = tmp_path / "sys" / "devices"
    for index in range(1, host.MAX_ACCELERATORS + 2):
        device_dir = devices / "pci0000:00" / f"0000:{index:02d}:00.0"
        device_dir.mkdir(parents=True)
        (device_dir / "vendor").write_text("0x1002\n", encoding="utf-8")
        (device_dir / "class").write_text("0x030000\n", encoding="utf-8")
        card = class_dir / f"card{index}"
        card.mkdir()
        (card / "device").symlink_to(device_dir, target_is_directory=True)
    monkeypatch.setattr(host, "DRM_ROOT", class_dir)
    monkeypatch.setattr(host, "SYS_DEVICES_ROOT", devices)

    accelerators, _, degraded, enumeration = host._collect_accelerators(
        ProbeLedger(LocalObservationSource()), system="Linux"
    )

    assert len(accelerators) == host.MAX_ACCELERATORS
    assert degraded is True
    assert enumeration["status"] == "partial"
    assert enumeration["card_limit_reached"] is True
    assert enumeration["candidate_count"] == host.MAX_ACCELERATORS + 1
    assert enumeration["inspected_count"] == host.MAX_ACCELERATORS
    assert enumeration["inspection_failures"] == 0


def test_truncated_drm_listing_reports_discovered_candidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bounded directory scan advertises both truncation and the card cap."""
    class_dir = tmp_path / "sys" / "class" / "drm"
    class_dir.mkdir(parents=True)
    devices = tmp_path / "sys" / "devices"
    for index in range(1, host.MAX_DRM_FILES + 2):
        device_dir = devices / "pci0000:00" / f"0000:{index:02d}:00.0"
        device_dir.mkdir(parents=True)
        (device_dir / "vendor").write_text("0x1002\n", encoding="utf-8")
        (device_dir / "class").write_text("0x030000\n", encoding="utf-8")
        card = class_dir / f"card{index}"
        card.mkdir()
        (card / "device").symlink_to(device_dir, target_is_directory=True)
    monkeypatch.setattr(host, "DRM_ROOT", class_dir)
    monkeypatch.setattr(host, "SYS_DEVICES_ROOT", devices)

    accelerators, _, degraded, enumeration = host._collect_accelerators(
        ProbeLedger(LocalObservationSource()), system="Linux"
    )

    assert len(accelerators) == host.MAX_ACCELERATORS
    assert degraded is True
    assert enumeration["status"] == "partial"
    assert enumeration["candidate_count"] == host.MAX_DRM_FILES
    assert enumeration["inspected_count"] == host.MAX_ACCELERATORS
    assert enumeration["inspection_failures"] == 0
    assert enumeration["listing_truncated"] is True
    assert enumeration["card_limit_reached"] is True


def test_unreadable_drm_listing_is_not_reported_as_no_gpus(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unreadable DRM directory yields unavailable enumeration, not absence."""
    monkeypatch.setattr(host, "DRM_ROOT", tmp_path / "missing-drm")
    monkeypatch.setattr(host, "SYS_DEVICES_ROOT", tmp_path / "devices")

    accelerators, _, degraded, enumeration = host._collect_accelerators(
        ProbeLedger(LocalObservationSource()), system="Linux"
    )

    assert accelerators == []
    assert degraded is True
    assert enumeration["status"] == "unavailable"
    assert enumeration["reason"] == "file_not_found"
