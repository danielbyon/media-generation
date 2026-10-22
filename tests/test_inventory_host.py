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
    accelerators, findings, degraded = host._collect_accelerators(
        ledger, system="Linux"
    )

    assert degraded is False
    assert findings == []
    assert len(accelerators) == 1
    accelerator = accelerators[0]
    assert accelerator["id"] == "drm:card1"
    assert accelerator["driver"] == "amdgpu"
    assert accelerator["pools"][0]["kind"] == "unknown_vram"  # type: ignore[index]


def test_local_sysfs_untrusted_device_link_is_degraded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A device link outside /sys/devices is rejected without an absence claim."""
    class_dir, devices = _sysfs_tree(tmp_path, trusted=False)
    monkeypatch.setattr(host, "DRM_ROOT", class_dir)
    monkeypatch.setattr(host, "SYS_DEVICES_ROOT", devices)

    ledger = ProbeLedger(LocalObservationSource())
    accelerators, findings, degraded = host._collect_accelerators(
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
