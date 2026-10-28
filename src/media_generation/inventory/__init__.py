"""Read-only host, runtime, and model inventory collection.

The package exposes one programmatic entry point, :func:`collect_inventory`,
used by the ``media-generation inventory`` command and by focused tests.  All
probes are local and read-only; collection never installs software, loads model
weights for inference, or performs network requests.
"""

from __future__ import annotations

from .report import InventoryOptions, InventoryResult, collect_inventory, write_inventory
from .contract import ValidatedInventoryReport, validate_inventory_report
from .schema import (
    FINGERPRINT_ALGORITHM,
    MANIFEST_SCHEMA_NAME,
    MANIFEST_SCHEMA_VERSION,
    REPLAY_SCHEMA_NAME,
    REPLAY_SCHEMA_VERSION,
    SCHEMA_NAME,
    SCHEMA_VERSION,
    InventoryError,
    InventoryOutputError,
    InventoryValidationError,
)

__all__ = [
    "FINGERPRINT_ALGORITHM",
    "InventoryError",
    "InventoryOptions",
    "InventoryOutputError",
    "InventoryResult",
    "InventoryValidationError",
    "ValidatedInventoryReport",
    "MANIFEST_SCHEMA_NAME",
    "MANIFEST_SCHEMA_VERSION",
    "REPLAY_SCHEMA_NAME",
    "REPLAY_SCHEMA_VERSION",
    "SCHEMA_NAME",
    "SCHEMA_VERSION",
    "collect_inventory",
    "validate_inventory_report",
    "write_inventory",
]
