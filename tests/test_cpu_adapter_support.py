"""Imported test support for exact-type CPU adapter fixtures.

This module is imported by service-level tests. It intentionally contains no
pytest-collectable tests; the test_* filename keeps the helper within the run's
authorized test scope. Containment trust is deliberately limited to the exact
bundled DeterministicCpuAdapter class. Tests that need another renderer or
configuration use that exact class and replace behavior on an instance instead
of defining a subclass, which would no longer be trusted.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import BinaryIO

from media_generation.adapters import (
    AdapterCapabilities,
    DeterministicCpuAdapter,
    ImageMetadata,
)
from media_generation.domain import GenerationPlan

_UNSET = object()


class HeavyweightTestAdapter:
    """Adapter stand-in that admission deliberately treats as heavyweight.

    It renders through a bundled deterministic CPU adapter, but it is not that
    exact class. Exact-type admission checks therefore require capacity
    evidence, which is the behavior heavyweight admission tests exercise.
    """

    adapter_id = "heavyweight-test-adapter"
    containment_contract = None
    capabilities = AdapterCapabilities(
        max_width=256,
        max_height=256,
        supports_references=True,
        max_references=4,
    )

    def __init__(self, configuration: dict[str, object] | None = None) -> None:
        delegate = DeterministicCpuAdapter()
        self._delegate = delegate
        self.configuration = (
            configuration
            if configuration is not None
            else dict(delegate.configuration)
        )

    def generate(self, plan: GenerationPlan, destination: BinaryIO) -> ImageMetadata:
        return DeterministicCpuAdapter.generate(self._delegate, plan, destination)


def heavyweight_adapter(
    *,
    configuration: dict[str, object] | None = None,
) -> HeavyweightTestAdapter:
    """Return the shared heavyweight admission stand-in."""
    return HeavyweightTestAdapter(configuration=configuration)


def cpu_adapter(
    *,
    generate: Callable[[GenerationPlan, BinaryIO], object] | None = None,
    adapter_id: str | None = None,
    configuration: dict[str, object] | None = None,
    capabilities: AdapterCapabilities | None = None,
    containment_contract: object = _UNSET,
) -> DeterministicCpuAdapter:
    """Return the exact bundled adapter with optional per-instance behavior."""
    adapter = DeterministicCpuAdapter()
    if generate is not None:
        adapter.generate = generate  # type: ignore[method-assign]
    if adapter_id is not None:
        adapter.adapter_id = adapter_id
    if configuration is not None:
        adapter.configuration = dict(configuration)
    if capabilities is not None:
        adapter.capabilities = capabilities
    if containment_contract is not _UNSET:
        adapter.containment_contract = containment_contract  # type: ignore[attr-defined]
    return adapter
