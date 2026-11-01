"""Adapter contracts and the deterministic CPU-only PNG implementation."""

from __future__ import annotations

import hashlib
import json
import struct
import zlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, BinaryIO, Protocol

from .domain import GenerationPlan

if TYPE_CHECKING:
    from .supervisor import ProcessSupervisor


PROCESS_CONTAINED_CONTRACT = "process-contained/v1"
BACKEND_EXECUTION_CONTRACT_VERSION = "backend-execution/v1"


@dataclass(frozen=True, slots=True)
class AdapterCapabilities:
    """Limits the service checks before creating a job for an adapter."""

    max_width: int
    max_height: int
    supports_references: bool
    max_references: int
    supports_editing: bool = False
    max_source_images: int = 0
    dimension_multiple: int = 1
    supported_operations: frozenset[str] = frozenset({"generate"})
    min_width: int = 1
    min_height: int = 1


@dataclass(frozen=True, slots=True)
class ImageMetadata:
    """Image properties reported by an adapter after it writes an output file."""

    media_type: str
    image_format: str
    width: int
    height: int


class GenerationAdapter(Protocol):
    """Interface between engine-neutral service records and image execution."""

    adapter_id: str
    capabilities: AdapterCapabilities

    @property
    def configuration(self) -> dict[str, object]:
        """Return stable JSON settings persisted with each job.

        A real adapter includes its exact effective privacy settings here so an
        application-owned profile can verify them before admission. Credentials,
        model acquisition configuration, and the adapter's own compliance claims
        do not belong in this mapping.
        """

    def generate(self, plan: GenerationPlan, destination: BinaryIO) -> ImageMetadata:
        """Write to the publisher's open staging stream without closing it.

        Adapters must not reopen or replace its pathname. The publisher owns
        validation, flush/sync ordering, and final filesystem publication.
        """


class BackendExecutionAdapter(Protocol):
    """A declared adapter that resolves and executes one local backend process.

    The version string must be declared directly on the concrete class or on a
    concrete instance. Inheriting it through a subclass does not qualify.
    """

    backend_contract_version: str
    adapter_id: str
    capabilities: AdapterCapabilities

    def resolve_execution(self, plan: GenerationPlan) -> object:
        """Re-verify declared inputs and return one immutable execution plan."""

    def execute(
        self,
        plan: GenerationPlan,
        destination: BinaryIO,
        *,
        supervisor: ProcessSupervisor,
    ) -> ImageMetadata:
        """Run the resolved direct child through the application supervisor.

        The service constructs the supervisor with the claimed attempt
        authority and the exact argv and environment from resolution. Adapter
        code calls :meth:`ProcessSupervisor.run` exactly once and streams the
        validated output. It cannot record launch or termination facts itself.
        """


class DeterministicCpuAdapter:
    """Generate a deterministic RGB PNG using only Python's standard library.

    The adapter uses resolved request values and reference content hashes to
    derive a small abstract color field. It has no GPU, model, or network
    dependency and writes a valid PNG with embedded format metadata.
    """

    adapter_id = "deterministic-cpu-png-v1"
    containment_contract = PROCESS_CONTAINED_CONTRACT
    # Retained for source compatibility. Worker admission trusts only the
    # directly declared versioned contract above.
    process_contained = True
    capabilities = AdapterCapabilities(
        max_width=256,
        max_height=256,
        supports_references=True,
        max_references=4,
    )

    # Default runtime settings are also exposed on the class so a subclass
    # that defines __init__ without calling super().__init__ still resolves
    # them. Every exact instance receives its own copy in __init__.
    configuration: dict[str, object] = {
        "configuration_version": 1,
        "image_format": "PNG",
        "pattern_version": 1,
    }

    def __init__(self) -> None:
        """Retain the implementation version persisted with every job.

        The value is an ordinary instance attribute so an exact bundled adapter
        can be configured by the application or a test without defining a new
        class. Containment trust remains bound to the exact class identity.
        """
        self.configuration = dict(type(self).configuration)

    def generate(self, plan: GenerationPlan, destination: BinaryIO) -> ImageMetadata:
        """Write a valid RGB PNG whose bytes are stable for equivalent plan input."""
        material = json.dumps(
            {
                "prompt": plan.resolved_prompt,
                "seed": plan.seed,
                "width": plan.width,
                "height": plan.height,
                "reference_hashes": [reference.content_sha256 for reference in plan.references],
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        palette = hashlib.sha256(material).digest()
        scanlines = bytearray()
        for y in range(plan.height):
            scanlines.append(0)  # PNG filter type 0: raw RGB bytes follow.
            for x in range(plan.width):
                band = ((x // 8) * 5 + (y // 8) * 3 + plan.seed) % len(palette)
                scanlines.extend(
                    (
                        (palette[band] + x * 3 + y) & 0xFF,
                        (palette[(band + 9) % len(palette)] + y * 4 + plan.seed) & 0xFF,
                        (palette[(band + 19) % len(palette)] + x + y * 2) & 0xFF,
                    )
                )

        png = bytearray(b"\x89PNG\r\n\x1a\n")
        png.extend(
            _png_chunk(
                b"IHDR",
                struct.pack(">IIBBBBB", plan.width, plan.height, 8, 2, 0, 0, 0),
            )
        )
        png.extend(_png_chunk(b"tEXt", b"Software\x00media-generation deterministic CPU adapter"))
        png.extend(_png_chunk(b"tEXt", f"GenerationSeed\x00{plan.seed}".encode("ascii")))
        png.extend(_png_chunk(b"IDAT", zlib.compress(bytes(scanlines), level=9)))
        png.extend(_png_chunk(b"IEND", b""))
        destination.seek(0)
        destination.write(png)
        destination.truncate()
        destination.flush()
        return ImageMetadata("image/png", "PNG", plan.width, plan.height)


def trusted_containment_contract(adapter: GenerationAdapter) -> str | None:
    """Return the bundled static containment contract, if one is trusted.

    Trust is bound to the exact bundled :class:`DeterministicCpuAdapter` class,
    matching the exact-type stance used by the lightweight CPU admission check.
    A subclass that reuses the adapter identity, configuration, or
    ``process_contained`` boolean cannot opt in by declaring the version string.
    """
    if type(adapter) is not DeterministicCpuAdapter:
        return None
    instance_values = getattr(adapter, "__dict__", {})
    if "containment_contract" in instance_values:
        declared = instance_values["containment_contract"]
    else:
        declared = type(adapter).__dict__.get("containment_contract")
    return PROCESS_CONTAINED_CONTRACT if declared == PROCESS_CONTAINED_CONTRACT else None


def backend_execution_contract(adapter: object) -> str | None:
    """Return a directly declared backend execution contract version.

    Inheritance is deliberately excluded. A subclass that inherits the
    execution methods from another adapter does not become a trusted backend
    execution adapter unless it declares the version string on its own
    concrete class or instance.
    """
    instance_values = getattr(adapter, "__dict__", {})
    if "backend_contract_version" in instance_values:
        declared = instance_values["backend_contract_version"]
    else:
        declared = type(adapter).__dict__.get("backend_contract_version")
    if declared == BACKEND_EXECUTION_CONTRACT_VERSION:
        return BACKEND_EXECUTION_CONTRACT_VERSION
    return None


def _png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    """Encode a PNG chunk with its length and CRC required by the file format."""
    checksum = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + chunk_type + payload + struct.pack(">I", checksum)
