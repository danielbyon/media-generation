"""Adapter contracts and the deterministic CPU-only PNG implementation."""

from __future__ import annotations

import hashlib
import json
import struct
import zlib
from dataclasses import dataclass
from typing import BinaryIO, Protocol

from .domain import GenerationPlan


PROCESS_CONTAINED_CONTRACT = "process-contained/v1"


@dataclass(frozen=True, slots=True)
class AdapterCapabilities:
    """Limits the service checks before creating a job for an adapter."""

    max_width: int
    max_height: int
    supports_references: bool
    max_references: int


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

    @property
    def configuration(self) -> dict[str, object]:
        """Describe the implementation version retained in job provenance."""
        return {"configuration_version": 1, "image_format": "PNG", "pattern_version": 1}

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
    """Return a directly declared containment contract, if one is trusted.

    Inheritance is deliberately excluded. A subclass that reuses the
    deterministic adapter's identity, configuration, or ``process_contained``
    boolean does not become process contained unless its concrete class or an
    instance explicitly declares the versioned contract.
    """
    instance_values = getattr(adapter, "__dict__", {})
    if "containment_contract" in instance_values:
        declared = instance_values["containment_contract"]
    else:
        declared = type(adapter).__dict__.get("containment_contract")
    return PROCESS_CONTAINED_CONTRACT if declared == PROCESS_CONTAINED_CONTRACT else None


def _png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    """Encode a PNG chunk with its length and CRC required by the file format."""
    checksum = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + chunk_type + payload + struct.pack(">I", checksum)
