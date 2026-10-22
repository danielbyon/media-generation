"""Adapter contracts and the deterministic CPU-only PNG implementation."""

from __future__ import annotations

import hashlib
import json
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .domain import GenerationPlan


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
        """Return the stable, JSON-compatible configuration to persist per job."""

    def generate(self, plan: GenerationPlan, destination: Path) -> ImageMetadata:
        """Write one image file for a previously persisted plan."""


class DeterministicCpuAdapter:
    """Generate a deterministic RGB PNG using only Python's standard library.

    The adapter uses resolved request values and reference content hashes to
    derive a small abstract color field. It has no GPU, model, or network
    dependency and writes a valid PNG with embedded format metadata.
    """

    adapter_id = "deterministic-cpu-png-v1"
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

    def generate(self, plan: GenerationPlan, destination: Path) -> ImageMetadata:
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
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(png)
        return ImageMetadata("image/png", "PNG", plan.width, plan.height)


def _png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    """Encode a PNG chunk with its length and CRC required by the file format."""
    checksum = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + chunk_type + payload + struct.pack(">I", checksum)
