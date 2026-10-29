"""Current-schema artifact lineage and path-authority contracts."""

from __future__ import annotations

from pathlib import Path
import shutil

from media_generation.domain import ArtifactSource, GenerationRequest
from media_generation.service import GenerationService
from test_durable_execution import request


def test_artifact_path_survives_a_different_service_output_root(tmp_path: Path) -> None:
    """Persisted artifact identity never infers a new path from the opener."""
    database = tmp_path / "studio.sqlite3"
    first_root = tmp_path / "first-images"
    first = GenerationService(database, first_root)
    submission = first.submit("stored-path", request())

    reopened = GenerationService(database, tmp_path / "different-images")
    artifact = reopened.get_artifact(submission.artifact_id)

    assert Path(artifact.path).parent == first_root.resolve()
    assert reopened.get_integrity(submission.artifact_id)["status"] == "ok"


def test_generated_reference_lineage_survives_restart(tmp_path: Path) -> None:
    """Ordered current-schema lineage remains immutable across reopen."""
    database = tmp_path / "studio.sqlite3"
    service = GenerationService(database, tmp_path / "images")
    parent = service.submit("lineage-parent", request("parent"))
    child = service.submit(
        "lineage-child",
        GenerationRequest(
            "child",
            seed=11,
            width=8,
            height=9,
            reference_ids=(parent.artifact_id,),
        ),
    )

    lineage = GenerationService(database, tmp_path / "images").get_lineage(
        child.artifact_id
    )

    assert [parent_row["source_id"] for parent_row in lineage["parents"]] == [
        parent.artifact_id
    ]
    assert lineage["parents"][0]["role"] == "reference"
    assert lineage["parents"][0]["position"] == 0


def test_import_across_roots_keeps_content_identity_and_source_lineage(
    tmp_path: Path,
) -> None:
    """Operator-approved imports use current rows without migration backfill."""
    database = tmp_path / "studio.sqlite3"
    service = GenerationService(database, tmp_path / "images")
    parent_submission = service.submit("import-parent", request("import parent"))
    parent = service.get_artifact(parent_submission.artifact_id)
    approved_root = tmp_path / "approved"
    approved_root.mkdir()
    copied = approved_root / Path(parent.path).name
    shutil.copy2(parent.path, copied)

    imported = service.import_image(
        approved_root,
        copied.name,
        sources=(ArtifactSource(parent.artifact_id, "source"),),
    )

    assert imported.artifact_id != parent.artifact_id
    assert imported.sha256 == parent.sha256
    lineage = service.get_lineage(imported.artifact_id)
    assert [
        (row["source_id"], row["role"], row["position"])
        for row in lineage["parents"]
    ] == [(parent.artifact_id, "source", 0)]
    assert service.get_integrity(imported.artifact_id)["status"] == "ok"
