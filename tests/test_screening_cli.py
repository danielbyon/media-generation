from pathlib import Path

import pytest

import media_generation.cli as cli
from media_generation.adapters import DeterministicCpuAdapter
from media_generation.cli import build_parser
from media_generation.screening import ScreeningRunner


def test_screen_run_requires_an_external_data_directory_and_pinned_candidate() -> None:
    parser = build_parser()

    with pytest.raises(SystemExit) as missing_candidate:
        parser.parse_args(
            [
                "screen",
                "run",
                "--manifest",
                "/private/manifest.json",
                "--data-dir",
                "/private/screening-data",
            ]
        )
    assert missing_candidate.value.code == 2

    options = parser.parse_args(
        [
            "screen",
            "run",
            "--manifest",
            "/private/manifest.json",
            "--data-dir",
            "/private/screening-data",
            "--engine-candidate",
            "/private/candidate.json",
            "--engine-trusted-evidence",
            "/private/trusted-evidence.json",
        ]
    )
    assert options.screen_command == "run"
    assert options.data_dir == Path("/private/screening-data")
    assert options.engine_candidate == Path("/private/candidate.json")


def test_screen_resume_and_report_have_explicit_subcommands() -> None:
    parser = build_parser()
    resume = parser.parse_args(
        ["screen", "resume", "--run-id", "run_" + "0" * 32, "--data-dir", "/private/data"]
    )
    report = parser.parse_args(
        [
            "screen",
            "report",
            "--run-id",
            "run_" + "0" * 32,
            "--data-dir",
            "/private/data",
            "--format",
            "summary",
        ]
    )
    assert resume.screen_command == "resume"
    assert report.screen_command == "report"
    assert report.format == "summary"


def test_screen_run_emits_run_id_before_execution_can_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    run_id = "run_" + "1" * 32
    monkeypatch.setattr(
        cli.ScreeningManifest, "from_json", staticmethod(lambda _path: object())
    )
    monkeypatch.setattr(
        cli, "_engine_adapter", lambda *_args, **_kwargs: DeterministicCpuAdapter()
    )
    monkeypatch.setattr(ScreeningRunner, "create_run", lambda _self, _manifest: run_id)

    def terminate_after_run_creation(_self, _run_id, **_kwargs):
        raise SystemExit("simulated interruption")

    monkeypatch.setattr(ScreeningRunner, "resume", terminate_after_run_creation)
    with pytest.raises(SystemExit, match="simulated interruption"):
        cli.main(
            [
                "screen",
                "run",
                "--manifest",
                str(tmp_path / "manifest.json"),
                "--data-dir",
                str(tmp_path / "screening-data"),
                "--engine-candidate",
                str(tmp_path / "candidate.json"),
            ]
        )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"screening_run_id={run_id}" in captured.err
