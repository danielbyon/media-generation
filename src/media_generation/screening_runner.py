"""Coordinate durable screening runs, case claims, and heartbeat fencing."""
from __future__ import annotations

import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, Mapping

from .screening_store import (
    CaseClaim,
    ScreeningClaimLostError,
    ScreeningLedger,
    ScreeningStoreError,
)
from .screening_execution import ScreeningCaseExecutor
from .screening_manifest import (
    ScreeningConfigurationError,
    ScreeningManifest,
    _canonical_json,
    _fingerprint,
    _sha256,
    _validate_variant_against_candidate,
    build_case_definitions,
)
from .screening_report import ScreeningReportBuilder
from .service import GenerationService

class ScreeningRunner:
    """Create immutable runs, resume cases safely, and produce evidence reports."""

    def __init__(
        self,
        *,
        data_directory: Path,
        service_database: Path,
        output_directory: Path,
        execution_identity: Mapping[str, object] | None,
        service_factory: Callable[[], GenerationService] | None,
        workload_demand: object | None = None,
        clock: Callable[[], float] = time.time,
        lease_seconds: float = 60.0,
        heartbeat_interval: float | None = 10.0,
    ) -> None:
        if lease_seconds <= 0:
            raise ValueError("screening case lease must be positive")
        if heartbeat_interval is not None and not 0 < heartbeat_interval < lease_seconds:
            raise ValueError("screening heartbeat must be positive and shorter than its lease")
        self.data_directory = _external_path(data_directory, "screening data directory")
        self.service_database = _external_path(service_database, "GenerationService database")
        self.output_directory = _external_path(output_directory, "artifact output directory")
        self.data_directory.mkdir(parents=True, exist_ok=True)
        self.execution_identity = (
            None if execution_identity is None else _normalize_execution_identity(
                execution_identity, self.service_database, self.output_directory
            )
        )
        self.service_factory = service_factory
        self.workload_demand = workload_demand
        self.clock = clock
        self.lease_seconds = float(lease_seconds)
        self.heartbeat_interval = heartbeat_interval
        self.ledger = ScreeningLedger(self.data_directory / "screening.sqlite3")
        self._case_executor = ScreeningCaseExecutor(
            ledger=self.ledger,
            service_database=self.service_database,
            output_directory=self.output_directory,
            execution_identity=self.execution_identity,
            service_factory=self.service_factory,
            workload_demand=self.workload_demand,
            clock=self.clock,
        )
        self._runner_id = f"runner_{uuid.uuid4().hex}"
        self._report_builder = ScreeningReportBuilder(
            ledger=self.ledger,
            service_database=self.service_database,
            clock=self.clock,
            inspect_job=lambda job_id: self._case_executor.inspect_job(job_id),
        )

    @property
    def service_factory(self) -> Callable[[], GenerationService] | None:
        return self._service_factory

    @service_factory.setter
    def service_factory(self, value: Callable[[], GenerationService] | None) -> None:
        self._service_factory = value
        executor = getattr(self, "_case_executor", None)
        if executor is not None:
            executor.service_factory = value

    def create_run(self, manifest: ScreeningManifest) -> str:
        """Freeze run identity and every case request before service admission."""
        if self.execution_identity is None:
            raise ScreeningConfigurationError(
                "a new run requires an explicit, pinned execution configuration"
            )
        run_id = f"run_{uuid.uuid4().hex}"
        cases = build_case_definitions(manifest, run_id=run_id)
        operation_intents = tuple(
            case["operation_intent"] for case in cases
        )
        _validate_variant_against_candidate(
            manifest.to_dict()["selected_model_variant"],
            self.execution_identity,
            operation_intents=operation_intents,
        )
        for case in cases:
            case["idempotency_key"] = f"t10:{run_id}:{case['case_id']}"
        fixture_states = self._case_executor.preflight_fixtures(cases)
        for case in cases:
            inputs = case["conditioning_inputs"]
            assert isinstance(inputs, list)
            observations = [fixture_states[str(item["artifact_id"])] for item in inputs]
            case["fixture_preflight"] = {
                "status": "ready"
                if all(item["status"] == "metadata_match" for item in observations)
                else "blocked",
                "inputs": observations,
            }
        identity_json = _canonical_json(dict(self.execution_identity))
        data = manifest.to_dict()
        self.ledger.create_run(
            run_id=run_id,
            manifest_json=manifest.document_json,
            manifest_sha256=manifest.fingerprint,
            execution_identity_json=identity_json,
            execution_identity_sha256=_sha256(identity_json.encode("utf-8")),
            fixture_fingerprint=_fingerprint(data["reference_styles"]),
            profile_fingerprint=_fingerprint(data["request_profile"]),
            selected_variant_json=_canonical_json(data["selected_model_variant"]),
            protocol_id=str(data["protocol_id"]),
            cases=cases,
            now=self.clock(),
        )
        return run_id

    def resume(
        self,
        run_id: str,
        *,
        manifest: ScreeningManifest | None = None,
        max_cases: int | None = None,
    ) -> dict[str, object]:
        """Reconcile accepted jobs first, then advance only incomplete cases."""
        run = self.ledger.get_run(run_id)
        cases = self.ledger.list_cases(run_id)
        operation_intents = tuple(
            case["operation_intent"] for case in cases
        )
        manifest_matches = manifest is None or manifest.fingerprint == run["manifest_sha256"]
        frozen_identity = run["execution_identity"]
        assert isinstance(frozen_identity, dict)
        identity_matches = False
        if self.execution_identity is not None:
            identity_matches = (
                _canonical_json(dict(self.execution_identity)) == _canonical_json(frozen_identity)
            )
            if identity_matches:
                try:
                    _validate_variant_against_candidate(
                        run["selected_model_variant"],
                        self.execution_identity,
                        operation_intents=operation_intents,
                    )
                except ScreeningConfigurationError:
                    identity_matches = False
        execution_compatible = manifest_matches and identity_matches
        if max_cases is not None and (
            isinstance(max_cases, bool) or not isinstance(max_cases, int) or max_cases < 0
        ):
            raise ValueError("max_cases must be a nonnegative integer")

        processed = 0
        for case in cases:
            if max_cases is not None and processed >= max_cases:
                break
            claim = self.ledger.claim_case(
                run_id,
                str(case["case_id"]),
                self._runner_id,
                now=self.clock(),
                lease_seconds=self.lease_seconds,
            )
            if claim is None:
                continue
            try:
                with self._heartbeat(claim):
                    self._case_executor.advance_case(
                        run, case, claim, execution_compatible=execution_compatible
                    )
            except Exception as error:
                self._case_executor.record_error(claim, error)
            else:
                self.ledger.release_claim(claim, now=self.clock())
            processed += 1
        return self.report(run_id)

    def report(self, run_id: str) -> dict[str, object]:
        """Return a read-only report of benchmark and service state."""
        return self._report_builder.report(run_id)











    @contextmanager
    def _heartbeat(self, claim: CaseClaim) -> Iterator[None]:
        interval = self.heartbeat_interval
        if interval is None:
            yield
            return
        stop = threading.Event()
        lost = threading.Event()

        def renew() -> None:
            while not stop.wait(interval):
                try:
                    active = self.ledger.renew_claim(
                        claim, now=self.clock(), lease_seconds=self.lease_seconds
                    )
                except Exception:
                    active = False
                if not active:
                    lost.set()
                    return

        thread = threading.Thread(target=renew, name="screening-case-lease", daemon=True)
        thread.start()
        try:
            yield
            if lost.is_set():
                raise ScreeningClaimLostError(
                    f"screening case claim was lost during execution: {claim.case_id}"
                )
        finally:
            stop.set()
            thread.join(timeout=max(0.1, interval * 2))

def _normalize_execution_identity(
    value: Mapping[str, object], service_database: Path, output_directory: Path
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ScreeningConfigurationError("execution identity must be a JSON object")
    result = dict(value)
    result["service_database"] = str(service_database)
    result["output_directory"] = str(output_directory)
    if not isinstance(result.get("adapter_id"), str) or not result["adapter_id"]:
        raise ScreeningConfigurationError("execution identity must include adapter_id")
    if "adapter_configuration" not in result:
        raise ScreeningConfigurationError("execution identity must include adapter_configuration")
    try:
        _canonical_json(result)
    except (TypeError, ValueError) as error:
        raise ScreeningConfigurationError("execution identity must be finite JSON") from error
    return result

def _external_path(path: Path, label: str) -> Path:
    resolved = Path(path).expanduser().resolve()
    for parent in (resolved, *resolved.parents):
        marker = parent / ".git"
        if marker.exists():
            raise ScreeningConfigurationError(f"{label} must be outside Git worktrees")
    return resolved
