"""Read-only screening reports built from ledger and service evidence."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Callable, Mapping

from .errors import RecordNotFoundError
from .screening_store import ScreeningLedger, ScreeningStoreError
from .service import GenerationService

REPORT_SCHEMA_VERSION = 2
_TERMINAL_JOB_STATES = frozenset({"succeeded", "failed", "ambiguous", "canceled"})

class ScreeningReportBuilder:
    """Reconcile a run with persisted service records without execution."""

    def __init__(
        self,
        *,
        ledger: ScreeningLedger,
        service_database: Path,
        clock: Callable[[], float],
        inspect_job: Callable[[str], dict[str, object]],
    ) -> None:
        self.ledger = ledger
        self.service_database = service_database
        self.clock = clock
        self._inspect_job = inspect_job

    def report(self, run_id: str) -> dict[str, object]:
        """Reconcile service evidence without admission, inference, or replacement."""
        run = self.ledger.get_run(run_id)
        cases = self.ledger.list_cases(run_id)
        matrix: list[dict[str, object]] = []
        supplementary: list[dict[str, object]] = []
        for case in cases:
            observed = self._report_case(case)
            if case["kind"] == "matrix":
                matrix.append(observed)
            else:
                supplementary.append(observed)
        pairings: dict[str, list[dict[str, object]]] = {}
        chains: dict[str, list[dict[str, object]]] = {}
        for case in supplementary:
            pairing = case.get("pairing")
            if isinstance(pairing, dict):
                pairings.setdefault(str(pairing["pair_id"]), []).append(
                    {"role": pairing["role"], "case_id": case["case_id"], "artifact_id": case.get("artifact_id")}
                )
            metadata = case.get("supplementary_metadata")
            if isinstance(metadata, dict) and metadata.get("chain_id") is not None:
                chains.setdefault(str(metadata["chain_id"]), []).append(
                    {
                        "step": metadata["chain_step"],
                        "case_id": case["case_id"],
                        "status": case["status"],
                        "conditioning_inputs": case["conditioning_inputs"],
                        "artifact_id": case.get("artifact_id"),
                    }
                )
        for steps in chains.values():
            steps.sort(key=lambda item: int(item["step"]))
        matrix_counts: dict[str, int] = {}
        for case in matrix:
            status = str(case["status"])
            matrix_counts[status] = matrix_counts.get(status, 0) + 1
        summary = {
            "matrix_denominator": 24,
            "matrix_accounted": len(matrix),
            "matrix_status_counts": matrix_counts,
            "supplementary_denominator": len(supplementary),
            "supplementary_status_counts": _count_statuses(supplementary),
        }
        completed_cases = [
            case
            for case in matrix
            if case.get("execution_status") in _TERMINAL_JOB_STATES
        ]
        completed = len(completed_cases)
        successful = sum(
            case.get("execution_status") == "succeeded" for case in completed_cases
        )
        failed = completed - successful
        unresolved = max(0, 24 - completed)
        matrix_complete = len(matrix) == 24 and completed == 24
        matrix_execution = {
            "status": "complete" if matrix_complete else "incomplete",
            "denominator": 24,
            "accounted": len(matrix),
            "completed": completed,
            "successful": successful,
            "failed": failed,
            "unresolved": unresolved,
            "execution_success": (
                successful == 24 if matrix_complete else None
            ),
        }
        return {
            "schema_version": REPORT_SCHEMA_VERSION,
            "run_id": run_id,
            "status": "available",
            "summary": summary,
            "matrix_execution": matrix_execution,
            "protocol_id": run["protocol_id"],
            "protocol_fingerprint": run["manifest_sha256"],
            "fixture_fingerprint": run["fixture_fingerprint"],
            "profile_fingerprint": run["profile_fingerprint"],
            "selected_model_variant": run["selected_model_variant"],
            "execution_identity": run["execution_identity"],
            "apex_execution": {
                "status": "unverified",
                "reason": "software validation and local job records do not establish live APEX screening",
            },
            "qualification": {
                "status": "unverified",
                "reason": "owner review and live APEX evidence are required for qualification",
            },
            "matrix_cases": matrix,
            "supplementary_cases": supplementary,
            "preview_final_pairings": [
                {"pair_id": key, "cases": values} for key, values in sorted(pairings.items())
            ],
            "chain_sequences": [
                {"chain_id": key, "steps": values} for key, values in sorted(chains.items())
            ],
            "followups": [
                "Run the pinned 24-case matrix on the owner-selected APEX configuration and retain its outputs.",
                "Review supplementary capability, editing, chain, composition, outfit, and test-profile results separately.",
            ],
        }

    def _report_case(self, case: Mapping[str, object]) -> dict[str, object]:
        definition = case.get("definition")
        definition = definition if isinstance(definition, dict) else {}
        result = dict(definition)
        result.update(
            {
                "status": case["status"],
                "benchmark_status": case["status"],
                "service_status": None,
                "service_execution_status": None,
                "execution_status": case.get("execution_status"),
                "execution_succeeded": case.get("execution_succeeded"),
                "request_digest": case["request_digest"],
                "idempotency_key": case["idempotency_key"],
                "request_id": case.get("request_id"),
                "job_id": case.get("job_id"),
                "attempt_ids": case.get("attempt_ids") or [],
                "artifact_id": case.get("artifact_id"),
                "artifact_integrity": case.get("artifact_integrity"),
                "service_evidence": case.get("service_evidence"),
                "admission": case.get("admission"),
                "error_code": case.get("error_code"),
                "reason": case.get("reason"),
                "execution_succeeded": bool(case.get("execution_succeeded"))
                if case.get("execution_succeeded") is not None
                else None,
            }
        )
        key = str(case["idempotency_key"])
        try:
            existing = GenerationService.lookup_existing_idempotency_key(
                self.service_database, key
            )
        except Exception as error:
            self._set_report_reconciliation_error(
                result,
                case,
                "service_lookup_unavailable",
                f"read-only service lookup failed: {type(error).__name__}",
            )
            return result
        if existing is None:
            if case.get("job_id"):
                self._set_report_reconciliation_error(
                    result,
                    case,
                    "persisted_job_missing",
                    "ledger job id is absent from the configured service database",
                )
            elif definition.get("fixture_preflight", {}).get("status") != "ready":
                fixture = definition.get("fixture_preflight")
                self._set_report_reconciliation_error(
                    result,
                    case,
                    "fixture_fingerprint_unverified",
                    "conditioning artifacts are missing or do not match the frozen fixture fingerprints",
                )
                result["service_evidence"] = {"fixture_preflight": fixture}
            elif case.get("status") == "in_progress":
                lease_until = case.get("lease_expires_at")
                if lease_until is None or float(lease_until) <= self.clock():
                    result["status"] = "interrupted"
                    result["benchmark_status"] = "interrupted"
            return result
        job_id, request_digest = existing
        if request_digest != case["request_digest"]:
            self._set_report_reconciliation_error(
                result,
                case,
                "idempotency_digest_conflict",
                "persisted idempotency key belongs to a different canonical request digest",
            )
            result["job_id"] = job_id
            return result
        try:
            state = self._inspect_job(job_id)
        except (RecordNotFoundError, ScreeningStoreError, sqlite3.Error) as error:
            self._set_report_reconciliation_error(
                result,
                case,
                "service_job_unavailable",
                f"persisted service job could not be inspected: {type(error).__name__}",
            )
            result["job_id"] = job_id
            return result
        result.update(
            {
                key: value
                for key, value in state.items()
                if key not in {"status", "error_code", "reason"}
            }
        )
        result["service_status"] = state.get("status")
        result["service_error_code"] = state.get("error_code")
        result["service_reason"] = state.get("reason")
        result["service_execution_status"] = state.get("execution_status")
        result["request_digest"] = request_digest
        return result

    @staticmethod
    def _set_report_reconciliation_error(
        result: dict[str, object],
        case: Mapping[str, object],
        error_code: str,
        reason: str,
    ) -> None:
        """Expose read-only reconciliation errors without replacing ledger evidence."""
        result["service_reconciliation_error"] = {
            "error_code": error_code,
            "reason": reason,
        }
        if case.get("error_code") is None:
            result.update(
                {"status": "blocked", "error_code": error_code, "reason": reason}
            )
            result["benchmark_status"] = "blocked"


def _count_statuses(cases: list[Mapping[str, object]]) -> dict[str, int]:
    result: dict[str, int] = {}
    for case in cases:
        status = str(case["status"])
        result[status] = result.get(status, 0) + 1
    return result

def _table_cell(value: object) -> str:
    if value is None:
        return ""
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")

def render_summary(report: Mapping[str, object]) -> str:
    """Render a compact human-readable summary without scores or qualification claims."""
    summary = report["summary"]
    assert isinstance(summary, dict)
    counts = summary["matrix_status_counts"]
    assert isinstance(counts, dict)
    lines = [
        f"# Character screening run {report['run_id']}",
        "",
        f"Report retrieval: {report['status']}",
        f"Protocol: {report['protocol_id']}",
        f"Matrix denominator: {summary['matrix_accounted']} of 24 cases",
        f"Matrix execution: {report['matrix_execution']['status']}",
        "Matrix outcomes: "
        + (
            ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))
            if counts
            else "no cases completed"
        ),
        "APEX execution: unverified",
        "Qualification: unverified",
        "",
        "## Matrix cases",
        "",
        "| Case | Status | Execution | Artifact integrity | Artifact | Reason |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    matrix = report["matrix_cases"]
    assert isinstance(matrix, list)
    for case in matrix:
        integrity = case.get("artifact_integrity")
        integrity_status = integrity.get("status", "unverified") if isinstance(integrity, dict) else "unverified"
        reason = str(case.get("reason") or case.get("error_code") or "")
        lines.append(
            "| {label} | {status} | {execution} | {integrity} | {artifact} | {reason} |".format(
                label=_table_cell(case.get("label")),
                status=_table_cell(case.get("status")),
                execution=_table_cell(case.get("execution_status")),
                integrity=_table_cell(integrity_status),
                artifact=_table_cell(case.get("artifact_id")),
                reason=_table_cell(reason),
            )
        )
    lines.extend(
        [
            "",
            "## Supplementary cases",
            "",
            "These cases are reported separately and do not change the 24-case denominator.",
            "",
        ]
    )
    supplements = report["supplementary_cases"]
    assert isinstance(supplements, list)
    for case in supplements:
        lines.append(
            f"- {_table_cell(case.get('label'))}: {_table_cell(case.get('status'))}; "
            f"execution {_table_cell(case.get('execution_status'))}; "
            f"artifact {_table_cell(case.get('artifact_id'))}."
        )
    lines.extend(
        [
            "",
            "Software validation and local job records do not establish completed APEX screening or configuration qualification.",
            "",
        ]
    )
    return "\n".join(lines)
