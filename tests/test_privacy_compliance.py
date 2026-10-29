"""Configuration-only local inference privacy compliance contracts."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Mapping
from pathlib import Path

import pytest

from media_generation.adapters import (
    DeterministicCpuAdapter,
    PROCESS_CONTAINED_CONTRACT,
    trusted_containment_contract,
)
from media_generation.domain import GenerationRequest
from media_generation.errors import (
    GenerationError,
    IdempotencyConflictError,
    PrivacyComplianceError,
)
from media_generation.privacy import (
    DEFAULT_PRIVACY_POLICY,
    PRIVACY_PROFILE_SCHEMA_VERSION,
    PRIVACY_RESULT_SCHEMA_VERSION,
    PrivacyCompliancePolicy,
    PrivacyComplianceStatus,
    PrivacyControl,
    PrivacyProfile,
    PrivacySettingRule,
    historical_privacy_compliance,
    is_privacy_compliance_record,
)
from media_generation.service import GenerationService
from media_generation.admission import (
    build_admission_profile,
    parse_admission_policy,
    parse_workload_demand,
)
from test_resource_admission import GIB, inventory_report, workload_demand


FIXTURE_ADAPTER_ID = "fixture-local-engine-adapter-v1"
FIXTURE_TOOL_ID = "fixture-local-engine"
FIXTURE_TOOL_VERSION = "1.0"
SENSITIVE_SENTINEL = "do-not-emit-this-secret"


def _compliant_configuration(
    *,
    configuration_version: bool | int | str = 1,
) -> dict[str, object]:
    """Build settings for the synthetic profile used only by these tests."""
    return {
        "configuration_version": configuration_version,
        "inference": {
            control.value: False for control in PrivacyControl
        },
    }


def _profile(
    *,
    profile_version: int = 1,
    supports_compliance: bool = True,
) -> PrivacyProfile:
    """Describe a complete test-only local-only configuration contract."""
    requirements = tuple(
        PrivacySettingRule(
            control=control,
            path=("inference", control.value),
            expected=False,
            prohibited=(True,),
        )
        for control in PrivacyControl
    )
    return PrivacyProfile(
        schema_version=PRIVACY_PROFILE_SCHEMA_VERSION,
        profile_id="fixture-local-only",
        profile_version=profile_version,
        adapter_id=FIXTURE_ADAPTER_ID,
        tool_id=FIXTURE_TOOL_ID,
        tool_version=FIXTURE_TOOL_VERSION,
        configuration_version=1,
        requirements=requirements if supports_compliance else (),
        supports_configuration_compliance=supports_compliance,
    )


def _policy(*, profile_version: int = 1) -> PrivacyCompliancePolicy:
    """Create the evaluator used by service and serialization tests."""
    return PrivacyCompliancePolicy((_profile(profile_version=profile_version),))


@pytest.mark.parametrize(
    "invalid_value",
    [None, 0, 1, 2, "true", "false", [], {}, object()],
)
def test_privacy_profile_rejects_non_boolean_configuration_compliance(
    invalid_value: object,
) -> None:
    with pytest.raises(
        ValueError,
        match="supports_configuration_compliance must be a boolean",
    ):
        _profile(supports_compliance=invalid_value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [True, False])
def test_privacy_profile_accepts_boolean_configuration_compliance(
    value: bool,
) -> None:
    profile = _profile(supports_compliance=value)

    assert type(profile.supports_configuration_compliance) is bool
    assert profile.supports_configuration_compliance is value


class _FixturePrivacyAdapter(DeterministicCpuAdapter):
    """Deterministic renderer with exact fixture privacy configuration."""

    adapter_id = FIXTURE_ADAPTER_ID
    containment_contract = PROCESS_CONTAINED_CONTRACT

    def __init__(self, configuration: Mapping[str, object]) -> None:
        self._configuration = dict(configuration)

    @property
    def configuration(self) -> dict[str, object]:
        return dict(self._configuration)

    def set_control(self, control: PrivacyControl, value: object) -> None:
        inference = self._configuration["inference"]
        assert isinstance(inference, dict)
        inference[control.value] = value


class _HashableMapping(Mapping[str, object]):
    """Immutable mapping wrapper that can be nested inside a set fixture."""

    def __init__(self, values: Mapping[str, object]) -> None:
        self._values = dict(values)

    def __getitem__(self, key: str) -> object:
        return self._values[key]

    def __iter__(self):
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __hash__(self) -> int:
        return id(self)


def _request(output_slot: str = "privacy") -> GenerationRequest:
    return GenerationRequest(
        prompt="A lantern in a quiet workshop",
        seed=41,
        width=8,
        height=7,
        output_slot=output_slot,
    )


def _heavyweight_profile():
    """Return deterministic capacity evidence for the fixture adapter."""
    return build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )


def _heavyweight_demand():
    """Return explicit demand that fits the privacy fixture profile."""
    return parse_workload_demand(workload_demand())


def test_compliant_effective_settings_produce_versioned_configuration_pass() -> None:
    configuration = _compliant_configuration()
    result = _policy().evaluate(FIXTURE_ADAPTER_ID, configuration)

    assert result.status is PrivacyComplianceStatus.PASS
    payload = result.to_dict()
    assert payload["schema_version"] == PRIVACY_RESULT_SCHEMA_VERSION
    assert payload["assurance_scope"] == "configuration-compliance-only"
    assert payload["evidence_source"] == "application-owned-profile"
    assert payload["supports_configuration_compliance"] is True
    assert payload["adapter_id"] == FIXTURE_ADAPTER_ID
    assert payload["tool_id"] == FIXTURE_TOOL_ID
    assert payload["tool_version"] == FIXTURE_TOOL_VERSION
    assert payload["configuration_fingerprint"] == result.configuration_fingerprint
    assert len(payload["controls"]) == len(PrivacyControl)
    assert {item["status"] for item in payload["controls"]} == {"pass"}
    assert payload["fingerprint"] == result.to_json_result()["fingerprint"]


@pytest.mark.parametrize("control", tuple(PrivacyControl))
def test_known_enabled_prohibited_control_fails(control: PrivacyControl) -> None:
    configuration = _compliant_configuration()
    inference = configuration["inference"]
    assert isinstance(inference, dict)
    inference[control.value] = True

    result = _policy().evaluate(FIXTURE_ADAPTER_ID, configuration)

    assert result.status is PrivacyComplianceStatus.FAIL
    assert "prohibited_setting_enabled" in result.reason_codes


@pytest.mark.parametrize("control", tuple(PrivacyControl))
def test_missing_required_control_is_unverified(control: PrivacyControl) -> None:
    configuration = _compliant_configuration()
    inference = configuration["inference"]
    assert isinstance(inference, dict)
    del inference[control.value]

    result = _policy().evaluate(FIXTURE_ADAPTER_ID, configuration)

    assert result.status is PrivacyComplianceStatus.UNVERIFIED
    assert "setting_missing" in result.reason_codes


def test_unknown_adapter_and_configuration_version_are_unverified() -> None:
    unknown_adapter = _policy().evaluate(
        "unregistered-adapter",
        _compliant_configuration(configuration_version="release-7"),
    )
    unknown_version = _policy().evaluate(
        FIXTURE_ADAPTER_ID,
        _compliant_configuration(configuration_version="release-8"),
    )

    assert unknown_adapter.status is PrivacyComplianceStatus.UNVERIFIED
    assert "profile_not_found" in unknown_adapter.reason_codes
    assert unknown_adapter.configuration_version == "release-7"
    assert unknown_version.status is PrivacyComplianceStatus.UNVERIFIED
    assert "configuration_version_mismatch" in unknown_version.reason_codes
    assert unknown_version.configuration_version == "release-8"


def test_non_json_configuration_is_unverified() -> None:
    configuration = _compliant_configuration()
    configuration["non_json_setting"] = object()

    result = _policy().evaluate(FIXTURE_ADAPTER_ID, configuration)

    assert result.status is PrivacyComplianceStatus.UNVERIFIED
    assert "configuration_not_json" in result.reason_codes
    assert result.configuration_fingerprint is None


def test_non_json_adapter_configuration_extension_values_set_fails_admission_without_persistence(
    tmp_path: Path,
) -> None:
    configuration = _compliant_configuration()
    configuration["extension_values"] = {SENSITIVE_SENTINEL}
    database = tmp_path / "non-json.sqlite3"

    with pytest.raises(PrivacyComplianceError) as raised:
        GenerationService(
            database,
            tmp_path / "images",
            adapter=_FixturePrivacyAdapter(configuration),
        )

    result = raised.value.result
    assert result.status is PrivacyComplianceStatus.UNVERIFIED
    assert "configuration_not_json" in result.reason_codes
    assert SENSITIVE_SENTINEL not in result.to_json()
    assert not database.exists()


class _HashableMapping(Mapping[str, object]):
    """Expose a nested key/value mapping as a set member for traversal tests."""

    def __init__(self, values: Mapping[str, object]) -> None:
        self._values = dict(values)

    def __getitem__(self, key: str) -> object:
        return self._values[key]

    def __iter__(self):
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __hash__(self) -> int:
        return id(self)


@pytest.mark.parametrize(
    ("marker", "reason_code"),
    (
        ("apiKey", "credential_material_present"),
        ("modelAcquisition", "acquisition_configuration_present"),
    ),
)
def test_set_values_are_scanned_for_sensitive_configuration_markers(
    marker: str,
    reason_code: str,
) -> None:
    configuration = _compliant_configuration()
    configuration["extension_values"] = {
        frozenset({_HashableMapping({marker: SENSITIVE_SENTINEL})})
    }

    result = _policy().evaluate(FIXTURE_ADAPTER_ID, configuration)

    assert result.status is PrivacyComplianceStatus.FAIL
    assert reason_code in result.reason_codes
    assert SENSITIVE_SENTINEL not in result.to_json()


def test_non_json_adapter_configuration_unserializable_setting_fails_admission_without_persistence(
    tmp_path: Path,
) -> None:
    configuration = _compliant_configuration()
    configuration["unserializable"] = {SENSITIVE_SENTINEL}
    database = tmp_path / "unserializable.sqlite3"

    with pytest.raises(PrivacyComplianceError) as raised:
        GenerationService(
            database,
            tmp_path / "images",
            adapter=_FixturePrivacyAdapter(configuration),
        )

    result_json = raised.value.result.to_json()
    assert raised.value.result.status is PrivacyComplianceStatus.UNVERIFIED
    assert "configuration_not_json" in raised.value.result.reason_codes
    assert SENSITIVE_SENTINEL not in result_json
    assert not database.exists()


@pytest.mark.parametrize(
    ("marker", "reason_code"),
    (
        ("apiKey", "credential_material_present"),
        ("modelAcquisition", "acquisition_configuration_present"),
    ),
)
def test_set_nested_configuration_markers_are_detected_and_redacted(
    marker: str,
    reason_code: str,
) -> None:
    configuration = _compliant_configuration()
    configuration["extension"] = {
        frozenset({_HashableMapping({marker: SENSITIVE_SENTINEL})})
    }

    result = _policy().evaluate(FIXTURE_ADAPTER_ID, configuration)

    assert result.status is PrivacyComplianceStatus.FAIL
    assert reason_code in result.reason_codes
    assert SENSITIVE_SENTINEL not in result.to_json()


@pytest.mark.parametrize(
    "container_factory",
    (set, frozenset),
    ids=("set", "frozenset"),
)
@pytest.mark.parametrize(
    ("marker", "reason_code"),
    (
        ("apiKey", "credential_material_present"),
        ("modelAcquisition", "acquisition_configuration_present"),
    ),
)
def test_set_containers_are_scanned_for_sensitive_markers(
    container_factory: type[set[object]] | type[frozenset[object]],
    marker: str,
    reason_code: str,
) -> None:
    configuration = _compliant_configuration()
    configuration["extension_values"] = container_factory(
        {_HashableMapping({marker: SENSITIVE_SENTINEL})}
    )

    result = _policy().evaluate(FIXTURE_ADAPTER_ID, configuration)

    assert result.status is PrivacyComplianceStatus.FAIL
    assert reason_code in result.reason_codes
    assert SENSITIVE_SENTINEL not in result.to_json()


def test_cyclic_configuration_fails_closed_without_recursion_error() -> None:
    configuration = _compliant_configuration()
    recursive_mapping: dict[str, object] = {}
    recursive_mapping["self"] = recursive_mapping
    recursive_sequence: list[object] = []
    recursive_sequence.append(recursive_sequence)
    recursive_set: set[object] = set()
    set_mapping = _HashableMapping({"self": recursive_set})
    recursive_set.add(set_mapping)
    configuration["recursive_mapping"] = recursive_mapping
    configuration["recursive_sequence"] = recursive_sequence
    configuration["recursive_set"] = recursive_set

    result = _policy().evaluate(FIXTURE_ADAPTER_ID, configuration)

    assert result.status is PrivacyComplianceStatus.UNVERIFIED
    assert "configuration_not_json" in result.reason_codes
    assert result.configuration_fingerprint is None


def test_unrecognized_control_value_is_unverified() -> None:
    configuration = _compliant_configuration()
    inference = configuration["inference"]
    assert isinstance(inference, dict)
    inference[PrivacyControl.TELEMETRY.value] = "disabled-elsewhere"

    result = _policy().evaluate(FIXTURE_ADAPTER_ID, configuration)

    assert result.status is PrivacyComplianceStatus.UNVERIFIED
    assert "setting_value_unrecognized" in result.reason_codes


def test_self_attested_privacy_claim_never_produces_pass() -> None:
    configuration = _compliant_configuration()
    configuration["privacy_status"] = "pass"
    configuration["privacy_compliance"] = {"status": "pass"}

    result = _policy().evaluate(FIXTURE_ADAPTER_ID, configuration)

    assert result.status is PrivacyComplianceStatus.UNVERIFIED
    assert "untrusted_self_attestation" in result.reason_codes


def test_nested_camel_case_self_attestation_is_untrusted() -> None:
    configuration = _compliant_configuration()
    inference = configuration["inference"]
    assert isinstance(inference, dict)
    inference["provider"] = {"privacyStatus": "pass"}

    result = _policy().evaluate(FIXTURE_ADAPTER_ID, configuration)

    assert result.status is PrivacyComplianceStatus.UNVERIFIED
    assert "untrusted_self_attestation" in result.reason_codes


@pytest.mark.parametrize(
    "nested_configuration",
    (
        {"providers": [{"modelAcquisition": {"endpoint": SENSITIVE_SENTINEL}}]},
        {
            "provider": {
                "acquisitionConfiguration": {"endpoint": SENSITIVE_SENTINEL}
            }
        },
    ),
    ids=("list-of-dicts", "nested-camel-case"),
)
def test_nested_camel_case_acquisition_configuration_fails(
    nested_configuration: dict[str, object],
) -> None:
    configuration = _compliant_configuration()
    inference = configuration["inference"]
    assert isinstance(inference, dict)
    inference.update(nested_configuration)

    result = _policy().evaluate(FIXTURE_ADAPTER_ID, configuration)

    assert result.status is PrivacyComplianceStatus.FAIL
    assert "acquisition_configuration_present" in result.reason_codes
    assert SENSITIVE_SENTINEL not in result.to_json()


def test_credentials_and_acquisition_configuration_fail_without_redaction_leak() -> None:
    credential_configuration = _compliant_configuration()
    credential_configuration["api_key"] = SENSITIVE_SENTINEL
    acquisition_configuration = _compliant_configuration()
    acquisition_configuration["model_acquisition"] = {
        "endpoint": SENSITIVE_SENTINEL,
    }

    credential_result = _policy().evaluate(FIXTURE_ADAPTER_ID, credential_configuration)
    acquisition_result = _policy().evaluate(FIXTURE_ADAPTER_ID, acquisition_configuration)

    assert credential_result.status is PrivacyComplianceStatus.FAIL
    assert "credential_material_present" in credential_result.reason_codes
    assert acquisition_result.status is PrivacyComplianceStatus.FAIL
    assert "acquisition_configuration_present" in acquisition_result.reason_codes
    assert SENSITIVE_SENTINEL not in credential_result.to_json()
    assert SENSITIVE_SENTINEL not in acquisition_result.to_json()


@pytest.mark.parametrize("credential_key", ("apiKey", "clientSecret"))
def test_camel_case_credentials_fail_configuration_evaluation(
    credential_key: str,
) -> None:
    configuration = _compliant_configuration()
    configuration[credential_key] = SENSITIVE_SENTINEL

    result = _policy().evaluate(FIXTURE_ADAPTER_ID, configuration)

    assert result.status is PrivacyComplianceStatus.FAIL
    assert "credential_material_present" in result.reason_codes
    assert SENSITIVE_SENTINEL not in result.to_json()


@pytest.mark.parametrize(
    "nested_configuration",
    (
        {"providers": [{"clientSecret": SENSITIVE_SENTINEL}]},
        {
            "provider": {
                "connections": [{"connection": {"apiKey": SENSITIVE_SENTINEL}}]
            }
        },
    ),
    ids=("list-of-dicts", "nested-list-of-dicts"),
)
def test_container_credentials_are_rejected_before_persistence(
    tmp_path: Path,
    nested_configuration: dict[str, object],
) -> None:
    database = tmp_path / "studio.sqlite3"
    adapter = _FixturePrivacyAdapter(_compliant_configuration())
    service = GenerationService(
        database,
        tmp_path / "images",
        adapter=adapter,
        privacy_policy=_policy(),
    )
    inference = adapter.configuration["inference"]
    assert isinstance(inference, dict)
    inference.update(nested_configuration)

    with pytest.raises(PrivacyComplianceError) as raised:
        service.enqueue("nested-credential", _request("nested-credential"))

    assert "credential_material_present" in raised.value.result.reason_codes
    assert SENSITIVE_SENTINEL not in str(raised.value)
    assert SENSITIVE_SENTINEL.encode() not in database.read_bytes()
    with service._store._connection() as connection:
        job_count = connection.execute(
            "SELECT COUNT(*) FROM generation_jobs"
        ).fetchone()[0]
    assert job_count == 0


def test_known_credential_failure_takes_precedence_over_unknown_profile() -> None:
    configuration = _compliant_configuration()
    configuration["password"] = SENSITIVE_SENTINEL

    result = _policy().evaluate("unregistered-adapter", configuration)

    assert result.status is PrivacyComplianceStatus.FAIL
    assert "credential_material_present" in result.reason_codes
    assert SENSITIVE_SENTINEL not in result.to_json()


def test_fingerprints_are_stable_and_change_with_configuration_or_profile() -> None:
    first = _policy(profile_version=1).evaluate(
        FIXTURE_ADAPTER_ID,
        _compliant_configuration(),
    )
    reordered_configuration = dict(reversed(list(_compliant_configuration().items())))
    reordered = _policy(profile_version=1).evaluate(
        FIXTURE_ADAPTER_ID,
        reordered_configuration,
    )
    changed_configuration = _compliant_configuration()
    changed_configuration["workflow_label"] = "different"
    changed = _policy(profile_version=1).evaluate(
        FIXTURE_ADAPTER_ID,
        changed_configuration,
    )
    changed_profile = _policy(profile_version=2).evaluate(
        FIXTURE_ADAPTER_ID,
        _compliant_configuration(),
    )

    assert first.configuration_fingerprint == reordered.configuration_fingerprint
    assert first.fingerprint == reordered.fingerprint
    assert first.configuration_fingerprint != changed.configuration_fingerprint
    assert first.fingerprint != changed.fingerprint
    assert first.profile_fingerprint != changed_profile.profile_fingerprint
    assert any(
        line["code"] == "unqualified_configuration"
        for line in DEFAULT_PRIVACY_POLICY.evaluate(
            DeterministicCpuAdapter().adapter_id,
            DeterministicCpuAdapter().configuration,
        ).to_dict()["reasons"]
    )


def test_profile_rejects_duplicate_or_incomplete_control_contracts() -> None:
    duplicate_rule = PrivacySettingRule(
        control=PrivacyControl.TELEMETRY,
        path=("inference", "telemetry"),
        expected=False,
        prohibited=(True,),
    )
    complete = _profile()

    with pytest.raises(ValueError, match="each supported privacy control once"):
        PrivacyProfile(
            schema_version=complete.schema_version,
            profile_id="duplicate-controls",
            profile_version=1,
            adapter_id=complete.adapter_id,
            tool_id=complete.tool_id,
            tool_version=complete.tool_version,
            configuration_version=1,
            requirements=(duplicate_rule, duplicate_rule),
            supports_configuration_compliance=True,
        )
    with pytest.raises(ValueError, match="each supported privacy control once"):
        PrivacyProfile(
            schema_version=complete.schema_version,
            profile_id="incomplete-controls",
            profile_version=1,
            adapter_id=complete.adapter_id,
            tool_id=complete.tool_id,
            tool_version=complete.tool_version,
            configuration_version=1,
            requirements=(duplicate_rule,),
            supports_configuration_compliance=True,
        )


def test_profile_rejects_controls_reusing_one_configuration_path() -> None:
    complete = _profile()
    reused_path = ("inference", "local_only")
    reused_requirements = tuple(
        PrivacySettingRule(
            control=control,
            path=reused_path,
            expected=False,
            prohibited=(True,),
        )
        for control in PrivacyControl
    )

    with pytest.raises(ValueError, match="distinct configuration paths"):
        PrivacyProfile(
            schema_version=complete.schema_version,
            profile_id="reused-configuration-path",
            profile_version=1,
            adapter_id=complete.adapter_id,
            tool_id=complete.tool_id,
            tool_version=complete.tool_version,
            configuration_version=1,
            requirements=reused_requirements,
            supports_configuration_compliance=True,
        )

    distinct_paths = PrivacyProfile(
        schema_version=complete.schema_version,
        profile_id="distinct-configuration-paths",
        profile_version=1,
        adapter_id=complete.adapter_id,
        tool_id=complete.tool_id,
        tool_version=complete.tool_version,
        configuration_version=1,
        requirements=complete.requirements,
        supports_configuration_compliance=True,
    )
    assert len({rule.path for rule in distinct_paths.requirements}) == len(
        PrivacyControl
    )


def test_policy_rejects_duplicate_adapter_configuration_bindings() -> None:
    first = _profile()
    duplicate = PrivacyProfile(
        schema_version=first.schema_version,
        profile_id="another-profile-id",
        profile_version=2,
        adapter_id=first.adapter_id,
        tool_id=first.tool_id,
        tool_version=first.tool_version,
        configuration_version=first.configuration_version,
        requirements=first.requirements,
        supports_configuration_compliance=True,
    )

    with pytest.raises(ValueError, match="unique adapter and configuration bindings"):
        PrivacyCompliancePolicy((first, duplicate))


def test_deterministic_cpu_remains_usable_but_unverified_and_unchanged(
    tmp_path: Path,
) -> None:
    database = tmp_path / "studio.sqlite3"
    output = tmp_path / "images"
    adapter = DeterministicCpuAdapter()
    service = GenerationService(database, output, adapter=adapter)

    submitted = service.submit("deterministic-privacy", _request())
    provenance = service.get_provenance(submitted.job_id)

    assert submitted.status == "succeeded"
    assert provenance["adapter_configuration"] == adapter.configuration
    assert provenance["privacy_compliance"]["status"] == "unverified"
    assert "unqualified_configuration" in {
        reason["code"] for reason in provenance["privacy_compliance"]["reasons"]
    }


def test_strict_admission_accepts_only_configuration_pass(tmp_path: Path) -> None:
    policy = _policy()
    admission_profile = _heavyweight_profile()
    demand = _heavyweight_demand()
    admission_service = GenerationService(
        tmp_path / "accepted.sqlite3",
        tmp_path / "accepted-images",
        adapter=_FixturePrivacyAdapter(_compliant_configuration()),
        privacy_policy=policy,
        require_privacy_pass=True,
        admission_profile=admission_profile,
    )
    accepted = admission_service.enqueue(
        "accepted-privacy", _request(), workload_demand=demand
    )

    assert accepted.status == "queued"
    assert (
        admission_service.get_provenance(accepted.job_id)["privacy_compliance"]["status"]
        == "pass"
    )

    with pytest.raises(PrivacyComplianceError, match="unverified"):
        GenerationService(
            tmp_path / "unverified.sqlite3",
            tmp_path / "unverified-images",
            adapter=_FixturePrivacyAdapter(_compliant_configuration(configuration_version=2)),
            privacy_policy=policy,
            require_privacy_pass=True,
        )


def test_supported_profile_cannot_admit_unverified_configuration_implicitly(
    tmp_path: Path,
) -> None:
    with pytest.raises(PrivacyComplianceError, match="unverified"):
        GenerationService(
            tmp_path / "studio.sqlite3",
            tmp_path / "images",
            adapter=_FixturePrivacyAdapter(_compliant_configuration(configuration_version=2)),
            privacy_policy=_policy(),
        )


def test_known_prohibited_behavior_fails_even_without_strict_admission(
    tmp_path: Path,
) -> None:
    configuration = _compliant_configuration()
    inference = configuration["inference"]
    assert isinstance(inference, dict)
    inference[PrivacyControl.CLOUD_FALLBACK.value] = True

    with pytest.raises(PrivacyComplianceError, match="fail"):
        GenerationService(
            tmp_path / "studio.sqlite3",
            tmp_path / "images",
            adapter=_FixturePrivacyAdapter(configuration),
            privacy_policy=_policy(),
        )


_PRIVACY_CLAIM_EVIDENCE_ERROR = (
    "protected execution claim requires exact privacy-compliance evidence"
)
_PRIVACY_CLAIM_CONFIGURATION_ERROR = (
    "protected execution claim requires exact adapter-configuration evidence"
)


def _assert_claim_refusal_preserved_state(
    service: GenerationService,
    job_id: str,
) -> None:
    """Assert a rejected claim consumed no execution authority or resource."""
    with service._store._connection() as connection:
        execution = connection.execute(
            """SELECT status, current_attempt_id, fence_epoch, retry_eligible
               FROM execution_jobs WHERE job_id = ?""",
            (job_id,),
        ).fetchone()
        attempt_count = connection.execute(
            "SELECT count(*) FROM execution_attempts WHERE job_id = ?",
            (job_id,),
        ).fetchone()[0]
        authority_count = connection.execute(
            "SELECT count(*) FROM artifact_publication_authority WHERE job_id = ?",
            (job_id,),
        ).fetchone()[0]
        resource = connection.execute(
            """SELECT state, job_id, attempt_id, owner_id
               FROM execution_resource WHERE id = 1"""
        ).fetchone()

    assert execution is not None
    assert execution["status"] == "queued"
    assert execution["current_attempt_id"] is None
    assert execution["fence_epoch"] == 0
    assert execution["retry_eligible"] == 0
    assert attempt_count == 0
    assert authority_count == 0
    assert resource is not None
    assert resource["state"] == "available"
    assert resource["job_id"] is None
    assert resource["attempt_id"] is None
    assert resource["owner_id"] is None


def _execution_state_snapshot(
    service: GenerationService,
    job_id: str,
) -> dict[str, object]:
    """Capture durable job, execution, attempt, resource, and authority rows."""
    with service._store._connection() as connection:
        job = connection.execute(
            "SELECT * FROM generation_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        execution = connection.execute(
            "SELECT * FROM execution_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        attempts = connection.execute(
            """SELECT * FROM execution_attempts
               WHERE job_id = ? ORDER BY attempt_number""",
            (job_id,),
        ).fetchall()
        authority = connection.execute(
            """SELECT * FROM artifact_publication_authority
               WHERE job_id = ? ORDER BY publication_id""",
            (job_id,),
        ).fetchall()
        resource = connection.execute(
            "SELECT * FROM execution_resource WHERE id = 1"
        ).fetchone()
    return {
        "job": dict(job) if job is not None else None,
        "execution": dict(execution) if execution is not None else None,
        "attempts": [dict(row) for row in attempts],
        "authority": [dict(row) for row in authority],
        "resource": dict(resource) if resource is not None else None,
    }


def test_policy_version_change_cannot_reuse_stale_pass(tmp_path: Path) -> None:
    database = tmp_path / "studio.sqlite3"
    output = tmp_path / "images"
    adapter = _FixturePrivacyAdapter(_compliant_configuration())
    admission_profile = _heavyweight_profile()
    demand = _heavyweight_demand()
    first = GenerationService(
        database,
        output,
        adapter=adapter,
        privacy_policy=_policy(profile_version=1),
        require_privacy_pass=True,
        admission_profile=admission_profile,
    )
    first.enqueue("stale-privacy", _request("stale"), workload_demand=demand)
    changed_policy = GenerationService(
        database,
        output,
        adapter=adapter,
        privacy_policy=_policy(profile_version=2),
        require_privacy_pass=True,
        admission_profile=admission_profile,
    )

    with pytest.raises(IdempotencyConflictError, match="privacy"):
        changed_policy.enqueue(
            "stale-privacy", _request("stale"), workload_demand=demand
        )


def test_strict_idempotent_retry_rejects_completed_unverified_job(
    tmp_path: Path,
) -> None:
    """Strict admission cannot reuse a completed job with unverified evidence."""
    database = tmp_path / "studio.sqlite3"
    output = tmp_path / "images"
    adapter = _FixturePrivacyAdapter(_compliant_configuration())
    admission_profile = _heavyweight_profile()
    demand = _heavyweight_demand()
    permissive = GenerationService(
        database, output, adapter=adapter, admission_profile=admission_profile
    )
    key = "unverified-strict-retry"

    queued = permissive.enqueue(key, _request("unverified"), workload_demand=demand)
    assert queued.status == "queued"
    permissive.work(limit=1)
    produced = permissive.enqueue(
        key, _request("unverified"), workload_demand=demand
    )
    assert produced.job_id == queued.job_id
    assert produced.status == "succeeded"
    assert produced.artifact_id is not None
    assert (
        permissive.get_provenance(produced.job_id)["privacy_compliance"]["status"]
        == "unverified"
    )
    before = _execution_state_snapshot(permissive, produced.job_id)

    strict = GenerationService(
        database,
        output,
        adapter=adapter,
        privacy_policy=_policy(),
        require_privacy_pass=True,
        admission_profile=admission_profile,
    )
    reused = None
    with pytest.raises(
        IdempotencyConflictError,
        match="privacy-compliance evidence",
    ):
        reused = strict.enqueue(
            key, _request("unverified"), workload_demand=demand
        )

    assert reused is None
    assert strict.get_job(produced.job_id).artifact_id == produced.artifact_id
    after = _execution_state_snapshot(strict, produced.job_id)
    assert after["job"] == before["job"]
    assert after["execution"] == before["execution"]
    assert after["attempts"] == before["attempts"]
    assert after["resource"] == before["resource"]
    assert after["authority"] == before["authority"]


def test_worker_does_not_claim_job_with_stale_privacy_evidence(tmp_path: Path) -> None:
    database = tmp_path / "studio.sqlite3"
    output = tmp_path / "images"
    adapter = _FixturePrivacyAdapter(_compliant_configuration())
    admission_profile = _heavyweight_profile()
    demand = _heavyweight_demand()
    first = GenerationService(
        database,
        output,
        adapter=adapter,
        privacy_policy=_policy(profile_version=1),
        require_privacy_pass=True,
        admission_profile=admission_profile,
    )
    first.enqueue("stale-worker", _request("worker"), workload_demand=demand)
    changed_policy = GenerationService(
        database,
        output,
        adapter=adapter,
        privacy_policy=_policy(profile_version=2),
        require_privacy_pass=True,
        admission_profile=admission_profile,
    )

    job_id = first._store.find_idempotency_key("stale-worker")[0]
    with pytest.raises(GenerationError) as raised:
        changed_policy.work(limit=1)

    assert str(raised.value) == f"{_PRIVACY_CLAIM_EVIDENCE_ERROR}: {job_id}"
    _assert_claim_refusal_preserved_state(first, job_id)


def test_omitted_privacy_claim_allows_only_valid_unverified_evidence(
    tmp_path: Path,
) -> None:
    adapter = DeterministicCpuAdapter()
    output = tmp_path / "unverified-images"
    service = GenerationService(tmp_path / "unverified.sqlite3", output, adapter=adapter)
    unverified = service.enqueue("unverified-privacy", _request("unverified"))

    passed_adapter = _FixturePrivacyAdapter(_compliant_configuration())
    passed_output = tmp_path / "passed-images"
    passed = GenerationService(
        tmp_path / "passed.sqlite3",
        passed_output,
        adapter=passed_adapter,
        privacy_policy=_policy(),
        require_privacy_pass=True,
        admission_profile=_heavyweight_profile(),
    )
    passed_job = passed.enqueue(
        "passed-privacy", _request("passed"), workload_demand=_heavyweight_demand()
    )
    passed_record = passed.get_provenance(passed_job.job_id)["privacy_compliance"]
    passed_json = json.dumps(
        passed_record,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )

    def claim(
        service,
        current_adapter,
        current_output,
        job_id,
        attempt_id,
        evidence,
        configuration=None,
    ):
        containment_contract = trusted_containment_contract(current_adapter)
        current_configuration = (
            current_adapter.configuration if configuration is None else configuration
        )
        return service._store.claim_next_execution(
            attempt_id=attempt_id,
            owner_id="privacy-compatibility-worker",
            adapter_id=current_adapter.adapter_id,
            adapter_configuration_json=json.dumps(
                current_configuration,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            resolved_output_directory=str(current_output),
            process_contained=containment_contract is not None,
            containment_contract=containment_contract,
            timestamp="2026-10-26T00:00:00+00:00",
            lease_expires_at="2026-10-26T00:01:00+00:00",
            privacy_compliance_json=evidence,
            job_id=job_id,
        allow_not_required=type(current_adapter) is DeterministicCpuAdapter,
        )

    with pytest.raises(
        GenerationError,
        match=f"^{_PRIVACY_CLAIM_EVIDENCE_ERROR}: {unverified.job_id}$",
    ):
        claim(
            service,
            adapter,
            output,
            unverified.job_id,
            "attempt-unverified-privacy",
            None,
        )
    _assert_claim_refusal_preserved_state(service, unverified.job_id)

    unverified_json = json.dumps(
        service.get_provenance(unverified.job_id)["privacy_compliance"],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    with pytest.raises(GenerationError) as raised:
        claim(
            service,
            adapter,
            output,
            unverified.job_id,
            "attempt-unverified-wrong-configuration",
            unverified_json,
            configuration={**adapter.configuration, "configuration_version": 2},
        )
    assert str(raised.value) == (
        f"{_PRIVACY_CLAIM_CONFIGURATION_ERROR}: {unverified.job_id}"
    )
    _assert_claim_refusal_preserved_state(service, unverified.job_id)

    unverified_claim = claim(
        service,
        adapter,
        output,
        unverified.job_id,
        "attempt-unverified-privacy",
        unverified_json,
    )
    assert unverified_claim is not None
    assert unverified_claim.job_id == unverified.job_id

    with pytest.raises(
        GenerationError,
        match=f"^{_PRIVACY_CLAIM_EVIDENCE_ERROR}: {passed_job.job_id}$",
    ):
        claim(
            passed,
            passed_adapter,
            passed_output,
            passed_job.job_id,
            "attempt-pass-without-evidence",
            None,
        )
    _assert_claim_refusal_preserved_state(passed, passed_job.job_id)

    with pytest.raises(GenerationError) as raised:
        claim(
            passed,
            passed_adapter,
            passed_output,
            passed_job.job_id,
            "attempt-pass-wrong-configuration",
            passed_json,
            configuration={
                **passed_adapter.configuration,
                "configuration_version": 2,
            },
        )
    assert str(raised.value) == (
        f"{_PRIVACY_CLAIM_CONFIGURATION_ERROR}: {passed_job.job_id}"
    )
    _assert_claim_refusal_preserved_state(passed, passed_job.job_id)

    passed_with_exact_evidence = claim(
        passed,
        passed_adapter,
        passed_output,
        passed_job.job_id,
        "attempt-pass-with-exact-evidence",
        passed_json,
    )
    assert passed_with_exact_evidence is not None
    assert passed_with_exact_evidence.job_id == passed_job.job_id


@pytest.mark.parametrize(
    "invalid_evidence",
    ("{malformed", '{"status":"unknown"}'),
    ids=("malformed-json", "unknown-record"),
)
def test_omitted_privacy_claim_rejects_invalid_stored_evidence(
    tmp_path: Path,
    invalid_evidence: str,
) -> None:
    adapter = DeterministicCpuAdapter()
    output = tmp_path / "images"
    service = GenerationService(tmp_path / "studio.sqlite3", output, adapter=adapter)
    queued = service.enqueue("invalid-evidence", _request())
    _, _, _, caller_evidence_json = service._current_privacy_snapshot()
    with service._store._connection(transaction=True) as connection:
        connection.execute(
            "UPDATE execution_jobs SET privacy_compliance_json = ? WHERE job_id = ?",
            (invalid_evidence, queued.job_id),
        )
    containment_contract = trusted_containment_contract(adapter)

    with pytest.raises(
        GenerationError,
        match="^stored privacy-compliance evidence is malformed$",
    ) as raised:
        service._store.claim_next_execution(
            attempt_id="attempt-invalid-privacy",
            owner_id="privacy-invalid-worker",
            adapter_id=adapter.adapter_id,
            adapter_configuration_json=json.dumps(
                adapter.configuration,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            resolved_output_directory=str(output),
            process_contained=containment_contract is not None,
            containment_contract=containment_contract,
            timestamp="2026-10-26T00:00:00+00:00",
            lease_expires_at="2026-10-26T00:01:00+00:00",
        privacy_compliance_json=caller_evidence_json,
            job_id=queued.job_id,
        allow_not_required=True,
        )

    assert invalid_evidence not in str(raised.value)
    assert invalid_evidence not in repr(raised.value)
    with service._store._connection() as connection:
        execution = connection.execute(
            """SELECT status, current_attempt_id, privacy_compliance_json
               FROM execution_jobs WHERE job_id = ?""",
            (queued.job_id,),
        ).fetchone()
        assert execution is not None
        assert execution["status"] == "queued"
        assert execution["current_attempt_id"] is None
        assert execution["privacy_compliance_json"] == invalid_evidence

        attempt_count = connection.execute(
            "SELECT count(*) FROM execution_attempts WHERE job_id = ?",
            (queued.job_id,),
        ).fetchone()[0]
        assert attempt_count == 0

        resource = connection.execute(
            "SELECT state, job_id, attempt_id FROM execution_resource WHERE id = 1"
        ).fetchone()
        assert resource is not None
        assert resource["state"] == "available"
        assert resource["job_id"] is None
        assert resource["attempt_id"] is None

    _assert_claim_refusal_preserved_state(service, queued.job_id)


def test_unverified_caller_cannot_store_null_evidence_without_fallback(
    tmp_path: Path,
) -> None:
    """SQLite rejects unrecorded fallback storage without changing execution state."""
    adapter = DeterministicCpuAdapter()
    output = tmp_path / "images"
    service = GenerationService(tmp_path / "studio.sqlite3", output, adapter=adapter)
    queued = service.enqueue("unverified-no-fallback", _request())
    caller_evidence = service.get_provenance(queued.job_id)["privacy_compliance"]
    assert caller_evidence["status"] == "unverified"
    evidence_json = json.dumps(
        caller_evidence,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    before = _execution_state_snapshot(service, queued.job_id)

    with pytest.raises(sqlite3.IntegrityError, match="NOT NULL"):
        with service._store._connection(transaction=True) as connection:
            connection.execute(
                "UPDATE execution_jobs SET privacy_compliance_json = NULL WHERE job_id = ?",
                (queued.job_id,),
            )

    assert _execution_state_snapshot(service, queued.job_id) == before
    assert before["execution"]["privacy_compliance_json"] == evidence_json
    containment_contract = trusted_containment_contract(adapter)
    with pytest.raises(
        GenerationError,
        match=f"^{_PRIVACY_CLAIM_EVIDENCE_ERROR}: {queued.job_id}$",
    ):
        service._store.claim_next_execution(
            attempt_id="attempt-unverified-no-fallback",
            owner_id="privacy-no-fallback-worker",
            adapter_id=adapter.adapter_id,
            adapter_configuration_json=json.dumps(
                adapter.configuration,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            resolved_output_directory=str(output),
            process_contained=containment_contract is not None,
            containment_contract=containment_contract,
            timestamp="2026-10-26T00:00:00+00:00",
            lease_expires_at="2026-10-26T00:01:00+00:00",
            privacy_compliance_json=None,
            allow_not_required=True,
            job_id=queued.job_id,
        )

    _assert_claim_refusal_preserved_state(service, queued.job_id)
    claim = service._store.claim_next_execution(
        attempt_id="attempt-unverified-exact-evidence",
        owner_id="privacy-exact-evidence-worker",
        adapter_id=adapter.adapter_id,
        adapter_configuration_json=json.dumps(
            adapter.configuration,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        resolved_output_directory=str(output),
        process_contained=containment_contract is not None,
        containment_contract=containment_contract,
        timestamp="2026-10-26T00:00:00+00:00",
        lease_expires_at="2026-10-26T00:01:00+00:00",
        privacy_compliance_json=evidence_json,
        allow_not_required=True,
        job_id=queued.job_id,
    )
    assert claim is not None
    assert claim.job_id == queued.job_id


@pytest.mark.parametrize(
    "caller_evidence",
    (
        "{malformed",
        json.dumps({**_policy().evaluate(
            FIXTURE_ADAPTER_ID,
            _compliant_configuration(),
        ).to_json_result(), "status": "unknown"}),
        _policy().evaluate(
            "different-adapter",
            _compliant_configuration(),
        ).to_json(),
    ),
    ids=("malformed-json", "unknown-status", "wrong-adapter"),
)
def test_invalid_caller_privacy_evidence_is_rejected_before_claim(
    tmp_path: Path,
    caller_evidence: str,
) -> None:
    adapter = DeterministicCpuAdapter()
    output = tmp_path / "images"
    service = GenerationService(tmp_path / "studio.sqlite3", output, adapter=adapter)
    queued = service.enqueue("invalid-caller-evidence", _request())
    containment_contract = trusted_containment_contract(adapter)

    with pytest.raises(ValueError):
        service._store.claim_next_execution(
            attempt_id="attempt-invalid-caller-evidence",
            owner_id="privacy-invalid-caller-worker",
            adapter_id=adapter.adapter_id,
            adapter_configuration_json=json.dumps(
                adapter.configuration,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            resolved_output_directory=str(output),
            process_contained=containment_contract is not None,
            containment_contract=containment_contract,
            timestamp="2026-10-26T00:00:00+00:00",
            lease_expires_at="2026-10-26T00:01:00+00:00",
            privacy_compliance_json=caller_evidence,
            allow_not_required=True,
            job_id=queued.job_id,
        )

    assert service.get_provenance(queued.job_id)["status"] == "queued"


def test_pass_evidence_requires_exact_non_null_claim(tmp_path: Path) -> None:
    """Stored pass evidence cannot be nulled or substituted at claim time."""
    adapter = _FixturePrivacyAdapter(_compliant_configuration())
    admission_profile = _heavyweight_profile()
    demand = _heavyweight_demand()
    output = tmp_path / "images"
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        output,
        adapter=adapter,
        privacy_policy=_policy(),
        require_privacy_pass=True,
        admission_profile=admission_profile,
    )
    queued = service.enqueue("pass-fallback", _request(), workload_demand=demand)
    evidence = service.get_provenance(queued.job_id)["privacy_compliance"]
    evidence_json = json.dumps(
        evidence,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    before = _execution_state_snapshot(service, queued.job_id)

    with pytest.raises(sqlite3.IntegrityError, match="NOT NULL"):
        with service._store._connection(transaction=True) as connection:
            connection.execute(
                "UPDATE execution_jobs SET privacy_compliance_json = NULL WHERE job_id = ?",
                (queued.job_id,),
            )

    assert _execution_state_snapshot(service, queued.job_id) == before
    assert before["execution"]["privacy_compliance_json"] == evidence_json
    containment_contract = trusted_containment_contract(adapter)
    with pytest.raises(
        GenerationError,
        match=f"^{_PRIVACY_CLAIM_EVIDENCE_ERROR}: {queued.job_id}$",
    ):
        service._store.claim_next_execution(
            attempt_id="attempt-pass-null-evidence",
            owner_id="privacy-pass-null-worker",
            adapter_id=adapter.adapter_id,
            adapter_configuration_json=json.dumps(
                adapter.configuration,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            resolved_output_directory=str(output),
            process_contained=containment_contract is not None,
            containment_contract=containment_contract,
            timestamp="2026-10-26T00:00:00+00:00",
            lease_expires_at="2026-10-26T00:01:00+00:00",
            privacy_compliance_json=None,
            job_id=queued.job_id,
        )

    _assert_claim_refusal_preserved_state(service, queued.job_id)
    claim = service._store.claim_next_execution(
        attempt_id="attempt-pass-exact-evidence",
        owner_id="privacy-pass-exact-worker",
        adapter_id=adapter.adapter_id,
        adapter_configuration_json=json.dumps(
            adapter.configuration,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        resolved_output_directory=str(output),
        process_contained=containment_contract is not None,
        containment_contract=containment_contract,
        timestamp="2026-10-26T00:00:00+00:00",
        lease_expires_at="2026-10-26T00:01:00+00:00",
        privacy_compliance_json=evidence_json,
        job_id=queued.job_id,
    )
    assert claim is not None
    assert claim.job_id == queued.job_id


def test_unverified_evidence_requires_exact_non_null_caller_evidence(
    tmp_path: Path,
) -> None:
    """Unverified evidence still requires a current non-null caller record."""
    adapter = DeterministicCpuAdapter()
    output = tmp_path / "images"
    service = GenerationService(tmp_path / "studio.sqlite3", output, adapter=adapter)
    queued = service.enqueue("unverified-fallback", _request())
    evidence = service.get_provenance(queued.job_id)["privacy_compliance"]
    evidence_json = json.dumps(
        evidence,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    before = _execution_state_snapshot(service, queued.job_id)

    with pytest.raises(sqlite3.IntegrityError, match="NOT NULL"):
        with service._store._connection(transaction=True) as connection:
            connection.execute(
                "UPDATE execution_jobs SET privacy_compliance_json = NULL WHERE job_id = ?",
                (queued.job_id,),
            )

    assert _execution_state_snapshot(service, queued.job_id) == before
    containment_contract = trusted_containment_contract(adapter)
    claim_kwargs = {
        "attempt_id": "attempt-unverified-null-evidence",
        "owner_id": "privacy-unverified-null-worker",
        "adapter_id": adapter.adapter_id,
        "adapter_configuration_json": json.dumps(
            adapter.configuration,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        "resolved_output_directory": str(output),
        "process_contained": containment_contract is not None,
        "containment_contract": containment_contract,
        "timestamp": "2026-10-26T00:00:00+00:00",
        "lease_expires_at": "2026-10-26T00:01:00+00:00",
        "allow_not_required": True,
        "job_id": queued.job_id,
    }
    with pytest.raises(
        GenerationError,
        match=f"^{_PRIVACY_CLAIM_EVIDENCE_ERROR}: {queued.job_id}$",
    ):
        service._store.claim_next_execution(**claim_kwargs)
    _assert_claim_refusal_preserved_state(service, queued.job_id)
    with pytest.raises(
        GenerationError,
        match=f"^{_PRIVACY_CLAIM_EVIDENCE_ERROR}: {queued.job_id}$",
    ):
        service._store.claim_next_execution(
            **claim_kwargs,
            privacy_compliance_json=None,
        )
    _assert_claim_refusal_preserved_state(service, queued.job_id)

    claim = service._store.claim_next_execution(
        **claim_kwargs,
        privacy_compliance_json=evidence_json,
    )
    assert claim is not None
    assert claim.job_id == queued.job_id
def test_worker_reevaluates_current_settings_before_claim(tmp_path: Path) -> None:
    adapter = _FixturePrivacyAdapter(_compliant_configuration())
    admission_profile = _heavyweight_profile()
    demand = _heavyweight_demand()
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        adapter=adapter,
        privacy_policy=_policy(),
        require_privacy_pass=True,
        admission_profile=admission_profile,
    )
    queued = service.enqueue(
        "changed-before-work", _request("changed"), workload_demand=demand
    )
    adapter.set_control(PrivacyControl.TELEMETRY, True)

    with pytest.raises(PrivacyComplianceError, match="fail"):
        service.work(limit=1)

    assert service.get_provenance(queued.job_id)["status"] == "queued"


def test_result_serialization_is_canonical_and_json_compatible() -> None:
    result = _policy().evaluate(FIXTURE_ADAPTER_ID, _compliant_configuration())

    encoded = result.to_json()

    assert encoded == json.dumps(
        result.to_json_result(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    assert json.loads(encoded)["status"] == "pass"


def test_stored_result_fingerprint_detects_tampering() -> None:
    payload = _policy().evaluate(
        FIXTURE_ADAPTER_ID,
        _compliant_configuration(),
    ).to_json_result()
    tampered = dict(payload)
    tampered["status"] = "fail"

    assert is_privacy_compliance_record(payload)
    assert not is_privacy_compliance_record(tampered)


def _rehash_privacy_record(record: dict[str, object]) -> dict[str, object]:
    """Recompute a record digest independently of the production validator."""
    payload = {key: item for key, item in record.items() if key != "fingerprint"}
    fingerprint = hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    return {**payload, "fingerprint": fingerprint}


def test_stored_result_validation_accepts_expected_result_forms() -> None:
    records = (
        _policy()
        .evaluate(FIXTURE_ADAPTER_ID, _compliant_configuration())
        .to_json_result(),
        _policy()
        .evaluate(
            "unregistered-adapter",
            _compliant_configuration(configuration_version="release-7"),
        )
        .to_json_result(),
        historical_privacy_compliance(FIXTURE_ADAPTER_ID).to_json_result(),
        DEFAULT_PRIVACY_POLICY.evaluate(
            DeterministicCpuAdapter().adapter_id,
            DeterministicCpuAdapter().configuration,
        ).to_json_result(),
    )

    assert all(is_privacy_compliance_record(record) for record in records)


def test_stored_result_validation_rejects_invalid_fields_with_valid_digest() -> None:
    valid = _policy().evaluate(
        FIXTURE_ADAPTER_ID,
        _compliant_configuration(),
    ).to_json_result()
    missing_profile_id = json.loads(json.dumps(valid))
    missing_profile_id.pop("profile_id")
    invalid_profile_version = json.loads(json.dumps(valid))
    invalid_profile_version["profile_version"] = True
    missing_control_field = json.loads(json.dumps(valid))
    missing_control_field["controls"][0].pop("reason_code")
    invalid_configuration_version = json.loads(json.dumps(valid))
    invalid_configuration_version["configuration_version"] = {"unexpected": True}
    missing_reasons = json.loads(json.dumps(valid))
    missing_reasons.pop("reasons")
    invalid_reason_code = json.loads(json.dumps(valid))
    invalid_reason_code["reasons"][0]["code"] = "unexpected_reason"
    missing_limitations = json.loads(json.dumps(valid))
    missing_limitations.pop("limitations")

    malformed_records = (
        missing_profile_id,
        invalid_profile_version,
        missing_control_field,
        invalid_configuration_version,
        missing_reasons,
        invalid_reason_code,
        missing_limitations,
    )

    assert all(
        not is_privacy_compliance_record(_rehash_privacy_record(record))
        for record in malformed_records
    )


@pytest.mark.parametrize("status", ("fail", "unverified"))
def test_stored_result_validation_rejects_rehashed_non_pass_status_with_pass_shape(
    status: str,
) -> None:
    record = _policy().evaluate(
        FIXTURE_ADAPTER_ID,
        _compliant_configuration(),
    ).to_json_result()
    record["status"] = status

    assert not is_privacy_compliance_record(_rehash_privacy_record(record))


@pytest.mark.parametrize("status", ("fail", "unverified"))
def test_stored_result_validation_rejects_orphaned_control_reason_with_valid_digest(
    status: str,
) -> None:
    configuration = _compliant_configuration()
    inference = configuration["inference"]
    assert isinstance(inference, dict)
    if status == "fail":
        inference[PrivacyControl.TELEMETRY.value] = True
    else:
        del inference[PrivacyControl.TELEMETRY.value]
    record = _policy().evaluate(FIXTURE_ADAPTER_ID, configuration).to_json_result()
    assert record["status"] == status
    record["controls"] = []

    assert not is_privacy_compliance_record(_rehash_privacy_record(record))


def test_unprofiled_unverified_record_preserves_observed_configuration_version() -> None:
    record = _policy().evaluate(
        "unregistered-adapter",
        _compliant_configuration(configuration_version="release-7"),
    ).to_json_result()

    assert record["status"] == "unverified"
    assert record["configuration_version"] == "release-7"
    assert is_privacy_compliance_record(record)


def test_worker_rechecks_privacy_before_each_claim_in_batch(
    tmp_path: Path,
) -> None:
    adapter = _FixturePrivacyAdapter(_compliant_configuration())
    admission_profile = _heavyweight_profile()
    demand = _heavyweight_demand()

    class _ConfigurationChangingService(GenerationService):
        def _execute_claim(self, *args: object, **kwargs: object) -> object:
            result = super()._execute_claim(*args, **kwargs)
            assert self._store.resource_snapshot()["state"] == "available"
            adapter.set_control(PrivacyControl.TELEMETRY, True)
            return result

    service = _ConfigurationChangingService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        adapter=adapter,
        privacy_policy=_policy(),
        require_privacy_pass=True,
        admission_profile=admission_profile,
    )
    first = service.enqueue(
        "batch-first", _request("batch-first"), workload_demand=demand
    )
    second = service.enqueue(
        "batch-second", _request("batch-second"), workload_demand=demand
    )

    with pytest.raises(PrivacyComplianceError):
        service.work(limit=2)

    assert service.get_provenance(first.job_id)["status"] == "succeeded"
    assert service.get_provenance(second.job_id)["status"] == "queued"
