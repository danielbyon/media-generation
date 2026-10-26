"""Versioned, configuration-only privacy checks for inference adapters."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import Enum


PRIVACY_PROFILE_SCHEMA_VERSION = "local-inference-privacy-profile/v1"
PRIVACY_RESULT_SCHEMA_VERSION = "local-inference-privacy-result/v1"
ASSURANCE_SCOPE = "configuration-compliance-only"

_MISSING = object()
_SELF_ATTESTATION_KEYS = {
    "configuration_compliance",
    "local_only",
    "local_only_attestation",
    "privacy_compliance",
    "privacy_pass",
    "privacy_status",
}
_ACQUISITION_ROOTS = {"acquisition", "acquisition_configuration", "model_acquisition"}
_CREDENTIAL_KEYS = {
    "api_key",
    "authorization",
    "bearer_token",
    "client_secret",
    "cookie",
    "credential",
    "credentials",
    "password",
    "passphrase",
    "private_key",
    "refresh_token",
    "secret",
    "token",
}
_CREDENTIAL_SUFFIXES = (
    "_api_key",
    "_authorization",
    "_cookie",
    "_credential",
    "_credentials",
    "_password",
    "_passphrase",
    "_private_key",
    "_secret",
    "_token",
)
_CREDENTIAL_COMPACT_KEYS = frozenset(key.replace("_", "") for key in _CREDENTIAL_KEYS)
_CREDENTIAL_COMPACT_SUFFIXES = tuple(
    suffix.removeprefix("_") for suffix in _CREDENTIAL_SUFFIXES
)
_ACQUISITION_COMPACT_ROOTS = frozenset(
    key.replace("_", "") for key in _ACQUISITION_ROOTS
)
_SELF_ATTESTATION_COMPACT_KEYS = frozenset(
    key.replace("_", "") for key in _SELF_ATTESTATION_KEYS
)
_LIMITATIONS = [
    "Configuration evidence does not prove network isolation or rule out unobserved outbound connections.",
    "Configuration evidence does not establish hardware or APEX qualification.",
]


class PrivacyComplianceStatus(str, Enum):
    """Configuration verdict."""

    PASS = "pass"
    FAIL = "fail"
    UNVERIFIED = "unverified"


class PrivacyControl(str, Enum):
    """Remote-behavior controls required by a local-only profile."""

    EXTERNAL_API = "external_api"
    CLOUD_INFERENCE = "cloud_inference"
    TELEMETRY = "telemetry"
    CONTENT_UPLOAD = "content_upload"
    AUTOMATIC_NETWORK_FETCH_OR_UPDATE = "automatic_network_fetch_or_update"
    REMOTE_ENDPOINT_OR_PROXY = "remote_endpoint_or_proxy"
    CLOUD_FALLBACK = "cloud_fallback"


@dataclass(frozen=True, slots=True)
class PrivacySettingRule:
    """One required setting and its known prohibited values."""

    control: PrivacyControl
    path: tuple[str, ...]
    expected: bool | int | str | None
    prohibited: tuple[bool | int | str | None, ...]

    def __post_init__(self) -> None:
        prohibited = tuple(self.prohibited)
        if not isinstance(self.control, PrivacyControl):
            raise ValueError("privacy setting control must be recognized")
        if not isinstance(self.path, tuple) or not self.path or any(
            not isinstance(part, str) or not part for part in self.path
        ):
            raise ValueError("privacy setting path must contain non-empty names")
        if not _is_json_scalar(self.expected):
            raise ValueError("privacy setting expectation must be a JSON scalar")
        if not prohibited or any(not _is_json_scalar(value) for value in prohibited):
            raise ValueError("privacy setting rule must declare JSON-scalar prohibited values")
        if any(_same_json_scalar(self.expected, value) for value in prohibited):
            raise ValueError("privacy expected and prohibited values must not overlap")
        object.__setattr__(self, "prohibited", prohibited)

    def to_dict(self) -> dict[str, object]:
        return {
            "control": self.control.value,
            "path": list(self.path),
            "expected": self.expected,
            "prohibited": list(self.prohibited),
        }


@dataclass(frozen=True, slots=True)
class PrivacyProfile:
    """Exact adapter, tool, version, and local-only setting contract.

    Each supported privacy control must use a distinct configuration path so
    evidence for one control cannot substitute for another control's evidence.
    """

    schema_version: str
    profile_id: str
    profile_version: int
    adapter_id: str
    tool_id: str
    tool_version: str
    configuration_version: bool | int | str
    requirements: tuple[PrivacySettingRule, ...]
    supports_configuration_compliance: bool

    def __post_init__(self) -> None:
        if self.schema_version != PRIVACY_PROFILE_SCHEMA_VERSION:
            raise ValueError("unsupported privacy profile schema version")
        if type(self.supports_configuration_compliance) is not bool:
            raise ValueError(
                "supports_configuration_compliance must be a boolean"
            )
        for name, value in (
            ("profile_id", self.profile_id),
            ("adapter_id", self.adapter_id),
            ("tool_id", self.tool_id),
            ("tool_version", self.tool_version),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if isinstance(self.profile_version, bool) or not isinstance(
            self.profile_version, int
        ) or self.profile_version < 1:
            raise ValueError("profile_version must be a positive integer")
        if self.configuration_version is None or not _is_json_scalar(
            self.configuration_version
        ):
            raise ValueError("configuration_version must be a non-null JSON scalar")
        requirements = tuple(self.requirements)
        if any(not isinstance(rule, PrivacySettingRule) for rule in requirements):
            raise ValueError("privacy requirements must be PrivacySettingRule values")
        controls = [rule.control for rule in requirements]
        if self.supports_configuration_compliance and (
            len(controls) != len(PrivacyControl) or set(controls) != set(PrivacyControl)
        ):
            raise ValueError("profile must define each supported privacy control once")
        if len(controls) != len(set(controls)):
            raise ValueError("profile must define each supported privacy control once")
        if len(requirements) != len({rule.path for rule in requirements}):
            raise ValueError("privacy controls must use distinct configuration paths")
        if not self.supports_configuration_compliance and requirements:
            raise ValueError("unqualified profiles cannot declare privacy controls")
        if any(
            _is_sensitive_name(part) or _is_self_attestation_name(part)
            for rule in requirements
            for part in rule.path
        ):
            raise ValueError("privacy paths cannot contain credentials or untrusted claims")
        order = {control: index for index, control in enumerate(PrivacyControl)}
        object.__setattr__(
            self,
            "requirements",
            tuple(sorted(requirements, key=lambda rule: order[rule.control])),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "adapter_id": self.adapter_id,
            "tool_id": self.tool_id,
            "tool_version": self.tool_version,
            "configuration_version": self.configuration_version,
            "requirements": [rule.to_dict() for rule in self.requirements],
            "supports_configuration_compliance": self.supports_configuration_compliance,
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self.to_dict())


@dataclass(frozen=True, slots=True)
class PrivacyComplianceResult:
    """Redacted, versioned evidence for one exact configuration."""

    status: PrivacyComplianceStatus
    adapter_id: str
    configuration_version: object
    configuration_fingerprint: str | None
    profile_id: str | None
    profile_version: int | None
    profile_fingerprint: str | None
    tool_id: str | None
    tool_version: str | None
    supports_configuration_compliance: bool
    controls: tuple[dict[str, object], ...]
    reasons: tuple[dict[str, str], ...]

    @property
    def reason_codes(self) -> frozenset[str]:
        return frozenset(reason["code"] for reason in self.reasons)

    def _payload(self) -> dict[str, object]:
        return {
            "schema_version": PRIVACY_RESULT_SCHEMA_VERSION,
            "status": self.status.value,
            "assurance_scope": ASSURANCE_SCOPE,
            "evidence_source": "application-owned-profile",
            "profile_schema_version": PRIVACY_PROFILE_SCHEMA_VERSION,
            "adapter_id": self.adapter_id,
            "configuration_version": self.configuration_version,
            "configuration_fingerprint": self.configuration_fingerprint,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "profile_fingerprint": self.profile_fingerprint,
            "tool_id": self.tool_id,
            "tool_version": self.tool_version,
            "supports_configuration_compliance": self.supports_configuration_compliance,
            "controls": list(self.controls),
            "reasons": list(self.reasons),
            "limitations": list(_LIMITATIONS),
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self._payload())

    def to_json_result(self) -> dict[str, object]:
        payload = self._payload()
        payload["fingerprint"] = self.fingerprint
        return payload

    def to_dict(self) -> dict[str, object]:
        return self.to_json_result()

    def to_json(self) -> str:
        return _canonical_json(self.to_json_result())


_PRIVACY_RESULT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "assurance_scope",
        "evidence_source",
        "profile_schema_version",
        "adapter_id",
        "configuration_version",
        "configuration_fingerprint",
        "profile_id",
        "profile_version",
        "profile_fingerprint",
        "tool_id",
        "tool_version",
        "supports_configuration_compliance",
        "controls",
        "reasons",
        "limitations",
        "fingerprint",
    }
)
_PRIVACY_CONTROL_FIELDS = frozenset(
    {"control", "path", "status", "observed", "reason_code"}
)
_PRIVACY_REASON_FIELDS = frozenset({"code", "detail"})
_PRIVACY_REASON_CODES = frozenset(
    {
        "acquisition_configuration_present",
        "all_required_settings_verified",
        "configuration_not_json",
        "configuration_not_json_object",
        "configuration_version_mismatch",
        "credential_material_present",
        "historical_record_unverified",
        "profile_not_found",
        "prohibited_setting_enabled",
        "setting_matches_requirement",
        "setting_missing",
        "setting_value_unrecognized",
        "unqualified_configuration",
        "untrusted_self_attestation",
    }
)
_PRIVACY_CONTROL_REASON_CODES = frozenset(
    {
        "prohibited_setting_enabled",
        "setting_missing",
        "setting_value_unrecognized",
    }
)
_PRIVACY_CONTEXT_REASON_CODES = frozenset(
    {
        "configuration_not_json",
        "configuration_not_json_object",
        "configuration_version_mismatch",
        "historical_record_unverified",
        "profile_not_found",
        "unqualified_configuration",
    }
)
_PRIVACY_DIAGNOSTIC_REASON_CODES = frozenset(
    {
        "acquisition_configuration_present",
        "credential_material_present",
        "untrusted_self_attestation",
    }
)
_PRIVACY_GLOBAL_REASON_DETAILS = {
    "acquisition_configuration_present": (
        "Model acquisition settings must remain separate from inference."
    ),
    "all_required_settings_verified": (
        "Every declared local-only setting matched its required value."
    ),
    "configuration_not_json": "Configuration is not valid JSON.",
    "configuration_not_json_object": "Configuration is not an object.",
    "configuration_version_mismatch": (
        "No application-owned profile matches this adapter and configuration version."
    ),
    "credential_material_present": (
        "Credentials must remain outside runtime inference settings."
    ),
    "historical_record_unverified": (
        "Job predates privacy evidence and remains unverified."
    ),
    "profile_not_found": (
        "No application-owned profile matches this adapter and configuration version."
    ),
    "unqualified_configuration": (
        "This profile cannot establish real inference-tool privacy."
    ),
    "untrusted_self_attestation": (
        "Adapter-provided compliance claims are not trusted."
    ),
}


def _is_sha256_hex(value: object) -> bool:
    """Return whether a value is a canonical SHA-256 hexadecimal digest."""
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_valid_privacy_control_record(value: object) -> bool:
    """Validate one serialized privacy-control assessment."""
    if not isinstance(value, dict) or set(value) != _PRIVACY_CONTROL_FIELDS:
        return False
    control = value["control"]
    path = value["path"]
    status = value["status"]
    observed = value["observed"]
    reason_code = value["reason_code"]
    if control not in {item.value for item in PrivacyControl}:
        return False
    if (
        not isinstance(path, list)
        or not path
        or any(not isinstance(part, str) or not part for part in path)
        or len(set(path)) != len(path)
        or any(
            _is_sensitive_name(part) or _is_self_attestation_name(part)
            for part in path
        )
    ):
        return False
    if status not in {item.value for item in PrivacyComplianceStatus}:
        return False
    if not _is_json_scalar(observed):
        return False
    if not isinstance(reason_code, str) or not reason_code:
        return False
    allowed_reason_codes = {
        "pass": {"setting_matches_requirement"},
        "fail": {"prohibited_setting_enabled"},
        "unverified": {"setting_missing", "setting_value_unrecognized"},
    }
    return reason_code in allowed_reason_codes[status]


def _is_valid_privacy_reason_record(value: object) -> bool:
    """Validate one serialized explanation attached to privacy evidence."""
    return (
        isinstance(value, dict)
        and set(value) == _PRIVACY_REASON_FIELDS
        and isinstance(value["code"], str)
        and value["code"] in _PRIVACY_REASON_CODES
        and isinstance(value["detail"], str)
        and bool(value["detail"])
    )


def _privacy_reason_counts(reasons: list[dict[str, object]]) -> Counter[str]:
    """Count serialized reason codes while preserving duplicate semantics."""
    return Counter(str(reason["code"]) for reason in reasons)


def _privacy_reason_evidence_is_consistent(
    controls: list[dict[str, object]],
    reasons: list[dict[str, object]],
) -> bool:
    """Match control failures to reasons and require canonical global text."""
    expected_control_reasons = Counter(
        (str(control["reason_code"]), _evidence_detail(control))
        for control in controls
        if control["status"] != PrivacyComplianceStatus.PASS.value
    )
    actual_control_reasons = Counter(
        (str(reason["code"]), str(reason["detail"]))
        for reason in reasons
        if reason["code"] in _PRIVACY_CONTROL_REASON_CODES
    )
    if actual_control_reasons != expected_control_reasons:
        return False
    return all(
        str(reason["code"]) in _PRIVACY_CONTROL_REASON_CODES
        or _PRIVACY_GLOBAL_REASON_DETAILS.get(str(reason["code"]))
        == reason["detail"]
        for reason in reasons
    )


def is_privacy_compliance_record(value: object) -> bool:
    """Validate a versioned result and its internally consistent semantics.

    The fingerprint detects content changes. It does not authenticate who
    produced the record, because any caller can recompute it from the JSON.
    """
    if not isinstance(value, dict) or set(value) != _PRIVACY_RESULT_FIELDS:
        return False
    if (
        value["schema_version"] != PRIVACY_RESULT_SCHEMA_VERSION
        or value["status"]
        not in {status.value for status in PrivacyComplianceStatus}
        or value["assurance_scope"] != ASSURANCE_SCOPE
        or value["evidence_source"] != "application-owned-profile"
        or value["profile_schema_version"] != PRIVACY_PROFILE_SCHEMA_VERSION
        or not isinstance(value["adapter_id"], str)
        or not value["adapter_id"].strip()
        or not _is_json_scalar(value["configuration_version"])
        or not isinstance(value["supports_configuration_compliance"], bool)
        or not isinstance(value["controls"], list)
        or not isinstance(value["reasons"], list)
        or not value["reasons"]
        or value["limitations"] != list(_LIMITATIONS)
    ):
        return False
    configuration_fingerprint = value["configuration_fingerprint"]
    if configuration_fingerprint is not None and not _is_sha256_hex(
        configuration_fingerprint
    ):
        return False
    profile_values = (
        value["profile_id"],
        value["profile_version"],
        value["profile_fingerprint"],
        value["tool_id"],
        value["tool_version"],
    )
    profile_present = all(item is not None for item in profile_values)
    profile_absent = all(item is None for item in profile_values)
    if not (profile_present or profile_absent):
        return False
    if not profile_present and (
        value["supports_configuration_compliance"] or value["controls"]
    ):
        return False
    if profile_present:
        profile_id = value["profile_id"]
        profile_version = value["profile_version"]
        tool_id = value["tool_id"]
        tool_version = value["tool_version"]
        if (
            not isinstance(profile_id, str)
            or not profile_id.strip()
            or isinstance(profile_version, bool)
            or not isinstance(profile_version, int)
            or profile_version < 1
            or not _is_sha256_hex(value["profile_fingerprint"])
            or not isinstance(tool_id, str)
            or not tool_id.strip()
            or not isinstance(tool_version, str)
            or not tool_version.strip()
        ):
            return False
    if not value["supports_configuration_compliance"] and value["controls"]:
        return False
    if any(not _is_valid_privacy_control_record(item) for item in value["controls"]):
        return False
    if len({item["control"] for item in value["controls"]}) != len(value["controls"]):
        return False
    if not all(_is_valid_privacy_reason_record(item) for item in value["reasons"]):
        return False
    controls = value["controls"]
    reasons = value["reasons"]
    reason_counts = _privacy_reason_counts(reasons)
    if not _privacy_reason_evidence_is_consistent(controls, reasons):
        return False

    has_full_controls = bool(controls)
    if has_full_controls and (
        not profile_present
        or not value["supports_configuration_compliance"]
        or {item["control"] for item in controls}
        != {control.value for control in PrivacyControl}
    ):
        return False

    context_reason_count = sum(
        reason_counts[code] for code in _PRIVACY_CONTEXT_REASON_CODES
    )
    if context_reason_count > 1:
        return False
    if any(
        reason_counts[code] > 1 for code in _PRIVACY_DIAGNOSTIC_REASON_CODES
    ):
        return False
    pass_reason_count = reason_counts["all_required_settings_verified"]
    if pass_reason_count > 1:
        return False
    if has_full_controls:
        if context_reason_count:
            return False
    elif pass_reason_count or context_reason_count != 1:
        return False

    if profile_present:
        if any(
            reason_counts[code]
            for code in {
                "configuration_not_json",
                "configuration_not_json_object",
                "historical_record_unverified",
                "profile_not_found",
            }
        ):
            return False
        if value["supports_configuration_compliance"]:
            if (
                not has_full_controls
                and reason_counts["configuration_version_mismatch"] != 1
            ):
                return False
        elif not any(
            reason_counts[code]
            for code in {
                "configuration_version_mismatch",
                "unqualified_configuration",
            }
        ):
            return False
    else:
        if any(
            reason_counts[code]
            for code in {
                "configuration_version_mismatch",
                "unqualified_configuration",
            }
        ):
            return False
        if not any(
            reason_counts[code]
            for code in {
                "configuration_not_json",
                "configuration_not_json_object",
                "historical_record_unverified",
                "profile_not_found",
            }
        ):
            return False

    no_fingerprint_expected = bool(
        reason_counts["configuration_not_json"]
        or reason_counts["historical_record_unverified"]
    )
    if (value["configuration_fingerprint"] is None) != no_fingerprint_expected:
        return False
    if (
        reason_counts["configuration_not_json"]
        or reason_counts["configuration_not_json_object"]
        or reason_counts["historical_record_unverified"]
    ) and value["configuration_version"] is not None:
        return False
    if has_full_controls and value["configuration_version"] is None:
        return False
    if (
        reason_counts["unqualified_configuration"]
        and value["configuration_version"] is None
    ):
        return False

    has_global_failure = bool(
        reason_counts["credential_material_present"]
        or reason_counts["acquisition_configuration_present"]
    )
    has_control_failure = any(
        item["status"] == PrivacyComplianceStatus.FAIL.value
        for item in controls
    )
    if value["status"] == PrivacyComplianceStatus.PASS.value:
        if (
            not has_full_controls
            or not value["supports_configuration_compliance"]
            or any(
                item["status"] != PrivacyComplianceStatus.PASS.value
                for item in controls
            )
            or len(reasons) != 1
            or reasons[0]["code"] != "all_required_settings_verified"
        ):
            return False
    elif value["status"] == PrivacyComplianceStatus.FAIL.value:
        if pass_reason_count or not (has_global_failure or has_control_failure):
            return False
    elif pass_reason_count or has_global_failure or has_control_failure:
        return False
    if value["status"] == PrivacyComplianceStatus.PASS.value:
        if (
            not profile_present
            or not value["supports_configuration_compliance"]
            or {item["control"] for item in value["controls"]}
            != {item.value for item in PrivacyControl}
            or any(item["status"] != "pass" for item in value["controls"])
            or {item["code"] for item in value["reasons"]}
            != {"all_required_settings_verified"}
        ):
            return False
    try:
        return (
            _digest(
                {key: item for key, item in value.items() if key != "fingerprint"}
            )
            == value["fingerprint"]
        )
    except (TypeError, ValueError):
        return False


class PrivacyCompliancePolicy:
    """Application-owned profiles used to evaluate adapter settings."""

    def __init__(self, profiles: Iterable[PrivacyProfile]) -> None:
        frozen = tuple(profiles)
        if not frozen or any(not isinstance(profile, PrivacyProfile) for profile in frozen):
            raise ValueError("privacy policy requires PrivacyProfile values")
        bindings = {
            _canonical_json([profile.adapter_id, profile.configuration_version])
            for profile in frozen
        }
        identities = {(profile.profile_id, profile.profile_version) for profile in frozen}
        if len(bindings) != len(frozen):
            raise ValueError(
                "privacy profiles must have unique adapter and configuration bindings"
            )
        if len(identities) != len(frozen):
            raise ValueError("privacy profiles must have unique identities")
        self._profiles = frozen

    @property
    def profiles(self) -> tuple[PrivacyProfile, ...]:
        return self._profiles

    def evaluate(
        self,
        adapter_id: str,
        configuration: Mapping[str, object],
    ) -> PrivacyComplianceResult:
        """Compare effective settings with one exact application-owned profile."""
        reasons: list[dict[str, str]] = []
        if _contains_sensitive_key(configuration):
            reasons.append(
                _reason(
                    "credential_material_present",
                    "Credentials must remain outside runtime inference settings.",
                )
            )
        if _contains_acquisition_configuration(configuration):
            reasons.append(
                _reason(
                    "acquisition_configuration_present",
                    "Model acquisition settings must remain separate from inference.",
                )
            )
        if _contains_self_attestation(configuration):
            reasons.append(
                _reason(
                    "untrusted_self_attestation",
                    "Adapter-provided compliance claims are not trusted.",
                )
            )
        try:
            configuration_json = _canonical_json(configuration)
            configuration_payload = json.loads(configuration_json)
            configuration_fingerprint = hashlib.sha256(
                configuration_json.encode("utf-8")
            ).hexdigest()
        except (TypeError, ValueError):
            reasons.append(
                _reason("configuration_not_json", "Configuration is not valid JSON.")
            )
            return _build_result(
                PrivacyComplianceStatus.FAIL
                if any(
                    reason["code"]
                    in {
                        "credential_material_present",
                        "acquisition_configuration_present",
                    }
                    for reason in reasons
                )
                else PrivacyComplianceStatus.UNVERIFIED,
                adapter_id,
                None,
                None,
                None,
                (),
                reasons,
            )
        if not isinstance(configuration_payload, Mapping):
            reasons.append(
                _reason(
                    "configuration_not_json_object",
                    "Configuration is not an object.",
                )
            )
            return _build_result(
                PrivacyComplianceStatus.FAIL
                if any(
                    reason["code"]
                    in {
                        "credential_material_present",
                        "acquisition_configuration_present",
                    }
                    for reason in reasons
                )
                else PrivacyComplianceStatus.UNVERIFIED,
                adapter_id,
                None,
                configuration_fingerprint,
                None,
                (),
                reasons,
            )

        observed_version = configuration_payload.get("configuration_version", _MISSING)
        profile = next(
            (
                item
                for item in self._profiles
                if item.adapter_id == adapter_id
                and _same_json_scalar(item.configuration_version, observed_version)
            ),
            None,
        )
        adapter_profile = next(
            (item for item in self._profiles if item.adapter_id == adapter_id), None
        )
        global_failure = any(
            reason["code"]
            in {"credential_material_present", "acquisition_configuration_present"}
            for reason in reasons
        )
        reported_version = (
            None
            if observed_version is _MISSING
            else observed_version
            if _is_json_scalar(observed_version)
            else _redacted_observation(observed_version)
        )

        if profile is None:
            reasons.append(
                _reason(
                    "configuration_version_mismatch" if adapter_profile else "profile_not_found",
                    "No application-owned profile matches this adapter and configuration version.",
                )
            )
            return _build_result(
                PrivacyComplianceStatus.FAIL if global_failure else PrivacyComplianceStatus.UNVERIFIED,
                adapter_id,
                reported_version,
                configuration_fingerprint,
                adapter_profile,
                (),
                reasons,
            )
        if not profile.supports_configuration_compliance:
            reasons.append(
                _reason(
                    "unqualified_configuration",
                    "This profile cannot establish real inference-tool privacy.",
                )
            )
            return _build_result(
                PrivacyComplianceStatus.FAIL if global_failure else PrivacyComplianceStatus.UNVERIFIED,
                adapter_id,
                reported_version,
                configuration_fingerprint,
                profile,
                (),
                reasons,
            )

        controls = tuple(_evaluate_rule(configuration_payload, rule) for rule in profile.requirements)
        reasons.extend(
            _reason(item["reason_code"], _evidence_detail(item))
            for item in controls
            if item["status"] != PrivacyComplianceStatus.PASS.value
        )
        if global_failure or any(item["status"] == "fail" for item in controls):
            status = PrivacyComplianceStatus.FAIL
        elif reasons or any(item["status"] == "unverified" for item in controls):
            status = PrivacyComplianceStatus.UNVERIFIED
        else:
            status = PrivacyComplianceStatus.PASS
            reasons.append(
                _reason(
                    "all_required_settings_verified",
                    "Every declared local-only setting matched its required value.",
                )
            )
        return _build_result(
            status,
            adapter_id,
            reported_version,
            configuration_fingerprint,
            profile,
            controls,
            reasons,
        )


def historical_privacy_compliance(adapter_id: str) -> PrivacyComplianceResult:
    """Expose pre-v4 work as unverified without retrospective qualification."""
    return _unverified_without_profile(
        adapter_id,
        None,
        _reason(
            "historical_record_unverified",
            _PRIVACY_GLOBAL_REASON_DETAILS["historical_record_unverified"],
        ),
    )


def _evaluate_rule(
    configuration: Mapping[str, object], rule: PrivacySettingRule
) -> dict[str, object]:
    observed = _lookup(configuration, rule.path)
    if observed is _MISSING:
        status, value, code = "unverified", None, "setting_missing"
    elif _same_json_scalar(observed, rule.expected):
        status, value, code = "pass", observed, "setting_matches_requirement"
    elif any(_same_json_scalar(observed, item) for item in rule.prohibited):
        status, value, code = "fail", observed, "prohibited_setting_enabled"
    else:
        status, value, code = (
            "unverified",
            _redacted_observation(observed),
            "setting_value_unrecognized",
        )
    return {
        "control": rule.control.value,
        "path": list(rule.path),
        "status": status,
        "observed": value,
        "reason_code": code,
    }


def _build_result(
    status: PrivacyComplianceStatus,
    adapter_id: str,
    configuration_version: object,
    configuration_fingerprint: str | None,
    profile: PrivacyProfile | None,
    controls: tuple[dict[str, object], ...],
    reasons: list[dict[str, str]],
) -> PrivacyComplianceResult:
    return PrivacyComplianceResult(
        status=status,
        adapter_id=adapter_id,
        configuration_version=configuration_version,
        configuration_fingerprint=configuration_fingerprint,
        profile_id=profile.profile_id if profile else None,
        profile_version=profile.profile_version if profile else None,
        profile_fingerprint=profile.fingerprint if profile else None,
        tool_id=profile.tool_id if profile else None,
        tool_version=profile.tool_version if profile else None,
        supports_configuration_compliance=(
            profile.supports_configuration_compliance if profile else False
        ),
        controls=controls,
        reasons=tuple(reasons),
    )


def _unverified_without_profile(
    adapter_id: str,
    configuration_fingerprint: str | None,
    reason: dict[str, str],
) -> PrivacyComplianceResult:
    return _build_result(
        PrivacyComplianceStatus.UNVERIFIED,
        adapter_id,
        None,
        configuration_fingerprint,
        None,
        (),
        [reason],
    )


def _reason(code: str, detail: str) -> dict[str, str]:
    return {"code": code, "detail": detail}


def _lookup(configuration: Mapping[str, object], path: tuple[str, ...]) -> object:
    value: object = configuration
    for name in path:
        if not isinstance(value, Mapping) or name not in value:
            return _MISSING
        value = value[name]
    return value


def _contains_named_key(
    value: object,
    predicate: Callable[[str], bool],
) -> bool:
    """Search nested mappings and containers for a matching configuration key.

    Traversal is iterative and tracks visited containers so cyclic or deeply
    nested adapter configurations cannot raise RecursionError.
    """
    pending: list[object] = [value]
    visited: set[int] = set()
    while pending:
        current = pending.pop()
        if not isinstance(current, (Mapping, list, tuple, set, frozenset)):
            continue
        identity = id(current)
        if identity in visited:
            continue
        visited.add(identity)
        if isinstance(current, Mapping):
            for key, item in current.items():
                if predicate(str(key)):
                    return True
                pending.append(item)
        else:
            pending.extend(current)
    return False

def _contains_sensitive_key(value: object) -> bool:
    """Return whether any nested key denotes credential material."""
    return _contains_named_key(value, _is_sensitive_name)


def _contains_acquisition_configuration(value: object) -> bool:
    """Return whether any nested key denotes model acquisition settings."""
    return _contains_named_key(value, _is_acquisition_name)


def _normalized_key_name(value: str) -> str:
    """Normalize separators before comparing configuration key names."""
    return value.casefold().replace("-", "_").strip()


def _compact_key_name(value: str) -> str:
    """Return a separator-free key name for delimited and camelCase matching."""
    return _normalized_key_name(value).replace("_", "")


def _is_sensitive_name(value: str) -> bool:
    """Match credential names in delimited or camelCase spellings."""
    normalized = _normalized_key_name(value)
    compact = normalized.replace("_", "")
    return (
        normalized in _CREDENTIAL_KEYS
        or normalized.endswith(_CREDENTIAL_SUFFIXES)
        or compact in _CREDENTIAL_COMPACT_KEYS
        or compact.endswith(_CREDENTIAL_COMPACT_SUFFIXES)
    )


def _is_acquisition_name(value: str) -> bool:
    """Match model acquisition roots in delimited or camelCase spellings."""
    return _compact_key_name(value) in _ACQUISITION_COMPACT_ROOTS


def _contains_self_attestation(value: object) -> bool:
    """Return whether any nested key makes an adapter-provided trust claim."""
    return _contains_named_key(value, _is_self_attestation_name)


def _is_self_attestation_name(value: str) -> bool:
    """Match self-attestation names in delimited or camelCase spellings."""
    return _compact_key_name(value) in _SELF_ATTESTATION_COMPACT_KEYS


def _redacted_observation(value: object) -> object:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, str):
        return "<redacted-unrecognized-string>"
    return f"<{type(value).__name__}>"


def _evidence_detail(evidence: dict[str, object]) -> str:
    setting = ".".join(str(part) for part in evidence["path"])
    control = evidence["control"]
    if evidence["status"] == "fail":
        return f"{setting} matched a prohibited value for {control}."
    if evidence["reason_code"] == "setting_missing":
        return f"{setting} was not reported for {control}."
    return f"{setting} used an unsupported value for {control}."


def _is_json_scalar(value: object) -> bool:
    return value is None or isinstance(value, (bool, int, str))


def _same_json_scalar(left: object, right: object) -> bool:
    return left is not _MISSING and right is not _MISSING and type(left) is type(
        right
    ) and left == right


def _canonical_json(value: object) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


DETERMINISTIC_CPU_PRIVACY_PROFILE = PrivacyProfile(
    schema_version=PRIVACY_PROFILE_SCHEMA_VERSION,
    profile_id="deterministic-cpu-png-v1/unqualified",
    profile_version=1,
    adapter_id="deterministic-cpu-png-v1",
    tool_id="deterministic-cpu-png",
    tool_version="1",
    configuration_version=1,
    requirements=(),
    supports_configuration_compliance=False,
)

DEFAULT_PRIVACY_POLICY = PrivacyCompliancePolicy((DETERMINISTIC_CPU_PRIVACY_PROFILE,))
