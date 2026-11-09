"""Versioned, configuration-only privacy checks for inference adapters."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from ipaddress import ip_address
from pathlib import Path


PRIVACY_PROFILE_SCHEMA_VERSION = "local-inference-privacy-profile/v1"
PRIVACY_RESULT_SCHEMA_VERSION = "local-inference-privacy-result/v1"
COMFYUI_PRIVACY_EVIDENCE_SCHEMA = "media-generation.comfyui-privacy-evidence"
COMFYUI_PRIVACY_EVIDENCE_SCHEMA_VERSION = 1
COMFYUI_PRIVACY_EVIDENCE_SOURCE = (
    "application-owned-profile+effective-configuration"
)
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


LOCAL_INFERENCE_CONFIGURATION_VERSION = "sd-cpp-local/v1"
LOCAL_INFERENCE_ENGINE_VERSION = "master-975-95b3090-2-gb13a482"
COMFYUI_ADAPTER_ID = "comfyui-local-v1"
COMFYUI_CONFIGURATION_VERSION = "comfyui-local/v2"
COMFYUI_TOOL_ID = "comfyui"
COMFYUI_SAFE_ENVIRONMENT_NAMES = frozenset(
    {
        "PATH",
        "LD_LIBRARY_PATH",
        "ROCM_PATH",
        "HIP_VISIBLE_DEVICES",
        "CUDA_VISIBLE_DEVICES",
        "HSA_OVERRIDE_GFX_VERSION",
        "PYTHONHASHSEED",
    }
)


# This is the application-owned input contract for the pinned ComfyUI graphs.
# A new class or input must be classified here; otherwise privacy stays unverified.
_COMFYUI_PRIVACY_INPUT_NAMES: dict[str, frozenset[str]] = {
    "UNETLoader": frozenset({"unet_name", "weight_dtype"}),
    "CLIPLoader": frozenset({"clip_name", "device", "type"}),
    "VAELoader": frozenset({"vae_name"}),
    "CLIPTextEncode": frozenset({"clip", "text"}),
    "TextEncodeQwenImageEditPlus": frozenset(
        {"clip", "image1", "image2", "image3", "prompt", "vae"}
    ),
    "FluxKontextImageScale": frozenset({"image"}),
    "FluxKontextMultiReferenceLatentMethod": frozenset(
        {"conditioning", "reference_latents_method"}
    ),
    "CFGNorm": frozenset({"model", "pre_cfg", "strength"}),
    "ModelSamplingAuraFlow": frozenset({"model", "sampling", "shift"}),
    "EmptyLatentImage": frozenset({"batch_size", "height", "width"}),
    "KSampler": frozenset(
        {
            "cfg",
            "denoise",
            "latent_image",
            "model",
            "negative",
            "positive",
            "sampler_name",
            "scheduler",
            "seed",
            "steps",
        }
    ),
    "VAEDecode": frozenset({"samples", "vae"}),
    "SaveImage": frozenset({"filename_prefix", "images"}),
    "LoadImage": frozenset({"image"}),
    "ImageScale": frozenset(
        {"crop", "height", "image", "upscale_method", "width"}
    ),
    "VAEEncode": frozenset({"pixels", "vae"}),
}
_PYTHON_HASH_SEED_MAX = "4294967295"
_PYTHON_HASH_SEED_DECIMAL = re.compile(r"[0-9]+\Z")


def is_valid_python_hash_seed(value: object) -> bool:
    """Validate the documented ``PYTHONHASHSEED`` value forms.

    Accept ``random`` or ASCII decimal digits from 0 through 4294967295.
    """
    if not isinstance(value, str):
        return False
    if value == "random":
        return True
    if not value.isascii() or _PYTHON_HASH_SEED_DECIMAL.fullmatch(value) is None:
        return False
    significant_digits = value.lstrip("0") or "0"
    return len(significant_digits) < 10 or (
        len(significant_digits) == 10
        and significant_digits <= _PYTHON_HASH_SEED_MAX
    )


_COMFYUI_PYTHON_BOOTSTRAP_PATH = str(
    Path(__file__).with_name("_comfyui_python_bootstrap.py").resolve()
)
COMFYUI_VALUE_ARGUMENTS = frozenset(
    {
        "--listen",
        "--port",
        "--base-directory",
        "--output-directory",
        "--temp-directory",
        "--input-directory",
        "--front-end-root",
        "--feature-flag",
    }
)
COMFYUI_BOOLEAN_ARGUMENTS = frozenset(
    {
        "--disable-all-custom-nodes",
        "--disable-auto-launch",
        "--offline",
    }
)
_COMFYUI_CREDENTIAL_VALUE = re.compile(
    r"(?i)\b(?:authorization|bearer|access[_-]?token|api[_-]?key|"
    r"client[_-]?secret|password|passwd|secret|token)\b\s*[:=]\s*\S+"
)
_COMFYUI_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
"""Exact stable-diffusion.cpp revision identity the local profile covers.

The value is the revision identity reported by the pinned stable-diffusion.cpp
source tree through git describe --tags. It denotes commit
b13a48219d5cdf408edcb93da6cd69b612ed03d3 on the observed master development
history. It is an opaque source-revision identity, not a semantic release
number.
The governing upstream tag is lightweight, so the --tags form is required;
plain git describe reports no annotated tag for this commit.

The string must match a candidate declaration's engine.version exactly. A
different git describe --tags value, branch, or commit identifies different engine
source and is refused by the application-owned privacy registration; the
application does not normalize versions or compare them by prefix.
"""

_INVOCATION_CONTROL_TOKENS: dict[PrivacyControl, frozenset[str]] = {
    PrivacyControl.EXTERNAL_API: frozenset({"api", "external_api"}),
    PrivacyControl.CLOUD_INFERENCE: frozenset({"cloud", "cloud_inference"}),
    PrivacyControl.TELEMETRY: frozenset({"telemetry", "analytics", "metrics"}),
    PrivacyControl.CONTENT_UPLOAD: frozenset({"upload", "multipart"}),
    PrivacyControl.AUTOMATIC_NETWORK_FETCH_OR_UPDATE: frozenset(
        {"download", "fetch", "update", "upgrade"}
    ),
    PrivacyControl.REMOTE_ENDPOINT_OR_PROXY: frozenset(
        {"remote", "host", "listen", "server", "proxy", "endpoint"}
    ),
    PrivacyControl.CLOUD_FALLBACK: frozenset({"fallback", "cloud_fallback"}),
}

_PROMPT_FLAGS = frozenset({"-p", "--prompt"})
_SAFE_INVOCATION_FLAGS = frozenset(
    {
        "--diffusion-model",
        "--vae",
        "--llm",
        "--llm_vision",
        "-p",
        "--prompt",
        "-W",
        "-H",
        "--seed",
        "--sampling-method",
        "--steps",
        "--cfg-scale",
        "--flow-shift",
        "-r",
        "--model-args",
        "--qwen-image-zero-cond-t",
        "-o",
    }
)
_SAFE_MODEL_ARGUMENT_KEYS = frozenset({"qwen_image_zero_cond_t"})
_SAFE_ENVIRONMENT_NAMES = frozenset(
    {
        "PATH",
        "LD_LIBRARY_PATH",
        "ROCM_PATH",
        "HIP_VISIBLE_DEVICES",
        "HSA_OVERRIDE_GFX_VERSION",
        "PYTHONHASHSEED",
    }
)
_REMOTE_URL = re.compile(r"[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_DATA_URL = re.compile(r"data:image/", re.IGNORECASE)
_WORD = re.compile(r"[a-z0-9]+")


def _token_words(value: str) -> set[str]:
    """Split one argument or variable name into lowercase alphanumeric words."""
    return set(_WORD.findall(value.lower()))


def _apply_control_tokens(
    settings: dict[str, bool | None], value: str
) -> None:
    """Mark controls named by one token and report a remote URL scheme."""
    words = _token_words(value)
    for control, keywords in _INVOCATION_CONTROL_TOKENS.items():
        if words & keywords:
            settings[control.value] = True


def invocation_privacy_settings(
    argv: Iterable[str],
    environment: Mapping[str, str],
) -> dict[str, bool | None]:
    """Derive local-only controls from the exact child invocation.

    The settings are observable facts about the program name, argument vector,
    and child environment the application passes to the engine. Remote URLs,
    proxy variables, and tokens that name network, upload, update, telemetry, or
    fallback behavior set the matching control to a prohibited value. An
    argument or environment name the application cannot classify leaves the
    controls unverified instead of assuming they are absent.

    Free-form prompt text and numeric dimensions are data, not configuration.
    The result therefore describes invocation settings only; it is not proof
    that the engine makes no network request.
    """
    settings: dict[str, bool | None] = {
        control.value: False for control in PrivacyControl
    }
    tokens = list(argv)
    unknown = False
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not isinstance(token, str):
            raise ValueError("argv entries must be strings")
        if token in _PROMPT_FLAGS:
            index += 2
            continue
        if token == "--model-args":
            value = tokens[index + 1] if index + 1 < len(tokens) else ""
            for entry in value.split(","):
                key, separator, model_value = entry.partition("=")
                if not separator or not key or not model_value:
                    unknown = True
                    continue
                if _matches_remote_token(key):
                    _apply_control_tokens(settings, key)
                elif key not in _SAFE_MODEL_ARGUMENT_KEYS:
                    unknown = True
            index += 2
            continue
        if token.startswith("-"):
            if token not in _SAFE_INVOCATION_FLAGS:
                if _matches_remote_token(token):
                    _apply_control_tokens(settings, token)
                else:
                    unknown = True
            index += 1
            continue
        if _REMOTE_URL.search(token):
            settings[PrivacyControl.REMOTE_ENDPOINT_OR_PROXY.value] = True
        _apply_control_tokens(settings, token)
        index += 1

    for name, value in environment.items():
        normalized = name.lower()
        if name == "PYTHONHASHSEED" and not is_valid_python_hash_seed(value):
            unknown = True
        if normalized.endswith("_proxy"):
            settings[PrivacyControl.REMOTE_ENDPOINT_OR_PROXY.value] = True
        elif name not in _SAFE_ENVIRONMENT_NAMES:
            if _matches_remote_token(name):
                _apply_control_tokens(settings, name)
            else:
                unknown = True
        if _REMOTE_URL.search(value):
            settings[PrivacyControl.REMOTE_ENDPOINT_OR_PROXY.value] = True

    if unknown:
        for control, value in settings.items():
            if value is False:
                settings[control] = None
    return settings


def _all_cached_privacy_settings() -> dict[str, bool | None]:
    return {control.value: None for control in PrivacyControl}


def _comfyui_listen_address_is_prohibited(value: object) -> bool:
    """Return whether a literal ComfyUI bind address is non-loopback."""
    if not isinstance(value, str):
        return False
    try:
        address = ip_address(value)
    except ValueError:
        return False
    return not address.is_loopback


def _comfyui_explicit_privacy_failures(
    argv: Iterable[str],
    environment: Mapping[str, str],
    effective_execution: Mapping[str, object],
) -> frozenset[PrivacyControl]:
    """Return controls disabled by exact, recognized ComfyUI settings.

    This pass recognizes only settings whose names and prohibited values are
    defined by the ComfyUI adapter contract. Prompt arguments and their values
    are skipped so prompt text cannot change the verdict. Any setting not
    recognized here remains unverified through the full invocation check.
    """
    failures: set[PrivacyControl] = set()
    for name in environment:
        if isinstance(name, str) and name.casefold().endswith("_proxy"):
            failures.add(PrivacyControl.REMOTE_ENDPOINT_OR_PROXY)

    tokens = tuple(argv)
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not isinstance(token, str):
            index += 1
            continue
        if token == "--listen":
            value = tokens[index + 1] if index + 1 < len(tokens) else None
            if _comfyui_listen_address_is_prohibited(value):
                failures.add(PrivacyControl.REMOTE_ENDPOINT_OR_PROXY)
            index += 2
            continue
        if token in _PROMPT_FLAGS:
            index += 2
            continue
        if token == "--feature-flag":
            value = tokens[index + 1] if index + 1 < len(tokens) else None
            if value == "enable_upload=true":
                failures.add(PrivacyControl.CONTENT_UPLOAD)
            elif value == "enable_telemetry=true":
                failures.add(PrivacyControl.TELEMETRY)
            elif value == "enable_remote=true":
                failures.add(PrivacyControl.REMOTE_ENDPOINT_OR_PROXY)
            index += 2
            continue
        if token in {"--proxy", "--remote-backend"}:
            failures.add(PrivacyControl.REMOTE_ENDPOINT_OR_PROXY)
            index += 2
            continue
        if token in {"--enable-upload", "--enable-remote-upload"}:
            failures.add(PrivacyControl.CONTENT_UPLOAD)
        index += 1

    configuration = effective_execution.get("configuration")
    if isinstance(configuration, Mapping):
        server = configuration.get("server")
        if isinstance(server, Mapping):
            host = server.get("host")
            if isinstance(host, str) and host != "127.0.0.1":
                failures.add(PrivacyControl.REMOTE_ENDPOINT_OR_PROXY)
            if server.get("offline") is False:
                failures.add(PrivacyControl.AUTOMATIC_NETWORK_FETCH_OR_UPDATE)
    return frozenset(failures)


def _privacy_settings_with_failures(
    failures: Iterable[PrivacyControl],
) -> dict[str, bool | None]:
    settings = _all_cached_privacy_settings()
    for control in failures:
        settings[control.value] = True
    return settings


_COMFYUI_PRIVACY_EVIDENCE_FIELDS = frozenset(
    {
        "schema",
        "schema_version",
        "status",
        "evidence_source",
        "adapter_id",
        "engine_id",
        "engine_version",
        "configuration_version",
        "profile_id",
        "profile_version",
        "profile_fingerprint",
        "effective_configuration_sha256",
        "reasons",
        "fingerprint",
    }
)


@dataclass(frozen=True, slots=True)
class ComfyUIResolvedPrivacyEvidence:
    """Redacted privacy result bound to one exact effective configuration."""

    status: PrivacyComplianceStatus
    adapter_id: str
    engine_id: str
    engine_version: str
    configuration_version: bool | int | str
    profile_id: str
    profile_version: int
    profile_fingerprint: str
    effective_configuration_sha256: str
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema": COMFYUI_PRIVACY_EVIDENCE_SCHEMA,
            "schema_version": COMFYUI_PRIVACY_EVIDENCE_SCHEMA_VERSION,
            "status": self.status.value,
            "evidence_source": COMFYUI_PRIVACY_EVIDENCE_SOURCE,
            "adapter_id": self.adapter_id,
            "engine_id": self.engine_id,
            "engine_version": self.engine_version,
            "configuration_version": self.configuration_version,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "profile_fingerprint": self.profile_fingerprint,
            "effective_configuration_sha256": self.effective_configuration_sha256,
            "reasons": list(self.reasons),
        }
        payload["fingerprint"] = _digest(payload)
        return payload


def comfyui_resolved_privacy_evidence(
    result: PrivacyComplianceResult,
    effective_execution: Mapping[str, object],
    *,
    configuration_version: object,
) -> ComfyUIResolvedPrivacyEvidence:
    """Bind one policy result to exact ComfyUI effective evidence."""

    configuration = effective_execution.get("configuration")
    if not isinstance(configuration, Mapping):
        raise ValueError("effective configuration must be an object")
    engine = configuration.get("engine")
    if not isinstance(engine, Mapping):
        raise ValueError("effective engine must be an object")
    engine_id = engine.get("id")
    engine_version = engine.get("version")
    if (
        engine_id != COMFYUI_TOOL_ID
        or not isinstance(engine_version, str)
        or not engine_version
        or configuration_version != COMFYUI_CONFIGURATION_VERSION
        or result.adapter_id != COMFYUI_ADAPTER_ID
        or result.tool_id != engine_id
        or result.tool_version != engine_version
        or result.configuration_version != configuration_version
        or result.profile_id is None
        or result.profile_version is None
        or result.profile_fingerprint is None
    ):
        raise ValueError("privacy result does not bind the ComfyUI profile")
    profile = comfyui_local_privacy_profile(
        adapter_id=result.adapter_id,
        tool_version=engine_version,
        configuration_version=configuration_version,
    )
    if (
        result.profile_id != profile.profile_id
        or result.profile_version != profile.profile_version
        or result.profile_fingerprint != profile.fingerprint
    ):
        raise ValueError("privacy result does not match the application-owned profile")
    return ComfyUIResolvedPrivacyEvidence(
        status=result.status,
        adapter_id=result.adapter_id,
        engine_id=engine_id,
        engine_version=engine_version,
        configuration_version=configuration_version,
        profile_id=result.profile_id,
        profile_version=result.profile_version,
        profile_fingerprint=result.profile_fingerprint,
        effective_configuration_sha256=_digest(configuration),
        reasons=tuple(sorted(result.reason_codes)),
    )


def validate_comfyui_resolved_privacy_evidence(value: object) -> None:
    """Validate one current ComfyUI privacy evidence object."""

    if not isinstance(value, dict) or set(value) != _COMFYUI_PRIVACY_EVIDENCE_FIELDS:
        raise ValueError("ComfyUI privacy evidence fields are invalid")
    if (
        value["schema"] != COMFYUI_PRIVACY_EVIDENCE_SCHEMA
        or type(value["schema_version"]) is not int
        or value["schema_version"] != COMFYUI_PRIVACY_EVIDENCE_SCHEMA_VERSION
        or value["evidence_source"] != COMFYUI_PRIVACY_EVIDENCE_SOURCE
    ):
        raise ValueError("ComfyUI privacy evidence schema is unsupported")
    status = value["status"]
    if status not in {item.value for item in PrivacyComplianceStatus}:
        raise ValueError("ComfyUI privacy evidence status is invalid")
    adapter_id = value["adapter_id"]
    engine_id = value["engine_id"]
    engine_version = value["engine_version"]
    configuration_version = value["configuration_version"]
    profile_id = value["profile_id"]
    profile_version = value["profile_version"]
    profile_fingerprint = value["profile_fingerprint"]
    effective_digest = value["effective_configuration_sha256"]
    if (
        adapter_id != COMFYUI_ADAPTER_ID
        or engine_id != COMFYUI_TOOL_ID
        or not isinstance(engine_version, str)
        or not engine_version
        or configuration_version != COMFYUI_CONFIGURATION_VERSION
        or profile_id != "comfyui-local"
        or isinstance(profile_version, bool)
        or not isinstance(profile_version, int)
        or profile_version < 1
        or not _is_sha256_hex(profile_fingerprint)
        or not _is_sha256_hex(effective_digest)
    ):
        raise ValueError("ComfyUI privacy evidence identity is invalid")
    profile = comfyui_local_privacy_profile(
        adapter_id=adapter_id,
        tool_version=engine_version,
        configuration_version=configuration_version,
    )
    if (
        profile_id != profile.profile_id
        or profile_version != profile.profile_version
        or profile_fingerprint != profile.fingerprint
    ):
        raise ValueError("ComfyUI privacy evidence profile does not match")
    reasons = value["reasons"]
    if (
        not isinstance(reasons, list)
        or not reasons
        or any(not isinstance(reason, str) or not reason for reason in reasons)
        or reasons != sorted(set(reasons))
        or any(reason not in _PRIVACY_REASON_CODES for reason in reasons)
    ):
        raise ValueError("ComfyUI privacy evidence reasons are invalid")
    reason_set = set(reasons)
    if status == PrivacyComplianceStatus.PASS.value:
        if reason_set != {"all_required_settings_verified"}:
            raise ValueError("passing ComfyUI privacy evidence has failing reasons")
    elif status == PrivacyComplianceStatus.FAIL.value:
        if not reason_set & {
            "acquisition_configuration_present",
            "credential_material_present",
            "prohibited_setting_enabled",
        }:
            raise ValueError("failing ComfyUI privacy evidence lacks a failure")
    elif reason_set & {
        "all_required_settings_verified",
        "acquisition_configuration_present",
        "credential_material_present",
        "prohibited_setting_enabled",
    }:
        raise ValueError("unverified ComfyUI privacy evidence has a verdict reason")
    payload = {key: item for key, item in value.items() if key != "fingerprint"}
    if not _is_sha256_hex(value["fingerprint"]) or _digest(payload) != value["fingerprint"]:
        raise ValueError("ComfyUI privacy evidence fingerprint does not match")


def is_comfyui_resolved_privacy_evidence(value: object) -> bool:
    """Return whether value is one valid ComfyUI privacy evidence object."""

    try:
        validate_comfyui_resolved_privacy_evidence(value)
    except (TypeError, ValueError):
        return False
    return True


def comfyui_invocation_privacy_settings(
    argv: Iterable[str],
    environment: Mapping[str, str],
    effective_execution: Mapping[str, object],
) -> dict[str, bool | None]:
    """Evaluate local-only privacy for a resolved ComfyUI launch and API.

    A bound launch has a fixed Python bootstrap prefix. Validate it before
    parsing engine options after ``--``. The ``--offline`` flag records a
    frontend and Partner Node control. It does not prove operating-system
    egress isolation or prevent backend dependencies from connecting remotely.
    """
    try:
        tokens = tuple(argv)
        configuration = effective_execution["configuration"]
        graph = effective_execution["graph"]
        request_body = effective_execution["request_body"]
        explicit_failures = _comfyui_explicit_privacy_failures(
            tokens, environment, effective_execution
        )
        if explicit_failures:
            return _privacy_settings_with_failures(explicit_failures)
        if (
            len(tokens) < 14
            or not all(isinstance(token, str) and token for token in tokens)
            or not isinstance(configuration, Mapping)
            or not isinstance(graph, Mapping)
            or not isinstance(request_body, Mapping)
        ):
            return _all_cached_privacy_settings()
        if set(configuration) != {
            "engine", "workflow", "server", "nodes", "components", "model_files",
            "model_facing", "api", "output",
        }:
            return _all_cached_privacy_settings()
        server = configuration["server"]
        nodes = configuration["nodes"]
        api = configuration["api"]
        model_components = configuration["components"]
        if not all(isinstance(value, Mapping) for value in (server, nodes, api)):
            return _all_cached_privacy_settings()
        if not isinstance(model_components, list):
            return _all_cached_privacy_settings()
        base_server_fields = {
        "host", "port", "offline", "base_directory", "models_directory",
        "frontend_root", "frontend_root_sha256",
            "output_directory", "temp_directory", "input_directory",
        }
        if set(server) not in (
            base_server_fields,
            base_server_fields | {"argv", "environment"},
        ):
            return _all_cached_privacy_settings()
        server_argument_start = 2
        if "argv" in server:
            engine = configuration["engine"]
            try:
                stdlib_marker = tokens.index("--stdlib-paths")
                imports_marker = tokens.index("--import-roots", stdlib_marker + 1)
                separator = tokens.index("--", imports_marker + 1)
            except ValueError:
                return _all_cached_privacy_settings()
            entrypoint_index = separator + 1
            runtime_paths = (
                tokens[5:7]
                + tokens[stdlib_marker + 1 : imports_marker]
                + tokens[imports_marker + 1 : imports_marker + 3]
            )
            if (
                not isinstance(engine, Mapping)
                or server["argv"] != list(tokens)
                or not isinstance(server["environment"], Mapping)
                or server["environment"] != dict(environment)
                or not Path(tokens[0]).is_absolute()
                or ".." in Path(tokens[0]).parts
                or str(Path(tokens[0])) != tokens[0]
                or tuple(tokens[1:5])
                != (
                    "-P",
                    "-s",
                    "-S",
                    _COMFYUI_PYTHON_BOOTSTRAP_PATH,
                )
                or stdlib_marker != 7
                or imports_marker <= stdlib_marker + 1
                or separator != imports_marker + 3
                or entrypoint_index >= len(tokens)
                or engine.get("executable_path") != tokens[entrypoint_index]
                or engine.get("runtime_fingerprint_sha256") is None
                or any(
                    not Path(path).is_relative_to(Path(tokens[6]))
                    for path in tokens[stdlib_marker + 1 : imports_marker]
                )
                or any(
                    not Path(value).is_absolute()
                    or ".." in Path(value).parts
                    or str(Path(value)) != value
                    for value in (*runtime_paths, tokens[entrypoint_index])
                )
            ):
                return _all_cached_privacy_settings()
            server_argument_start = entrypoint_index + 1
            if (
                set(environment) - COMFYUI_SAFE_ENVIRONMENT_NAMES
                or any(_is_sensitive_name(name) for name in environment)
                or any(not isinstance(value, str) for value in environment.values())
                or (
                    "PYTHONHASHSEED" in environment
                    and not is_valid_python_hash_seed(environment["PYTHONHASHSEED"])
                )
                or any(
                    name.upper().startswith("PYTHON")
                    and name.upper() != "PYTHONHASHSEED"
                    and not (
                        name.upper() == "PYTHONHASHSEED"
                        and is_valid_python_hash_seed(value)
                    )
                    for name, value in environment.items()
                )
            ):
                return _all_cached_privacy_settings()
        if api != {
            "prompt": "/prompt",
            "jobs": "/api/jobs?limit=1000",
            "queue": "/queue",
            "node_replacements": "/node_replacements",
            "history": "/history/{prompt_id}",
            "view": "/view",
            "upload": "/upload/image",
        }:
            return _all_cached_privacy_settings()
        if server["host"] != "127.0.0.1" or server["offline"] is not True:
            return _all_cached_privacy_settings()
        port = server["port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            return _all_cached_privacy_settings()
        frontend_root = server["frontend_root"]
        base_directory = server["base_directory"]
        models_directory = server["models_directory"]
        if (
            not isinstance(frontend_root, str)
            or not frontend_root.startswith("/")
            or "\\" in frontend_root
            or _REMOTE_URL.search(frontend_root)
            or not isinstance(server["frontend_root_sha256"], str)
            or not _COMFYUI_SHA256.fullmatch(server["frontend_root_sha256"])
            or not isinstance(base_directory, str)
            or not base_directory.startswith("/")
            or "\\" in base_directory
            or _REMOTE_URL.search(base_directory)
            or models_directory != f"{base_directory}/models"
        ):
            return _all_cached_privacy_settings()

        used_classes: set[str] = set()
        for node in graph.values():
            if not isinstance(node, Mapping):
                return _all_cached_privacy_settings()
            class_type = node.get("class_type")
            inputs = node.get("inputs")
            if (
                not isinstance(class_type, str)
            or not class_type
                or not isinstance(inputs, Mapping)
            ):
                return _all_cached_privacy_settings()
            used_classes.add(class_type)
            for input_name, value in inputs.items():
                if not isinstance(input_name, str) or _is_sensitive_name(input_name):
                    return _all_cached_privacy_settings()
                if _comfyui_private_graph_value(value):
                    return _all_cached_privacy_settings()
        if used_classes != set(nodes) or not nodes:
            return _all_cached_privacy_settings()
        node_components = {
            component.get("id"): component.get("sha256")
            for component in model_components
            if isinstance(component, Mapping) and component.get("role") == "other"
        }
        if not node_components:
            return _all_cached_privacy_settings()
        require_explicit_pin_class = "argv" in server
        for class_type, pin in nodes.items():
            pin_fields = {"component_id", "sha256", "inputs"}
            if isinstance(pin, Mapping) and "class" in pin:
                pin_fields.add("class")
            if (
                not isinstance(class_type, str)
            or not class_type
            or not isinstance(pin, Mapping)
            or set(pin) != pin_fields
            or (require_explicit_pin_class and "class" not in pin)
            or ("class" in pin and pin["class"] != class_type)
            or node_components.get(pin.get("component_id")) != pin.get("sha256")
            or not isinstance(pin.get("inputs"), list)
            or not pin["inputs"]
            or any(not isinstance(name, str) or not name for name in pin["inputs"])
            ):
                return _all_cached_privacy_settings()
            allowed_input_names = _COMFYUI_PRIVACY_INPUT_NAMES.get(class_type)
            if allowed_input_names is None or any(
                name not in allowed_input_names for name in pin["inputs"]
            ):
                return _all_cached_privacy_settings()

            graph_inputs = {
                str(input_name)
                for node in graph.values()
                if isinstance(node, Mapping)
                and node.get("class_type") == class_type
                and isinstance(node.get("inputs"), Mapping)
                for input_name in node["inputs"]
            }
            if not graph_inputs <= set(pin["inputs"]):
                return _all_cached_privacy_settings()

        observed: dict[str, str | bool] = {}
        feature_flags: list[str] = []
        index = server_argument_start
        while index < len(tokens):
            token = tokens[index]
            if token in COMFYUI_BOOLEAN_ARGUMENTS:
                if token in observed:
                    return _all_cached_privacy_settings()
                observed[token] = True
                index += 1
                continue
            if token in COMFYUI_VALUE_ARGUMENTS:
                if index + 1 >= len(tokens):
                    return _all_cached_privacy_settings()
                value = tokens[index + 1]
                if token == "--feature-flag":
                    if value != "enable_telemetry=false":
                        return _all_cached_privacy_settings()
                    feature_flags.append(value)
                elif token in observed or not value:
                    return _all_cached_privacy_settings()
                else:
                    observed[token] = value
                index += 2
                continue
            return _all_cached_privacy_settings()
        if feature_flags != ["enable_telemetry=false"]:
            return _all_cached_privacy_settings()
        if (
            observed.get("--listen") != "127.0.0.1"
            or observed.get("--port") != str(port)
            or observed.get("--base-directory") != base_directory
            or observed.get("--front-end-root") != frontend_root
            or observed.get("--offline") is not True
            or observed.get("--disable-all-custom-nodes") is not True
            or observed.get("--disable-auto-launch") is not True
        ):
            return _all_cached_privacy_settings()
        for flag in (
            "--base-directory",
            "--output-directory",
            "--temp-directory",
            "--input-directory",
        ):
            if observed.get(flag) != server[flag.removeprefix("--").replace("-", "_")]:
                return _all_cached_privacy_settings()
        if request_body.get("prompt") != graph:
            return _all_cached_privacy_settings()
        if _comfyui_private_graph_value(configuration) or _comfyui_private_graph_value(request_body):
            return _all_cached_privacy_settings()

        for name, value in environment.items():
            if (
                not isinstance(name, str)
                or not isinstance(value, str)
                or name.lower().endswith("_proxy")
                or _is_sensitive_name(name)
                or name not in COMFYUI_SAFE_ENVIRONMENT_NAMES
                or (
                    name == "PYTHONHASHSEED"
                    and not is_valid_python_hash_seed(value)
                )
                or _REMOTE_URL.search(value)
            ):
                return _all_cached_privacy_settings()
        return {control.value: False for control in PrivacyControl}
    except (KeyError, TypeError, ValueError):
        return _all_cached_privacy_settings()


def _comfyui_private_graph_value(value: object) -> bool:
    """Return true when nested ComfyUI evidence contains remote or secret data."""
    if isinstance(value, str):
        return bool(
            _REMOTE_URL.search(value)
            or _DATA_URL.search(value)
            or _COMFYUI_CREDENTIAL_VALUE.search(value)
        )
    if isinstance(value, Mapping):
        return any(
            not isinstance(name, str)
            or _is_sensitive_name(name)
            or _comfyui_private_graph_value(child)
            for name, child in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_comfyui_private_graph_value(child) for child in value)
    return False


def _matches_remote_token(value: str) -> bool:
    """Return whether a token names remote or network behavior."""
    words = _token_words(value)
    return any(words & keywords for keywords in _INVOCATION_CONTROL_TOKENS.values())


def local_inference_privacy_profile(
    *,
    adapter_id: str,
    tool_version: str,
    configuration_version: object = LOCAL_INFERENCE_CONFIGURATION_VERSION,
) -> PrivacyProfile:
    """Return the application-owned profile for one pinned local engine build.

    Every control maps to an explicit setting that the application constructs
    for the declared invocation: only local artifact paths are passed, the
    environment is rebuilt from a fixed allowlist, and no remote, telemetry,
    upload, update, proxy, or fallback path is configured. The profile proves
    configuration compliance only. It does not prove that the engine makes no
    network call and does not provide operating-system network confinement.
    """
    if not isinstance(tool_version, str) or not tool_version.strip():
        raise ValueError("tool_version must be a non-empty string")
    requirements = tuple(
        PrivacySettingRule(
            control=control,
            path=("privacy", control.value),
            expected=False,
            prohibited=(True,),
        )
        for control in PrivacyControl
    )
    return PrivacyProfile(
        schema_version=PRIVACY_PROFILE_SCHEMA_VERSION,
        profile_id="stable-diffusion-cpp-local",
        profile_version=1,
        adapter_id=adapter_id,
        tool_id="stable-diffusion.cpp",
        tool_version=tool_version,
        configuration_version=configuration_version,
        requirements=requirements,
        supports_configuration_compliance=True,
    )


def comfyui_local_privacy_profile(
    *,
    adapter_id: str = COMFYUI_ADAPTER_ID,
    tool_version: str,
    configuration_version: object = COMFYUI_CONFIGURATION_VERSION,
) -> PrivacyProfile:
    """Return the independent application-owned ComfyUI local-only profile."""
    if not isinstance(tool_version, str) or not tool_version.strip():
        raise ValueError("tool_version must be a non-empty string")
    requirements = tuple(
        PrivacySettingRule(
            control=control,
            path=("privacy", control.value),
            expected=False,
            prohibited=(True,),
        )
        for control in PrivacyControl
    )
    return PrivacyProfile(
        schema_version=PRIVACY_PROFILE_SCHEMA_VERSION,
        profile_id="comfyui-local",
        profile_version=1,
        adapter_id=adapter_id,
        tool_id=COMFYUI_TOOL_ID,
        tool_version=tool_version,
        configuration_version=configuration_version,
        requirements=requirements,
        supports_configuration_compliance=True,
    )


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

@dataclass(frozen=True, slots=True)
class LocalInferencePrivacyRegistration:
    """Application-owned binding for one local inference adapter.

    The registration names the exact adapter identity, engine identity,
    engine version, and configuration version the application is willing to
    evaluate. The profile is created from these pinned values, never from an
    adapter-supplied policy or an arbitrary candidate declaration.
    """

    adapter_id: str
    tool_id: str
    tool_version: str
    configuration_version: bool | int | str

    def __post_init__(self) -> None:
        """Reject incomplete or non-scalar registration values."""

        for name in ("adapter_id", "tool_id", "tool_version"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if self.configuration_version is None or not _is_json_scalar(
            self.configuration_version
        ):
            raise ValueError(
                "configuration_version must be a non-null JSON scalar"
            )

    def profile(self) -> PrivacyProfile:
        """Return the exact pinned profile this registration authorizes."""

        if self.tool_id == COMFYUI_TOOL_ID:
            return comfyui_local_privacy_profile(
                adapter_id=self.adapter_id,
                tool_version=self.tool_version,
                configuration_version=self.configuration_version,
            )
        return local_inference_privacy_profile(
            adapter_id=self.adapter_id,
            tool_version=self.tool_version,
            configuration_version=self.configuration_version,
        )

APPLICATION_PRIVACY_REGISTRATIONS = (
    LocalInferencePrivacyRegistration(
        adapter_id="stable-diffusion-cpp-local-v1",
        tool_id="stable-diffusion.cpp",
        tool_version=LOCAL_INFERENCE_ENGINE_VERSION,
        configuration_version=LOCAL_INFERENCE_CONFIGURATION_VERSION,
    ),
)
"""Application-owned registrations that may evaluate as local inference.

The registry lives in application code and never in an adapter. Adding an entry
is the only way to authorize another adapter identity, and every entry names
the exact engine identity, engine version, and configuration version it covers.
"""

APPLICATION_PRIVACY_REGISTRY = {
    registration.adapter_id: registration
    for registration in APPLICATION_PRIVACY_REGISTRATIONS
}


def application_privacy_registration(
    adapter_id: object,
) -> LocalInferencePrivacyRegistration:
    """Return the app-owned registration for an exact adapter identity."""

    if not isinstance(adapter_id, str) or not adapter_id:
        raise ValueError("backend execution adapter must declare adapter_id")
    if adapter_id == COMFYUI_ADAPTER_ID:
        try:
            from .comfyui_runtime_pins import load_runtime_pin_approval

            approval = load_runtime_pin_approval(verify_paths=False)
        except (ImportError, OSError, ValueError) as error:
            raise ValueError(
                "ComfyUI has no independently authenticated runtime version registration"
            ) from error
        if approval.configuration_version != COMFYUI_CONFIGURATION_VERSION:
            raise ValueError("ComfyUI runtime configuration version is unsupported")
        return LocalInferencePrivacyRegistration(
            adapter_id=COMFYUI_ADAPTER_ID,
            tool_id=COMFYUI_TOOL_ID,
            tool_version=approval.tool_version,
            configuration_version=approval.configuration_version,
        )
    registration = APPLICATION_PRIVACY_REGISTRY.get(adapter_id)
    if registration is None:
        raise ValueError(
            f"no application-owned privacy registration for adapter {adapter_id!r}"
        )
    return registration


def application_privacy_profile(
    adapter_id: object, configuration: object
) -> PrivacyProfile:
    """Return the app-owned profile for one exact adapter configuration.

    Selection never consults a policy object supplied by the adapter. The
    registration must match the adapter identifier, engine identifier, engine
    version, and configuration version exactly. Any mismatch raises instead of
    degrading into partial evaluation.
    """

    registration = application_privacy_registration(adapter_id)
    if not isinstance(configuration, Mapping):
        raise ValueError(
            "backend execution configuration must declare a mapping"
        )
    engine = configuration.get("engine")
    if not isinstance(engine, Mapping):
        raise ValueError(
            "backend execution configuration must declare an engine mapping"
        )
    if engine.get("id") != registration.tool_id:
        raise ValueError(
            "backend execution engine does not match application-owned "
            "registration"
        )
    tool_version = engine.get("version")
    if not isinstance(tool_version, str) or not tool_version.strip():
        raise ValueError(
            "backend execution configuration must declare engine version"
        )
    if tool_version != registration.tool_version:
        raise ValueError(
            "backend execution engine version does not match "
            "application-owned registration"
        )
    if not _same_json_scalar(
        configuration.get("configuration_version"),
        registration.configuration_version,
    ):
        raise ValueError(
            "backend execution configuration version does not match "
            "application-owned registration"
        )
    return registration.profile()


def application_privacy_policy(
    adapter: object,
) -> PrivacyCompliancePolicy:
    """Return the application-owned policy for one registered backend adapter."""

    return PrivacyCompliancePolicy(
        (
            application_privacy_profile(
                getattr(adapter, "adapter_id", None),
                getattr(adapter, "configuration", None),
            ),
        )
    )
