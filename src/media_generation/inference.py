"""Validate the built-in text and vision inference response contracts."""

from __future__ import annotations

import json
import hashlib
import math
import re
from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from importlib.metadata import PackageNotFoundError, version

from jsonschema import Draft202012Validator


class ResponseCategory(StrEnum):
    """Classify a response or a generation outcome reported by its caller."""

    VALID_OUTPUT = "valid_output"
    REFUSAL = "refusal"
    INCOMPLETE_JSON_AT_EOF = "incomplete_json_at_eof"
    MALFORMED_JSON_UNKNOWN_TERMINATION = "malformed_json_unknown_termination"
    SCHEMA_REJECTION = "schema_rejection"
    SEMANTIC_REJECTION = "semantic_rejection"
    GENERATION_TRUNCATED = "generation_truncated"
    RESPONSE_CAPTURE_OVERFLOW = "response_capture_overflow"
    RUNTIME_FAILURE = "runtime_failure"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class InferenceKind(StrEnum):
    """Select one of the fixed text or image response contracts."""

    TEXT = "text"
    VISION = "vision"


@dataclass(frozen=True, slots=True)
class ResponseResult:
    """Hold a validation category, parsed value, and optional explanation."""

    category: ResponseCategory
    value: object | None = None
    detail: str | None = None

    @property
    def repair_eligible(self) -> bool:
        """Return whether this category can be sent for a repair attempt."""
        return is_repair_eligible(self.category)


_REPAIRABLE_CATEGORIES = frozenset(
    {
        ResponseCategory.INCOMPLETE_JSON_AT_EOF,
        ResponseCategory.MALFORMED_JSON_UNKNOWN_TERMINATION,
        ResponseCategory.SCHEMA_REJECTION,
        ResponseCategory.SEMANTIC_REJECTION,
        ResponseCategory.GENERATION_TRUNCATED,
    }
)

_TEXT_RESPONSE_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "oneOf": [
        {
            "type": "object",
            "properties": {
                "status": {"const": "ok"},
                "answer": {"type": "string", "minLength": 1},
                "evidence_spans": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1},
                },
            },
            "required": ["status", "answer", "evidence_spans"],
            "additionalProperties": False,
        },
        {
            "type": "object",
            "properties": {
                "status": {"const": "refused"},
                "reason": {"type": "string", "minLength": 1},
            },
            "required": ["status", "reason"],
            "additionalProperties": False,
        },
    ],
}

_VISION_RESPONSE_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "oneOf": [
        {
            "type": "object",
            "properties": {
                "status": {"const": "ok"},
                "observations": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "label": {"type": "string", "minLength": 1},
                            "normalized_box": {
                                "type": "array",
                                "items": {"type": "number"},
                                "minItems": 4,
                                "maxItems": 4,
                            },
                        },
                        "required": ["label", "normalized_box"],
                        "additionalProperties": False,
                    },
                },
            },
            "required": ["status", "observations"],
            "additionalProperties": False,
        },
        {
            "type": "object",
            "properties": {
                "status": {"const": "refused"},
                "reason": {"type": "string", "minLength": 1},
            },
            "required": ["status", "reason"],
            "additionalProperties": False,
        },
    ],
}

_SCHEMA_VERSIONS = {
    InferenceKind.TEXT: "local-inference-text-response/v1",
    InferenceKind.VISION: "local-inference-vision-response/v1",
}
_TEMPLATE_VERSIONS = {
    InferenceKind.TEXT: "local-inference-text-prompt/v1",
    InferenceKind.VISION: "local-inference-vision-prompt/v1",
}
_VALIDATOR_ID = "jsonschema-draft2020-12"
MAX_INFERENCE_TEXT_BYTES = 65_536
MAX_REPAIR_RESPONSE_BYTES = 16_384

Draft202012Validator.check_schema(_TEXT_RESPONSE_SCHEMA)
Draft202012Validator.check_schema(_VISION_RESPONSE_SCHEMA)
_TEXT_VALIDATOR = Draft202012Validator(_TEXT_RESPONSE_SCHEMA)
_VISION_VALIDATOR = Draft202012Validator(_VISION_RESPONSE_SCHEMA)

_JSON_WHITESPACE = " \t\r\n"
_PARTIAL_LITERAL_TOKENS = frozenset(
    {"t", "tr", "tru", "f", "fa", "fal", "fals", "n", "nu", "nul"}
)
_PARTIAL_NUMBER = re.compile(
    r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]*)?(?:[eE][+-]?[0-9]*)?"
)


def response_schema(kind: InferenceKind) -> dict[str, object]:
    """Return a defensive copy of the fixed schema for one inference kind."""
    normalized = _normalize_kind(kind)
    schema = (
        _TEXT_RESPONSE_SCHEMA
        if normalized is InferenceKind.TEXT
        else _VISION_RESPONSE_SCHEMA
    )
    return deepcopy(schema)


def response_contract(kind: InferenceKind) -> dict[str, str]:
    """Return stable schema, template, and validator provenance for a request."""
    normalized = _normalize_kind(kind)
    schema_json = json.dumps(
        response_schema(normalized),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    try:
        validator_version = version("jsonschema")
    except PackageNotFoundError as error:
        raise RuntimeError("jsonschema package version is unavailable") from error
    return {
        "kind": normalized.value,
        "schema_version": _SCHEMA_VERSIONS[normalized],
        "schema_sha256": hashlib.sha256(schema_json.encode("utf-8")).hexdigest(),
        "template_version": _TEMPLATE_VERSIONS[normalized],
        "validator_id": _VALIDATOR_ID,
        "validator_package_version": validator_version,
    }


def render_prompt(
    kind: InferenceKind,
    prompt: str,
    *,
    repair_category: ResponseCategory | None = None,
    prior_response: str | None = None,
) -> str:
    """Build the versioned user message for one fixed response contract."""
    normalized = _normalize_kind(kind)
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("inference prompt must contain non-whitespace text")
    if len(prompt.encode("utf-8")) > MAX_INFERENCE_TEXT_BYTES:
        raise ValueError(
            f"inference prompt exceeds {MAX_INFERENCE_TEXT_BYTES} UTF-8 bytes"
        )
    if (repair_category is None) != (prior_response is None):
        raise ValueError("repair category and prior response must be supplied together")

    if normalized is InferenceKind.TEXT:
        task = (
            "Answer only from the supplied text. Every evidence span must be an "
            "exact substring of that text."
        )
    else:
        task = (
            "Answer about the image attached separately. Use normalized image "
            "coordinates in the range [0, 1] for every bounding box."
        )
    pieces = [
        "Return exactly one JSON object matching the application-provided JSON "
        "Schema. Do not add markdown, a preamble, or text after the object.",
        task,
        f"Input text as a JSON string: {json.dumps(prompt, ensure_ascii=False)}",
    ]
    if repair_category is not None:
        if not isinstance(repair_category, ResponseCategory) or not is_repair_eligible(
            repair_category
        ):
            raise ValueError("repair category is not eligible for correction")
        if not isinstance(prior_response, str):
            raise ValueError("prior response must be text")
        encoded_response = prior_response.encode("utf-8")
        if len(encoded_response) > MAX_REPAIR_RESPONSE_BYTES:
            encoded_response = encoded_response[:MAX_REPAIR_RESPONSE_BYTES]
            prior_response = encoded_response.decode("utf-8", errors="ignore")
        pieces.extend(
            [
                "Correct the previous response to satisfy the same application "
                "schema and task. This is the single bounded correction attempt.",
                f"Validation category: {repair_category.value}",
                "Previous response as a JSON string: "
                + json.dumps(prior_response, ensure_ascii=False),
            ]
        )
    return "\n\n".join(pieces)


def _normalize_kind(kind: InferenceKind) -> InferenceKind:
    """Parse only the two supported inference kinds."""
    if isinstance(kind, InferenceKind):
        return kind
    try:
        return InferenceKind(kind)
    except (TypeError, ValueError) as error:
        raise ValueError(f"unsupported inference kind: {kind!r}") from error


def is_repair_eligible(category: ResponseCategory) -> bool:
    """Return whether another generation attempt may repair this category."""
    if not isinstance(category, ResponseCategory):
        raise TypeError("category must be a ResponseCategory")
    return category in _REPAIRABLE_CATEGORIES


def validate_text_response(raw_json: str, original_text: str) -> ResponseResult:
    """Validate a text response and verify each evidence span against its input."""
    if not isinstance(raw_json, str):
        raise TypeError("raw_json must be a string")
    if not isinstance(original_text, str):
        raise TypeError("original_text must be a string")

    try:
        value = json.loads(raw_json)
    except json.JSONDecodeError as error:
        category = (
            ResponseCategory.INCOMPLETE_JSON_AT_EOF
            if _is_incomplete_json_at_eof(raw_json, error)
            else ResponseCategory.MALFORMED_JSON_UNKNOWN_TERMINATION
        )
        return ResponseResult(category, detail=error.msg)

    schema_error = next(_TEXT_VALIDATOR.iter_errors(value), None)
    if schema_error is not None:
        return ResponseResult(
            ResponseCategory.SCHEMA_REJECTION,
            value=value,
            detail=schema_error.message,
        )

    semantic_error = _text_semantic_error(value, original_text)
    if semantic_error is not None:
        return ResponseResult(
            ResponseCategory.SEMANTIC_REJECTION,
            value=value,
            detail=semantic_error,
        )

    category = (
        ResponseCategory.REFUSAL
        if value["status"] == "refused"
        else ResponseCategory.VALID_OUTPUT
    )
    return ResponseResult(category, value=value)


def validate_vision_response(raw_json: str) -> ResponseResult:
    """Validate a vision response and its normalized bounding boxes."""
    if not isinstance(raw_json, str):
        raise TypeError("raw_json must be a string")

    try:
        value = json.loads(raw_json)
    except json.JSONDecodeError as error:
        category = (
            ResponseCategory.INCOMPLETE_JSON_AT_EOF
            if _is_incomplete_json_at_eof(raw_json, error)
            else ResponseCategory.MALFORMED_JSON_UNKNOWN_TERMINATION
        )
        return ResponseResult(category, detail=error.msg)

    schema_error = next(_VISION_VALIDATOR.iter_errors(value), None)
    if schema_error is not None:
        return ResponseResult(
            ResponseCategory.SCHEMA_REJECTION,
            value=value,
            detail=schema_error.message,
        )

    semantic_error = _vision_semantic_error(value)
    if semantic_error is not None:
        return ResponseResult(
            ResponseCategory.SEMANTIC_REJECTION,
            value=value,
            detail=semantic_error,
        )

    category = (
        ResponseCategory.REFUSAL
        if value["status"] == "refused"
        else ResponseCategory.VALID_OUTPUT
    )
    return ResponseResult(category, value=value)


def _is_incomplete_json_at_eof(
    raw_json: str, error: json.JSONDecodeError
) -> bool:
    """Recognize JSON prefixes that stop while the decoder expects more input."""
    end = len(raw_json.rstrip(_JSON_WHITESPACE))
    if error.msg.startswith("Unterminated string") or error.pos >= end:
        return True

    if error.msg == "Invalid \\uXXXX escape":
        return _has_partial_unicode_escape(raw_json, end, error.pos)

    if error.msg == "Expecting value":
        suffix = raw_json[error.pos:end]
        if suffix in _PARTIAL_LITERAL_TOKENS or suffix == "-":
            return True

    if error.msg in {"Expecting value", "Expecting ',' delimiter", "Extra data"}:
        return _has_partial_number_at_error(raw_json, end, error.pos)
    return False


def _has_partial_unicode_escape(raw_json: str, end: int, position: int) -> bool:
    """Check whether an invalid Unicode escape ends at a valid escape prefix."""
    if position == 0 or raw_json[position - 1 : position + 1] != "\\u":
        return False
    digits = raw_json[position + 1 : end]
    return len(digits) < 4 and all(
        character in "0123456789abcdefABCDEF" for character in digits
    )


def _has_partial_number_at_error(raw_json: str, end: int, position: int) -> bool:
    """Check whether a number token stops at its decimal or exponent marker."""
    start = position
    while start > 0 and raw_json[start - 1] in "0123456789+-.eE":
        start -= 1
    token = raw_json[start:end]
    if token == "-":
        return True
    if start > 0 and raw_json[start - 1] not in _JSON_WHITESPACE + ":[,":
        return False
    return bool(
        _PARTIAL_NUMBER.fullmatch(token)
        and token.endswith((".", "e", "E", "e+", "e-", "E+", "E-"))
    )


def _text_semantic_error(value: dict[str, object], original_text: str) -> str | None:
    """Return the first text-contract rule that the schema cannot express."""
    if value["status"] == "refused":
        if not value["reason"].strip():
            return "refusal reason must contain non-whitespace text"
        return None

    if not value["answer"].strip():
        return "answer must contain non-whitespace text"
    for span in value["evidence_spans"]:
        if not span.strip():
            return "evidence spans must contain non-whitespace text"
        if span not in original_text:
            return "every evidence span must occur verbatim in the original text"
    return None


def _vision_semantic_error(value: dict[str, object]) -> str | None:
    """Return the first box rule that the schema cannot express."""
    if value["status"] == "refused":
        if not value["reason"].strip():
            return "refusal reason must contain non-whitespace text"
        return None

    for observation in value["observations"]:
        if not observation["label"].strip():
            return "observation labels must contain non-whitespace text"
        x0, y0, x1, y1 = observation["normalized_box"]
        if any(not _is_finite_number(coordinate) for coordinate in (x0, y0, x1, y1)):
            return "normalized box coordinates must be finite"
        if not (0 <= x0 < x1 <= 1 and 0 <= y0 < y1 <= 1):
            return "normalized boxes must have increasing coordinates within [0, 1]"
    return None


def _is_finite_number(value: int | float) -> bool:
    """Check finiteness without converting arbitrary-size JSON integers to float."""
    return isinstance(value, int) or math.isfinite(value)
