"""Public T07 interface for bounded, evidence-bound candidate preparation.

This facade exposes the declaration and trusted-evidence parsers together with
the inspect, verify, and prepare operations used by the command line. The
authoritative offline evaluator is shared by all three operations. Acquisition,
journal, and publication mechanics remain private to the T07 package modules.
"""

from __future__ import annotations

from . import _candidate_acquisition as _acquisition
from . import _candidate_contract as _contract
from . import _candidate_evaluation as _evaluation
from ._candidate_contract import (
    CandidateAcquisitionError,
    CandidateError,
    CandidateOutputError,
    CandidateValidationError,
    TrustedEvidence,
    parse_acquisition_config,
    parse_candidate,
    parse_trusted_evidence,
)
from ._candidate_evaluation import (
    candidate_exit_code,
    inspect_candidate,
    verify_candidate,
)
from ._candidate_acquisition import prepare_candidate

__all__ = [
    "CandidateAcquisitionError",
    "CandidateError",
    "CandidateOutputError",
    "CandidateValidationError",
    "TrustedEvidence",
    "candidate_exit_code",
    "inspect_candidate",
    "parse_acquisition_config",
    "parse_candidate",
    "parse_trusted_evidence",
    "prepare_candidate",
    "verify_candidate",
]
