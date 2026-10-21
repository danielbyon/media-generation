"""Errors raised at the local generation service boundary."""


class GenerationError(Exception):
    """Base class for expected request and execution failures."""


class InputValidationError(GenerationError):
    """The submitted request or idempotency key is malformed."""


class UnsupportedCapabilityError(GenerationError):
    """The selected adapter cannot provide a requested capability."""


class UnknownReferenceError(GenerationError):
    """A reference ID does not identify a persisted logical artifact."""


class IdempotencyConflictError(GenerationError):
    """An idempotency key is already bound to different request intent."""


class RecordNotFoundError(GenerationError):
    """A requested persisted record does not exist."""


class GenerationExecutionError(GenerationError):
    """An adapter failed after a job and attempt were durably created."""

    def __init__(self, job_id: str, message: str) -> None:
        super().__init__(message)
        self.job_id = job_id
