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


class ResourceBusyError(GenerationError):
    """The single local heavyweight resource is occupied by another attempt.

    The job identified by ``job_id`` remains durably admitted and can be
    inspected or executed later. Resource contention never grants a second
    execution authority.
    """

    def __init__(self, job_id: str, message: str = "local generation resource is busy") -> None:
        super().__init__(message)
        self.job_id = job_id


class RetryableGenerationError(GenerationError):
    """An adapter has identified a known, process-contained transient failure."""


class RecordNotFoundError(GenerationError):
    """A requested persisted record does not exist."""


class PublicationError(GenerationError):
    """Publication needs inspection or reconciliation before it can complete."""


class PublicationIncompleteError(PublicationError):
    """A generated publication is recoverable and its job is still running.

    The job ID identifies the durable execution to inspect. Recovery guidance
    applies to that execution without creating a new request or attempt.
    """

    def __init__(self, job_id: str, message: str) -> None:
        super().__init__(message)
        self.job_id = job_id
        self.recovery = (
            "Run reconcile with the same database and output directory, then "
            "resubmit the same request and idempotency key."
        )


class ArtifactIntegrityError(GenerationError):
    """Authoritative image content is missing, corrupt, or unsafe to read."""


class GenerationExecutionError(GenerationError):
    """An adapter failed after a job and attempt were durably created."""

    def __init__(self, job_id: str, message: str) -> None:
        super().__init__(message)
        self.job_id = job_id
