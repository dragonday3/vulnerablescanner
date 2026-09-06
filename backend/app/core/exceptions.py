class NotFoundError(Exception):
    pass


class ValidationConflictError(Exception):
    pass


class ScanStateError(Exception):
    """Raised when a scan operation is invalid given the scan's current status.

    Distinct from ValidationConflictError (-> 400) because this represents a
    conflict with the resource's current state (-> 409), e.g. attempting to
    cancel a scan that is already completed/cancelled/failed.
    """

    pass
