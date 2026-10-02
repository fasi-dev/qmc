class IngestionError(Exception):
    """Rejected or failed ingestion. `code` is a stable machine-readable identifier."""

    def __init__(self, code: str, message: str, status_code: int = 422):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
