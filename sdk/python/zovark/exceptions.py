"""Zovark SDK exceptions."""


class ZovarkAPIError(Exception):
    """Base exception for Zovark API errors."""

    def __init__(self, message, status_code=None, response_body=None):
        self.message = message
        self.status_code = status_code
        self.response_body = response_body
        super().__init__(self.message)

    def __str__(self):
        if self.status_code:
            return f"ZovarkAPIError({self.status_code}): {self.message}"
        return f"ZovarkAPIError: {self.message}"


class AuthenticationError(ZovarkAPIError):
    """Raised when authentication fails (401)."""

    def __init__(self, message="Authentication failed", **kwargs):
        super().__init__(message, status_code=401, **kwargs)


class RateLimitError(ZovarkAPIError):
    """Raised when rate limit is exceeded (429)."""

    def __init__(self, message="Rate limit exceeded", retry_after=None, **kwargs):
        self.retry_after = retry_after
        super().__init__(message, status_code=429, **kwargs)

    def __str__(self):
        base = super().__str__()
        if self.retry_after:
            return f"{base} (retry after {self.retry_after}s)"
        return base


class NotFoundError(ZovarkAPIError):
    """Raised when a resource is not found (404)."""

    def __init__(self, message="Resource not found", **kwargs):
        super().__init__(message, status_code=404, **kwargs)


class ForbiddenError(ZovarkAPIError):
    """Raised when access is forbidden (403)."""

    def __init__(self, message="Access forbidden", **kwargs):
        super().__init__(message, status_code=403, **kwargs)
