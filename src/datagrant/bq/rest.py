"""Small transport contract for the operator's authenticated HTTP session."""

from typing import Any, Protocol

TIMEOUT = 15


class Response(Protocol):
    @property
    def status_code(self) -> int: ...

    def json(self) -> Any: ...


class Session(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        timeout: int,
        allow_redirects: bool,
        **kwargs: Any,
    ) -> Response: ...
