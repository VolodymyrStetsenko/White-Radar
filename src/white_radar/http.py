from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class HttpError(RuntimeError):
    """An outbound HTTP request failed after retries."""


def redact_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    path_parts = parsed.path.split("/")
    path_parts = ["<redacted-bot>" if part.startswith("bot") else part for part in path_parts]
    if "v2" in path_parts:
        index = path_parts.index("v2")
        path_parts = [*path_parts[: index + 1], "<redacted>"]
    safe_path = "/".join(path_parts)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, safe_path, "", ""))


def request_json(
    method: str,
    url: str,
    *,
    timeout: int,
    retries: int = 3,
    headers: dict[str, str] | None = None,
    params: dict[str, object] | None = None,
    payload: object | None = None,
    allow_not_found: bool = False,
) -> Any:
    if params:
        separator = "&" if "?" in url else "?"
        url = f"{url}{separator}{urllib.parse.urlencode(params)}"
    body = None
    request_headers = {
        "Accept": "application/json",
        "User-Agent": "white-radar/0.1",
        **(headers or {}),
    }
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request_headers["Content-Type"] = "application/json"

    last_error: Exception | None = None
    for attempt in range(retries):
        try:
            request = urllib.request.Request(
                url,
                data=body,
                headers=request_headers,
                method=method.upper(),
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if allow_not_found and exc.code == 404:
                return None
            last_error = exc
            if exc.code < 500 and exc.code != 429:
                break
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
        if attempt + 1 < retries:
            time.sleep(min(4.0, 0.5 * (2**attempt)))
    raise HttpError(f"Request failed: {method.upper()} {redact_url(url)}: {last_error}")
