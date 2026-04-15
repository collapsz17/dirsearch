# -*- coding: utf-8 -*-

from __future__ import annotations

import http.client
import io
import subprocess
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urljoin, urlparse

from lib.core.exceptions import RequestException
from lib.core.structures import CaseInsensitiveDict

DIRECT_TLS_MODES = ("sslv3", "gost")
MAX_REDIRECTS = 20


@dataclass
class HistoryEntry:
    url: str


class _FakeSocket:
    def __init__(self, response_bytes: bytes) -> None:
        self._file = io.BytesIO(response_bytes)

    def makefile(self, *_args, **_kwargs) -> io.BytesIO:
        return self._file


class OpenSSLResponse:
    def __init__(
        self,
        url: str,
        status_code: int,
        headers: CaseInsensitiveDict,
        body: bytes,
        history: list[HistoryEntry] | None = None,
    ) -> None:
        self.url = url
        self.status_code = status_code
        self.headers = headers
        self.history = history or []
        self.encoding = "utf-8"
        self._body = body

    def iter_content(self, chunk_size: int = 8192) -> Iterable[bytes]:
        for index in range(0, len(self._body), chunk_size):
            yield self._body[index : index + chunk_size]

    async def aiter_bytes(self, chunk_size: int = 8192):
        for chunk in self.iter_content(chunk_size=chunk_size):
            yield chunk


def build_openssl_args(
    address: str,
    server_name: str,
    tls_mode: str,
    cert_file: str | None = None,
    key_file: str | None = None,
) -> list[str]:
    args = [
        "openssl",
        "s_client",
        "-quiet",
        "-ign_eof",
        "-connect",
        address,
    ]
    if server_name:
        args.extend(["-servername", server_name])

    if tls_mode == "sslv3":
        args.extend(["-ssl3", "-cipher", "ALL:@SECLEVEL=0"])
    elif tls_mode == "gost":
        args.extend(
            [
                "-engine",
                "gost",
                "-cipher",
                "ALL:@SECLEVEL=0",
                "-legacy_server_connect",
            ]
        )
    else:
        raise ValueError(f"Unsupported TLS mode: {tls_mode}")

    if cert_file:
        args.extend(["-cert", cert_file])

    if key_file:
        args.extend(["-key", key_file])

    return args


def send_request(
    url: str,
    method: str,
    headers: CaseInsensitiveDict,
    data: str | bytes | None,
    timeout: float,
    tls_mode: str,
    follow_redirects: bool = False,
    connect_host: str | None = None,
    cert_file: str | None = None,
    key_file: str | None = None,
) -> OpenSSLResponse:
    current_url = url
    history: list[HistoryEntry] = []

    for _ in range(MAX_REDIRECTS + 1):
        response = _send_single_request(
            current_url,
            method,
            headers,
            data,
            timeout,
            tls_mode,
            connect_host=connect_host,
            cert_file=cert_file,
            key_file=key_file,
        )
        response.history = history.copy()

        location = response.headers.get("location")
        if (
            not follow_redirects
            or response.status_code not in (301, 302, 303, 307, 308)
            or not location
        ):
            return response

        next_url = urljoin(current_url, location)
        if urlparse(next_url).scheme != "https":
            return response

        history.append(HistoryEntry(current_url))
        current_url = next_url

    raise RequestException(f"Too many redirects: {url}")


def _send_single_request(
    url: str,
    method: str,
    headers: CaseInsensitiveDict,
    data: str | bytes | None,
    timeout: float,
    tls_mode: str,
    connect_host: str | None = None,
    cert_file: str | None = None,
    key_file: str | None = None,
) -> OpenSSLResponse:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise RequestException(f"OpenSSL TLS mode requires HTTPS targets: {url}")

    server_name = parsed.hostname or ""
    address = f"{connect_host or server_name}:{parsed.port or 443}"
    request_bytes = build_http_request(url, method, headers, data)

    try:
        completed = subprocess.run(
            build_openssl_args(address, server_name, tls_mode, cert_file, key_file),
            input=request_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RequestException(f"Request timeout: {url}") from exc
    except OSError as exc:
        raise RequestException(f"Failed to execute openssl: {exc}") from exc

    try:
        return parse_openssl_response(url, completed.stdout)
    except RequestException as exc:
        stderr = completed.stderr.decode("utf-8", errors="ignore").strip()
        if stderr:
            raise RequestException(f"{exc}: {stderr}") from exc
        raise


def build_http_request(
    url: str, method: str, headers: CaseInsensitiveDict, data: str | bytes | None
) -> bytes:
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    body = data.encode("utf-8") if isinstance(data, str) else (data or b"")
    request_headers = CaseInsensitiveDict(headers)
    request_headers["host"] = parsed.netloc
    request_headers["connection"] = "close"
    if "accept-encoding" not in request_headers:
        request_headers["accept-encoding"] = "identity"
    if body:
        request_headers["content-length"] = str(len(body))

    lines = [f"{method} {path} HTTP/1.1"]
    for key, value in request_headers.items():
        lines.append(f"{key}: {value}")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode("utf-8") + body


def parse_openssl_response(url: str, stdout: bytes) -> OpenSSLResponse:
    response_offset = stdout.find(b"HTTP/")
    if response_offset == -1:
        raise RequestException(f"There was a problem in the request to: {url}")

    response_stream = stdout[response_offset:]
    response = http.client.HTTPResponse(_FakeSocket(response_stream))
    response.begin()
    body = response.read()
    headers = CaseInsensitiveDict(dict(response.getheaders()))
    return OpenSSLResponse(url, response.status, headers, body)
