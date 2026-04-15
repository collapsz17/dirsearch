#!/usr/bin/env python3

import unittest

from lib.connection.openssl import (
    DIRECT_TLS_MODES,
    build_http_request,
    build_openssl_args,
    parse_openssl_response,
)
from lib.core.structures import CaseInsensitiveDict


class TestOpenSSLTransport(unittest.TestCase):
    def test_direct_tls_modes(self):
        self.assertIn("sslv3", DIRECT_TLS_MODES)
        self.assertIn("gost", DIRECT_TLS_MODES)

    def test_build_openssl_args_sslv3(self):
        args = build_openssl_args("example.com:443", "example.com", "sslv3")
        self.assertIn("-ssl3", args)
        self.assertIn("ALL:@SECLEVEL=0", args)

    def test_build_openssl_args_gost(self):
        args = build_openssl_args("example.com:443", "example.com", "gost")
        self.assertIn("-engine", args)
        self.assertIn("gost", args)
        self.assertIn("-legacy_server_connect", args)

    def test_build_openssl_args_with_client_certificate(self):
        args = build_openssl_args(
            "example.com:443",
            "example.com",
            "gost",
            "/tmp/client.pem",
            "/tmp/client.key",
        )
        self.assertEqual(args[args.index("-cert") + 1], "/tmp/client.pem")
        self.assertEqual(args[args.index("-key") + 1], "/tmp/client.key")

    def test_build_http_request_sets_required_headers(self):
        request = build_http_request(
            "https://example.com/test?q=1",
            "GET",
            CaseInsensitiveDict({"user-agent": "dirsearch"}),
            None,
        ).decode("utf-8")
        self.assertIn("GET /test?q=1 HTTP/1.1", request)
        self.assertIn("host: example.com", request.lower())
        self.assertIn("connection: close", request.lower())
        self.assertIn("accept-encoding: identity", request.lower())

    def test_parse_openssl_response(self):
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 5\r\n"
            b"Location: /next\r\n"
            b"\r\n"
            b"hello"
        )
        response = parse_openssl_response("https://example.com", raw)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "text/plain")
        self.assertEqual(b"".join(response.iter_content()), b"hello")


if __name__ == "__main__":
    unittest.main()
