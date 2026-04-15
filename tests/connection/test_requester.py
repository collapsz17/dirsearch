#!/usr/bin/env python3

import unittest

from lib.connection.requester import AsyncRequester, Requester
from lib.core.data import options


class TestRequesterClientCertificate(unittest.TestCase):
    def setUp(self):
        self.original_options = options.copy()
        options.update(
            {
                "proxy_auth": None,
                "headers": {},
                "random_agents": False,
                "data": None,
                "network_interface": None,
                "thread_count": 1,
                "auth": None,
                "auth_type": None,
                "proxies": [],
                "timeout": 5,
                "cert_file": None,
                "key_file": None,
            }
        )

    def tearDown(self):
        options.clear()
        options.update(self.original_options)

    def test_requester_uses_combined_cert_bundle(self):
        options["cert_file"] = "/tmp/client.pem"

        requester = Requester()

        self.assertEqual(requester._cert, "/tmp/client.pem")
        self.assertEqual(requester.session.cert, "/tmp/client.pem")
        requester.session.close()

    def test_requester_uses_separate_cert_and_key(self):
        options["cert_file"] = "/tmp/client.pem"
        options["key_file"] = "/tmp/client.key"

        requester = Requester()

        self.assertEqual(requester._cert, ("/tmp/client.pem", "/tmp/client.key"))
        self.assertEqual(requester.session.cert, ("/tmp/client.pem", "/tmp/client.key"))
        requester.session.close()

    def test_async_requester_uses_combined_cert_bundle(self):
        options["cert_file"] = "/tmp/client.pem"

        requester = AsyncRequester()

        self.assertEqual(requester._cert, "/tmp/client.pem")

    def test_async_requester_uses_separate_cert_and_key(self):
        options["cert_file"] = "/tmp/client.pem"
        options["key_file"] = "/tmp/client.key"

        requester = AsyncRequester()

        self.assertEqual(requester._cert, ("/tmp/client.pem", "/tmp/client.key"))


if __name__ == "__main__":
    unittest.main()
