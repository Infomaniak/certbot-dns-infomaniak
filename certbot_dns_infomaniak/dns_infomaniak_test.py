"""Tests for certbot_dns_infomaniak.dns_infomaniak."""

import unittest

import mock
import logging
import os
import requests_mock

from certbot.errors import PluginError
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

logger = logging.getLogger(__name__)


FAKE_TOKEN = "xxxx"


class AuthenticatorTest(
    test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest
):
    def setUp(self):
        super().setUp()

        from certbot_dns_infomaniak.dns_infomaniak import Authenticator

        self.config = mock.MagicMock()

        os.environ["INFOMANIAK_API_TOKEN"] = FAKE_TOKEN

        self.auth = Authenticator(self.config, "infomaniak")

        self.mock_client = mock.MagicMock()
        # _get_ispconfig_client | pylint: disable=protected-access
        self.auth._api_client = mock.MagicMock(return_value=self.mock_client)

    def test_perform(self):
        self.auth.perform([self.achall])

        expected = [
            mock.call.add_txt_record(DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY)
        ]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [
            mock.call.del_txt_record(DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY)
        ]
        self.assertEqual(expected, self.mock_client.mock_calls)


class APIDomainTest(unittest.TestCase):
    record_name = "foo"
    record_content = "bar"
    record_ttl = 42

    def setUp(self):
        from certbot_dns_infomaniak.dns_infomaniak import _APIDomain

        self.adapter = requests_mock.Adapter()

        self.client = _APIDomain(FAKE_TOKEN)
        self.client.baseUrl = "mock://endpoint"
        self.client.session.mount("mock", self.adapter)

    def _register_response(self, url, data=None, method=requests_mock.ANY):
        resp = {"result": "success", "data": data}
        self.adapter.register_uri(
            method,
            self.client.baseUrl + url,
            json=resp,
        )

    def _register_error(self, url, code, description):
        resp = {"result": "error", "error": {"code": code, "description": description}}
        self.adapter.register_uri(
            requests_mock.ANY,
            self.client.baseUrl + url,
            json=resp,
        )

    def test_add_txt_record(self):
        self._register_response(
            "/1/product?service_name=domain&customer_name={domain}".format(domain=DOMAIN),
            data=[
                {
                    "id": 654321,
                    "account_id": 1234,
                    "service_id": 14,
                    "service_name": "domain",
                    "customer_name": DOMAIN,
                }
            ],
        )
        self._register_response("/1/domain/654321/dns/record", "1001234", "POST")
        self.client.add_txt_record(
            DOMAIN, self.record_name, self.record_content, self.record_ttl
        )

    def test_add_txt_record_fail_to_find_domain(self):
        self._register_response(
            "/1/product?service_name=domain&customer_name={domain}".format(domain=DOMAIN),
            data=[],
        )
        with self.assertRaises(PluginError):
            self.client.add_txt_record(
                DOMAIN, self.record_name, self.record_content, self.record_ttl
            )

    def test_add_txt_record_fail_to_authenticate(self):
        self._register_error(
            "/1/product?service_name=domain&customer_name={domain}".format(domain=DOMAIN),
            "not_authorized",
            "Authorization required",
        )
        with self.assertRaises(PluginError):
            self.client.add_txt_record(
                DOMAIN, self.record_name, self.record_content, self.record_ttl
            )

    def test_del_txt_record(self):
        self._register_response(
            "/1/product?service_name=domain&customer_name={domain}".format(domain=DOMAIN),
            data=[
                {
                    "id": "654321",
                    "account_id": "1234",
                    "service_id": "14",
                    "service_name": "domain",
                    "customer_name": DOMAIN,
                }
            ],
        )
        self._register_response(
            "/1/domain/654321/dns/record",
            [
                {
                    "id": "11110",
                    "source": ".",
                    "source_idn": DOMAIN,
                    "type": "NS",
                    "ttl": 3600,
                    "target": "ns1.death.star",
                },
                {
                    "id": "11111",
                    "source": self.record_name,
                    "source_idn": "{name}.{domain}".format(name=self.record_name, domain=DOMAIN),
                    "type": "TXT",
                    "ttl": self.record_ttl,
                    "target": self.record_content,
                },
            ],
        )
        self._register_response(
            "/1/domain/654321/dns/record/11111",
            True,
            "DELETE",
        )
        self.client.del_txt_record(
            DOMAIN, "{name}.{domain}".format(name=self.record_name, domain=DOMAIN), self.record_content, self.record_ttl
        )

    def test_del_txt_record_fail_to_find_domain(self):
        self._register_response(
            "/1/product?service_name=domain&customer_name={domain}".format(domain=DOMAIN),
            data=[],
        )
        with self.assertRaises(PluginError):
            self.client.del_txt_record(
                DOMAIN, self.record_name, self.record_content, self.record_ttl
            )

    def test_del_txt_record_fail_to_authenticate(self):
        self._register_error(
            "/1/product?service_name=domain&customer_name={domain}".format(domain=DOMAIN),
            "not_authorized",
            "Authorization required",
        )
        with self.assertRaises(PluginError):
            self.client.del_txt_record(
                DOMAIN, self.record_name, self.record_content, self.record_ttl
            )


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
