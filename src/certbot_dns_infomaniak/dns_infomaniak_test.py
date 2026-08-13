# SPDX-FileCopyrightText: 2021-2022 Rene Luria <rene.luria@infomaniak.com>
# SPDX-FileCopyrightText: 2021-2022 Yannik Roth <info@fuechslein.ch>
# SPDX-FileCopyrightText: 2021      Romain Autran <romain.autran@2itea.ch>
# SPDX-License-Identifier: Apache-2.0
"""Tests for certbot_dns_infomaniak.dns_infomaniak."""

import io
import logging
import sys
import unittest
from unittest import mock

import requests_mock
from certbot.errors import PluginError

try:
    from certbot.compat import os
except ImportError:
    import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

from certbot_dns_infomaniak.dns_infomaniak import _APIDomain

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


FAKE_TOKEN = "xxxx"
RECORD_ID = 1001234


class AuthenticatorTest(
    test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest,
):
    """Class to test the Authenticator class."""
    def setUp(self) -> None:
        super().setUp()

        self.config = mock.MagicMock()

        os.environ["INFOMANIAK_API_TOKEN"] = FAKE_TOKEN

        from certbot_dns_infomaniak.dns_infomaniak import Authenticator
        self.auth = Authenticator(self.config, "infomaniak")

        self.mock_client = mock.MagicMock(default_propagation_seconds=15)

        self.auth._api_client = mock.MagicMock(return_value=self.mock_client)

        try:
            from certbot.display.util import notify  # noqa: F401
            notify_patch = mock.patch("certbot._internal.main.display_util.notify")
            self.mock_notify = notify_patch.start()
            self.addCleanup(notify_patch.stop)
            self.old_stdout = sys.stdout
            sys.stdout = io.StringIO()
        except ImportError:
            self.old_stdout = sys.stdout

    def tearDown(self) -> None:
        sys.stdout = self.old_stdout

    def test_perform(self) -> None:
        """Tests the perform function to see if client method is called."""
        self.auth.perform([self.achall])

        expected = [
            mock.call.add_txt_record(DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY),
        ]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self) -> None:
        """Tests mthe cleanup method to see if client method is called."""
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [
            mock.call.del_txt_record(DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY),
        ]
        self.assertEqual(expected, self.mock_client.mock_calls)


class APIDomainTest(unittest.TestCase):
    """Class to test the _APIDomain class."""
    record_name = "foo"
    record_content = "bar"
    record_ttl = 42

    def setUp(self) -> None:
        self.adapter = requests_mock.Adapter()

        self.client = _APIDomain(FAKE_TOKEN)
        self.client.baseUrl = "mock://endpoint"
        self.client.session.mount("mock", self.adapter)

    def _register_response(self, url, data=None, method=requests_mock.ANY) -> None:
        """Registers a reply in the requests mock.

        :param str url: url to register response
        :param dict data: data to return
        :param str method: method for which response is registered (default to all)
        """
        resp = {"result": "success", "data": data}
        self.adapter.register_uri(
            method,
            self.client.baseUrl + url,
            json=resp,
        )

    def _register_error(self, url, code, description) -> None:
        """Registers an error reply in the requests mock.

        :param str url: url to register response
        :param int code: error code
        :param str description: error description
        """
        resp = {"result": "error", "error": {"code": code, "description": description}}
        self.adapter.register_uri(
            requests_mock.ANY,
            self.client.baseUrl + url,
            json=resp,
        )

    def test_add_txt_record(self) -> None:
        """add_txt_record with normal params should succeed."""
        self._register_response(
            f"/2/zones/{DOMAIN}/exists",
            data=True,
        )
        self._register_response(
            f"/2/zones/{DOMAIN}/records",
            data={
                "id": RECORD_ID, "type": "TXT",
                "source": self.record_name,
                "target": self.record_content,
                "ttl": self.record_ttl,
            },
            method="POST",
        )
        self.client.add_txt_record(
            DOMAIN, self.record_name, self.record_content, self.record_ttl,
        )
        self.assertEqual(self.client.record_ids, [RECORD_ID])

    def test_add_txt_record_apex(self) -> None:
        """add_txt_record for zone apex should use '.' as source."""
        self._register_response(
            f"/2/zones/{DOMAIN}/exists",
            data=True,
        )
        self._register_response(
            f"/2/zones/{DOMAIN}/records",
            data={
                "id": RECORD_ID, "type": "TXT",
                "source": ".",
                "target": self.record_content,
                "ttl": self.record_ttl,
            },
            method="POST",
        )
        self.client.add_txt_record(
            DOMAIN, f"_acme-challenge.{DOMAIN}", self.record_content, self.record_ttl,
        )
        self.assertEqual(self.client.record_ids, [RECORD_ID])
        posted = self.adapter.request_history[-1].json()
        self.assertEqual(posted["source"], "_acme-challenge")

    def test_add_txt_record_subdomain(self) -> None:
        """add_txt_record for sub-domain should send relative source."""
        self._register_response(
            f"/2/zones/{DOMAIN}/exists",
            data=True,
        )
        self._register_response(
            f"/2/zones/{DOMAIN}/records",
            data={
                "id": RECORD_ID, "type": "TXT",
                "source": "_acme-challenge.mail",
                "target": self.record_content,
                "ttl": self.record_ttl,
            },
            method="POST",
        )
        self.client.add_txt_record(
            DOMAIN, f"_acme-challenge.mail.{DOMAIN}", self.record_content, self.record_ttl,
        )
        self.assertEqual(self.client.record_ids, [RECORD_ID])
        posted = self.adapter.request_history[-1].json()
        self.assertEqual(posted["source"], "_acme-challenge.mail")

    def test_add_txt_record_fail_to_find_domain(self) -> None:
        """add_txt_record with non existing domain should fail."""
        self._register_error(
            f"/2/zones/{DOMAIN}/exists",
            "object_not_found",
            "Zone does not exist",
        )
        # parent zone also does not exist
        parent = DOMAIN[DOMAIN.find(".") + 1:]
        self._register_error(
            f"/2/zones/{parent}/exists",
            "object_not_found",
            "Zone does not exist",
        )
        with self.assertRaises(PluginError):
            self.client.add_txt_record(
                DOMAIN, self.record_name, self.record_content, self.record_ttl,
            )

    def test_add_txt_record_fail_to_authenticate(self) -> None:
        """add_txt_record with wrong token should fail."""
        self._register_error(
            f"/2/zones/{DOMAIN}/exists",
            "not_authorized",
            "Authorization required",
        )
        with self.assertRaises(PluginError):
            self.client.add_txt_record(
                DOMAIN, self.record_name, self.record_content, self.record_ttl,
            )

    def test_del_txt_record(self) -> None:
        """del_txt_record with normal params should succeed."""
        self._register_response(
            f"/2/zones/{DOMAIN}/exists",
            data=True,
        )
        self._register_response(
            f"/2/zones/{DOMAIN}/records/{RECORD_ID}",
            data={
                "id": RECORD_ID, "type": "TXT",
                "source": self.record_name,
                "target": self.record_content,
                "ttl": self.record_ttl,
            },
        )
        self._register_response(
            f"/2/zones/{DOMAIN}/records/{RECORD_ID}",
            data=True,
            method="DELETE",
        )
        self.client.record_ids = [RECORD_ID]
        self.client.del_txt_record(
            DOMAIN, f"{self.record_name}.{DOMAIN}",
            self.record_content,
        )
        self.assertEqual(self.client.record_ids, [])

    def test_del_txt_record_fail_to_find_domain(self) -> None:
        """del_txt_record with non existing domain should fail."""
        self._register_error(
            f"/2/zones/{DOMAIN}/exists",
            "object_not_found",
            "Zone does not exist",
        )
        parent = DOMAIN[DOMAIN.find(".") + 1:]
        self._register_error(
            f"/2/zones/{parent}/exists",
            "object_not_found",
            "Zone does not exist",
        )
        self.client.record_ids = [RECORD_ID]
        with self.assertRaises(PluginError):
            self.client.del_txt_record(
                DOMAIN, self.record_name, self.record_content,
            )

    def test_del_txt_record_fail_to_authenticate(self) -> None:
        """del_txt_recod with wrong token should fail."""
        self._register_error(
            f"/2/zones/{DOMAIN}/exists",
            "not_authorized",
            "Authorization required",
        )
        self.client.record_ids = [RECORD_ID]
        with self.assertRaises(PluginError):
            self.client.del_txt_record(
                DOMAIN, self.record_name, self.record_content,
            )


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
