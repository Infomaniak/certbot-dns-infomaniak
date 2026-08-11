# SPDX-FileCopyrightText: 2021-2022 Rene Luria <rene.luria@infomaniak.com>
# SPDX-FileCopyrightText: 2021-2022 Yannik Roth <info@fuechslein.ch>
# SPDX-FileCopyrightText: 2021      Romain Autran <romain.autran@2itea.ch>
# SPDX-License-Identifier: Apache-2.0
"""DNS Authenticator for Infomaniak."""
import json
import logging

import idna
import requests
from certbot import errors
from certbot.plugins import dns_common

try:
    from certbot.compat import os
except ImportError:
    import os

logger = logging.getLogger(__name__)


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Infomaniak.

    This plugin enables usage of Infomaniak public API to complete``dns-01`` challenges.
    """

    description = "Automates dns-01 challenges using Infomaniak API"

    def __init__(self, *args, **kwargs) -> None:
        # super(Authenticator, self).__init__(*args, **kwargs)
        super().__init__(*args, **kwargs)
        self.token = ""
        self.credentials = None
        self._api_domain = None

    @classmethod
    def add_parser_arguments(cls, add) -> None:  # pylint: disable=arguments-differ
        super().add_parser_arguments(
            add, default_propagation_seconds=120,
        )
        add("credentials", help="Infomaniak credentials INI file.")

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return self.description

    def _setup_credentials(self) -> None:
        token = os.getenv("INFOMANIAK_API_TOKEN")
        if token is None:
            self.credentials = self._configure_credentials(
                "credentials",
                "Infomaniak credentials INI file",
                {
                    "token": "Infomaniak API token.",
                },
            )
            if not self.credentials:
                msg = "INFOMANIAK API Token not defined"
                raise errors.PluginError(msg)
            self.token = self.credentials.conf("token")
        else:
            self.token = token

    def _perform(self, domain, validation_name, validation) -> None:
        decoded_domain = idna.decode(domain)
        try:
            self._api_client().add_txt_record(decoded_domain, validation_name, validation)
        except ValueError as err:
            msg = f"Cannot add txt record: {err}"
            raise errors.PluginError(msg)

    def _cleanup(self, domain, validation_name, validation) -> None:
        decoded_domain = idna.decode(domain)
        try:
            self._api_client().del_txt_record(decoded_domain, validation_name, validation)
        except ValueError as err:
            msg = f"Cannot del txt record: {err}"
            raise errors.PluginError(msg)

    def _api_client(self):
        if self._api_domain is None:
            self._api_domain = _APIDomain(self.token)
        return self._api_domain


class _APIDomain:

    baseUrl = "https://api.infomaniak.com"

    def __init__(self, token) -> None:
        """Initialize class managing a domain within Infomaniak API.

        :param str token: oauth2 token to consume Infomaniak API
        """
        self.token = token
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {self.token}"})
        self.record_ids = []

    def _get_request(self, url, payload=None):
        """Performs a GET request against API.

        :param str url: relative url
        :param dict payload : body of request
        """
        url = self.baseUrl + url
        logger.debug("GET %s", url)
        with self.session.get(url, params=payload) as req:
            try:
                result = req.json()
            except json.decoder.JSONDecodeError as exc:
                msg = "no JSON in API response"
                raise errors.PluginError(msg) from exc
            if result["result"] == "success":
                return result["data"]
            if result["error"]["code"] == "not_authorized":
                msg = "cannot authenticate"
                raise errors.PluginError(msg)
            msg = (
                "error in API request: {} / {}".format(
                    result["error"]["code"], result["error"]["description"],
                )
            )
            raise errors.PluginError(
                msg,
            )

    def _post_request(self, url, payload):
        """Performs a POST request.

        :param str url: relative url
        :param dict payload : body of request
        """
        url = self.baseUrl + url
        headers = {"Content-Type": "application/json"}
        json_data = json.dumps(payload)
        logger.debug("POST %s", url)
        with self.session.post(url, data=json_data, headers=headers) as req:
            try:
                result = req.json()
            except json.decoder.JSONDecodeError as exc:
                msg = "no JSON in API response"
                raise errors.PluginError(msg) from exc
            if result["result"] == "success":
                return result["data"]
            msg = (
                "error in API request: {} / {}".format(
                    result["error"]["code"], result["error"]["description"],
                )
            )
            raise errors.PluginError(
                msg,
            )

    def _delete_request(self, url):
        """Performs a POST request.

        :param str url: relative url
        """
        url = self.baseUrl + url
        logger.debug("DELETE %s", url)
        with self.session.delete(url) as req:
            try:
                result = req.json()
            except json.decoder.JSONDecodeError as exc:
                msg = "no JSON in API response"
                raise errors.PluginError(msg) from exc
            if result["result"] == "success":
                return result["data"]
            msg = (
                "error in API request: {} / {}".format(
                    result["error"]["code"], result["error"]["description"],
                )
            )
            raise errors.PluginError(
                msg,
            )

    def _find_zone(self, domain):
        """Finds the corresponding DNS zone through the API.

        :param str domain: domain name

        :returns: zone name
        """
        while "." in domain:
            try:
                result = self._get_request(
                    f"/2/zones/{domain}/exists",
                )
            except errors.PluginError as err:
                if "cannot authenticate" in str(err):
                    raise
                result = False
            if result is True:
                return domain
            domain = domain[domain.find(".") + 1:]
        msg = "Domain not found"
        raise errors.PluginError(msg)

    def add_txt_record(self, domain, source, target, ttl=300) -> None:
        """Add a TXT DNS record to a domain.

        :param str domain: domain name to lookup
        :param str source: record key in zone (left prefix before domain)
        :param str target: value of record
        :param int ttl: optional ttl of record to create
        """
        logger.debug("add_txt_record %s %s %s", domain, source, target)
        zone = self._find_zone(domain)
        logger.debug("%s", zone)
        if source.endswith("." + idna.encode(zone).decode("ascii")):
            relative_source = source[:source.rfind("." + idna.encode(zone).decode("ascii"))]
        else:
            relative_source = source
        logger.debug("add_txt_record %s %s %s", zone, relative_source, target)
        data = {"type": "TXT", "source": relative_source, "target": target, "ttl": ttl}
        result = self._post_request(f"/2/zones/{zone}/records", data)
        self.record_ids.append(result["id"])

    def del_txt_record(self, domain, source, target) -> None:
        """Delete a TXT DNS record from a domain.

        :param str source: record key in zone (left prefix before domain)
        :param str target: value of record
        """
        logger.debug("del_txt_record %s %s %s", domain, source, target)
        zone = self._find_zone(domain)
        if not self.record_ids:
            msg = "Record not found"
            raise errors.PluginError(msg)
        for record_id in self.record_ids:
            logger.debug("del_txt_record %s %s", zone, record_id)
            try:
                self._get_request(f"/2/zones/{zone}/records/{record_id}")
            except errors.PluginError:
                continue
            self._delete_request(f"/2/zones/{zone}/records/{record_id}")
            self.record_ids.remove(record_id)
            return
