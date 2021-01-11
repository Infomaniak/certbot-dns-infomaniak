"""DNS Authenticator for Infomaniak"""
import json
import logging
import os

import requests
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Infomaniak

    This plugin enables usage of Infomaniak public API to complete``dns-01`` challenges."""

    description = "Automates dns-01 challenges using Infomaniak API"

    def __init__(self, *args, **kwargs):
        # super(Authenticator, self).__init__(*args, **kwargs)
        super().__init__(*args, **kwargs)
        self.token = ""

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return self.description

    def _setup_credentials(self):
        token = os.getenv("INFOMANIAK_API_TOKEN")
        if token is None:
            raise errors.PluginError("INFOMANIAK_API_TOKEN variable not defined")
        self.token = token

    def _perform(self, domain, validation_name, validation):
        try:
            self._api_client().add_txt_record(domain, validation_name, validation)
        except ValueError as err:
            raise errors.PluginError("Cannot add txt record: {err}".format(err=err))

    def _cleanup(self, domain, validation_name, validation):
        try:
            self._api_client().del_txt_record(domain, validation_name, validation)
        except ValueError as err:
            raise errors.PluginError("Cannot del txt record: {err}".format(err=err))

    def _api_client(self):
        return _APIDomain(self.token)


class _APIDomain:

    baseUrl = "https://api.infomaniak.com"

    def __init__(self, token):
        """Initialize class managing a domain within Infomaniak API

        :param str token: oauth2 token to consume Infomaniak API
        """
        self.token = token
        self.session = requests.Session()
        self.session.headers.update({"Authorization": "Bearer {token}".format(token=self.token)})

    def get_request(self, url, payload=None):
        """Performs a GET request against API

        :param str url: relative url
        :param dict payload : body of request
        """
        url = self.baseUrl + url
        logger.debug("GET %s", url)
        with self.session.get(url, params=payload) as req:
            try:
                result = req.json()
            except json.decoder.JSONDecodeError as exc:
                raise errors.PluginError("no JSON in API response") from exc
            if result["result"] == "success":
                return result["data"]
            if result["error"]["code"] == "not_authorized":
                raise errors.PluginError("cannot authenticate")
            raise errors.PluginError(
                "error in API request: {} / {}".format(
                    result["error"]["code"], result["error"]["description"]
                )
            )

    def post_request(self, url, payload):
        """Performs a POST request

        :param str url: relative url
        :param dict payload : body of request
        """
        url = self.baseUrl + url
        logger.debug("POST %s", url)
        with self.session.post(url, data=payload) as req:
            try:
                result = req.json()
            except json.decoder.JSONDecodeError as exc:
                raise errors.PluginError("no JSON in API response") from exc
            if result["result"] == "success":
                return result["data"]
            raise errors.PluginError(
                "error in API request: {} / {}".format(
                    result["error"]["code"], result["error"]["description"]
                )
            )

    def delete_request(self, url):
        """Performs a POST request

        :param str url: relative url
        """
        url = self.baseUrl + url
        logger.debug("DELETE %s", url)
        with self.session.delete(url) as req:
            try:
                result = req.json()
            except json.decoder.JSONDecodeError as exc:
                raise errors.PluginError("no JSON in API response") from exc
            if result["result"] == "success":
                return result["data"]
            raise errors.PluginError(
                "error in API request: {} / {}".format(
                    result["error"]["code"], result["error"]["description"]
                )
            )

    def get_records(self, domain, domain_id, rtype, source, target):
        """Find record matching arguments

        :param str domain: domain name
        :param int domain_id: domain id
        :param str rtype: type of record (A, TXT, ...)
        :param str source: record key in zone
        :param str target: value of record to match
        """
        if source == ".":
            fqdn = domain
        else:
            fqdn = "{source}.{domain}".format(source=source, domain=domain)
        return list(
            filter(
                lambda x: (
                    x["source_idn"] == fqdn
                    and x["type"] == rtype
                    and x["target"] == target
                ),
                self.get_request("/1/domain/{domain_id}/dns/record".format(domain_id=domain_id)),
            )
        )

    def find_zone(self, domain):
        while "." in domain:
            result = self.get_request(
                "/1/product?service_name=domain&customer_name={domain}".format(domain=domain),
            )
            if len(result) == 1:
                return (
                    result[0]["id"],
                    domain,
                )
            domain = domain[domain.find(".") + 1:]
        raise errors.PluginError("Domain not found")

    def add_txt_record(self, domain, source, target, ttl=300):
        """Add a TXT DNS record to a domain

        :param str domain: domain name to lookup
        :param str source: record key in zone (left prefix before domain)
        :param str target: value of record
        :param int ttl: optional ttl of record to create
        """
        logger.debug("add_txt_record %s %s %s", domain, source, target)

        (domain_id, domain_name) = self.find_zone(domain)
        logger.debug("%s / %s", domain_id, domain_name)

        source = source[: source.rfind("." + domain_name)]

        logger.debug("add_txt_record %s %s %s", domain_name, source, target)

        data = {"type": "TXT", "source": source, "target": target, "ttl": ttl}
        self.post_request("/1/domain/{domain_id}/dns/record".format(domain_id=domain_id), data)

    def del_txt_record(self, domain, source, target, ttl=300):
        """Delete a TXT DNS record from a domain

        :param str source: record key in zone (left prefix before domain)
        :param str target: value of record
        :param int ttl: optional ttl of record to create
        """

        logger.debug("del_txt_record %s %s %s", domain, source, target)

        (domain_id, domain_name) = self.find_zone(domain)

        source = source[: source.rfind("." + domain_name)]

        records = self.get_records(domain_name, domain_id, "TXT", source, target)
        if records is None:
            raise errors.PluginError("Record not found")
        elif len(records) > 1:
            raise errors.PluginError("Several records match")
        record_id = records[0]["id"]

        self.delete_request("/1/domain/{domain_id}/dns/record/{record_id}".format(
            domain_id=domain_id, record_id=record_id))
