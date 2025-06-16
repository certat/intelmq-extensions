"""Transformers for the BlackKite

SPDX-FileCopyrightText: 2023 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

from abc import ABC
from datetime import datetime
from typing import Iterable, Sequence

import dateutil.parser
from dateutil.tz import UTC
from intelmq.lib.harmonization import IPAddress

from intelmq_extensions.lib.blackkite import Category


class BaseTransformer(ABC):
    DEFAULT_CLASSIFICATION = ("", "", "")
    CLASSIFICATION_MAP: dict[str, tuple] = {}
    _COMMON_FIELDS = (
        ("extra.feed_event_id", "FindingId"),
        # In general, the Domain field does not represent the affected domain.
        # It can be a primary domain of the affected URL, or just the domain
        # configured for the given company, without direct relation to the finding.
        # FIXME: waiting for BlackKite response on how to get the affected URL
        ("source.fqdn", "", "get_domain"),
        ("source.ip", "IpAddress", "get_ip"),
        ("event_description.text", "Detail", "get_description"),
        # The date that Black Kite first seen the finding.
        ("time.source", "FindingDate"),
        ("feed.documentation", "ControlId", "get_documentation_url"),
    )
    SPECIFIC_FIELDS = ()

    def __init__(self) -> None:
        self._data = None
        self._transformed = {}

    def to_events_data(self, incident_data: dict) -> Iterable[dict]:
        self._data = incident_data
        self._transformed = {}
        self._finding_id = incident_data.get("ControlId")
        self.transform()
        for event_data in self.transform_single():
            yield event_data

    def _map(self, event_key: str, finding_key: str, mapper: str = None):
        if finding_key in self._data:
            if not mapper:
                self._transformed[event_key] = self._data[finding_key]
            else:
                self._transformed[event_key] = getattr(self, mapper)(finding_key)

    def _map_many(self, mappings: Sequence[tuple]):
        for mapping in mappings:
            self._map(*mapping)

    def _map_classification(self):
        taxonomy, type_, identifier = self.CLASSIFICATION_MAP.get(
            self._finding_id, self.DEFAULT_CLASSIFICATION
        )
        self._transformed["classification.taxonomy"] = taxonomy
        self._transformed["classification.type"] = type_
        self._transformed["classification.identifier"] = identifier

    def _map_feed_data(self):
        category = self._data.get("ControlId", "").split("-")[0]
        self._transformed["feed.code"] = f"blackkite-{category.lower()}"
        self._transformed["feed.name"] = f"BlackKite {category.upper()}"

    def get_description(self, _):
        description = []
        if title := self._data.get("Title"):
            description.append(title)
        if detail := self._data.get("Detail"):
            description.append(detail)
        return ". ".join(description)

    def transform(self):
        self._map_classification()
        self._map_feed_data()
        self._map_many(self._COMMON_FIELDS)
        self._map_many(self.SPECIFIC_FIELDS)

    def transform_single(self) -> Iterable[dict]:
        """If an incident produce multiple events,
        this method should do the extraction and transformation"""

        yield self._transformed

    def get_documentation_url(self, _):
        return f"https://cyber.riskscore.cards/kb/{self._finding_id}"

    def lower(self, field: str) -> str:
        return (self._data.get(field) or "").lower()

    def get_ip(self, field: str):
        # BlackKite can send domain in the IPAddress field
        ip_data = self._data.get(field)
        if IPAddress.is_valid(ip_data, sanitize=True):
            return ip_data
        return None

    def get_domain(self, field: str):
        # BlackKite can send domain in the IPAddress field
        # as it's then a better domain, this should be used
        if ip_data := self._data.get("IpAddress"):
            if not IPAddress.is_valid(ip_data):
                return ip_data

        if field:
            return self._data.get(field)

    def get_first(self, field: str) -> str:
        """Get first item from the list"""
        items = self._data.get(field)
        if items:
            return items[0]
        return None


class PatchManagementTransformer(BaseTransformer):
    DEFAULT_CLASSIFICATION = ("vulnerable", "vulnerable-system", "bk-patchmanagement")
    CLASSIFICATION_MAP = {
        "PATCH-010": ("vulnerable", "vulnerable-system", "end-of-live")
    }
    SPECIFIC_FIELDS = (
        ("extra.product_name", "ProductName"),
        # lower to match with data from other sources
        ("extra.vulnerabilities", "CveId", "lower"),
        ("event_description.url", "References", "get_first"),
    )

    def _map_cpe(self):
        cpes = self._data.get("Cpes")
        if not cpes:
            return
        cpe_data = cpes[0].split(":")
        self._transformed["extra.vendor"] = cpe_data[3]
        self._transformed["extra.product"] = cpe_data[4]

    def _map_cve_to_identifier(self):
        if cve_id := self._data.get("CveId"):
            self._transformed["classification.identifier"] = cve_id.lower()

    def transform(self) -> Iterable[dict]:
        super().transform()
        self._map_cpe()
        self._map_cve_to_identifier()


class ApplicationSecurityTransformer(BaseTransformer):
    CLASSIFICATION_MAP = {
        "APPSEC-014": ("vulnerable", "potentially-unwanted-accessible", "bk-appsec")
    }


class CredentialManagementTransformer(BaseTransformer):
    DEFAULT_CLASSIFICATION = (
        "information-content-security",
        "data-leak",
        "leaked-credentials",
    )
    SPECIFIC_FIELDS = (
        ("source.fqdn", "EmailorUsername", "get_domain_from_email"),
        ("source.account", "EmailorUsername"),
        ("extra.account", "EmailorUsername"),
        ("extra.password", "PasswordType"),
        ("extra.compromise_time_full", "LeakDate"),
        ("extra.compromise_time", "LeakDate", "get_compromise_time"),
        ("extra.leak_source", "Source"),
    )
    _DESCRIPTION = (
        "A user with email in your domain"
        " was found in leaked credentials related to: {source}"
    )
    _COMPROMISE_TIME_FORMAT = "%Y-%m"

    def get_description(self, _):
        return self._DESCRIPTION.format(source=self._data.get("Source"))

    def get_compromise_time(self, _):
        # return the month only, as in DISP parser
        date_str = self._data.get("LeakDate")
        if not date_str:
            return None
        date: datetime = dateutil.parser.parse(date_str).astimezone(tz=UTC)
        return date.strftime(self._COMPROMISE_TIME_FORMAT)

    def get_domain_from_email(self, field):
        data = self._data.get(field)
        if "@" in data:
            return data.split("@")[-1]
        return None


TRANSFORMERS_MAPPER: dict[Category, BaseTransformer] = {
    Category.PatchManagement: PatchManagementTransformer(),
    Category.ApplicationSecurity: ApplicationSecurityTransformer(),
    Category.CredentialManagement: CredentialManagementTransformer(),
}
