"""Tests for BlackKiteParserBot

SPDX-FileCopyrightText: 2023 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import json
import unittest
from datetime import datetime

import intelmq.lib.message as message
from dateutil.tz import UTC

from intelmq_extensions.bots.parsers.blackkite.parser import BlackKiteParserBot

from ....base import BotTestCase
from .data import (
    APPLICATION_SECURITY,
    CREDENTIAL_MANAGEMENT,
    DEFAULT_COMPANY,
    PATCH_MANAGEMENT,
)


class TestBlackKiteParserBot(BotTestCase, unittest.TestCase):
    @classmethod
    def set_bot(cls):
        cls.bot_reference = BlackKiteParserBot
        cls.sysconfig = {}

    def _create_report_dict(self, finding_data: dict, company_data: dict = None):
        company_data = company_data or DEFAULT_COMPANY
        raw = {"company": company_data, "finding": finding_data}

        data = {
            "feed.accuracy": 100.0,
            "time.observation": datetime(2023, 1, 1, tzinfo=UTC).isoformat(),
        }

        report = message.Report(data, harmonization=self.harmonization)
        report.add("raw", json.dumps(raw))
        return report.to_dict(with_type=True)

    def _create_event_dict(
        self,
        ip: str = "127.0.0.1",
        fqdn: str = None,
        event_id: int = 1,
        monitored_asset: str = "cert.at",
        identifier: str = "bk-patch",
        taxonomy: str = "vulnerable",
        type_: str = "vulnerable-system",
        **kwargs,
    ):
        data = {
            "classification.identifier": identifier,
            "classification.taxonomy": taxonomy,
            "classification.type": type_,
            "source.fqdn": fqdn,
            "source.ip": ip,
            "extra.feed_event_id": event_id,
            "extra.blackkite_company_id": 1,
            "feed.accuracy": 100.0,
            "extra.monitored_asset": monitored_asset,  # Domain from Company
            "time.observation": datetime(2023, 1, 1, tzinfo=UTC).isoformat(),
            **kwargs,
        }
        event = message.Event(data, harmonization=self.harmonization)
        if "time.source" not in event:
            event.add("time.source", "2023-08-28T13:37:22.717")
        event.add("raw", json.dumps({"company": {}, "finding": {}}))
        return event.to_dict(with_type=True)

    def test_parse_patch_management_finding(self):
        self.input_message = self._create_report_dict(PATCH_MANAGEMENT)

        self.run_bot()

        expected = {
            "identifier": "cve-2023-38408",
            "event_description.text": PATCH_MANAGEMENT["Detail"],
            "event_description.url": "https://nvd.nist.gov/vuln/detail/CVE-2023-38408",
            "extra.vendor": "openbsd",
            "extra.product": "openssh",
            "extra.product_name": "openssh_/5.9",
            "extra.vulnerabilities": "cve-2023-38408",
            # Cvss score? Severity?
            "feed.documentation": "https://cyber.riskscore.cards/kb/PATCH-001",
            "feed.code": "blackkite-patch",
            "feed.name": "BlackKite PATCH",
        }
        self.assertMessageEqual(
            0, self._create_event_dict(**expected), compare_raw=False
        )

    def test_handling_domain_in_ip_field(self):
        "This is a workaround for bug in BlackKite, already reported. See Taiga#808"
        msg = PATCH_MANAGEMENT.copy()
        msg["IpAddress"] = "override.example.at"
        self.input_message = self._create_report_dict(msg)

        self.run_bot()

        expected = {
            "source.ip": None,
            # "source.fqdn": "override.example.at", FIXME: Wait for explanation from BlackKite
            "identifier": "cve-2023-38408",
            "event_description.text": PATCH_MANAGEMENT["Detail"],
            "event_description.url": "https://nvd.nist.gov/vuln/detail/CVE-2023-38408",
            "extra.vendor": "openbsd",
            "extra.product": "openssh",
            "extra.product_name": "openssh_/5.9",
            "extra.vulnerabilities": "cve-2023-38408",
            "feed.documentation": "https://cyber.riskscore.cards/kb/PATCH-001",
            "feed.code": "blackkite-patch",
            "feed.name": "BlackKite PATCH",
        }
        self.assertMessageEqual(
            0, self._create_event_dict(**expected), compare_raw=False
        )

    def test_parse_patch_management_finding_without_cve(self):
        # e.g. EoL software
        msg = PATCH_MANAGEMENT.copy()
        msg["ControlId"] = "PATCH-010"
        msg["CveId"] = None
        self.input_message = self._create_report_dict(msg)

        self.run_bot()

        expected = {
            "identifier": "end-of-live",
            "event_description.text": msg["Detail"],
            "event_description.url": "https://nvd.nist.gov/vuln/detail/CVE-2023-38408",
            "extra.vendor": "openbsd",
            "extra.product": "openssh",
            "extra.product_name": "openssh_/5.9",
            # Cvss score? Severity?
            "feed.documentation": "https://cyber.riskscore.cards/kb/PATCH-010",
            "feed.code": "blackkite-patch",
            "feed.name": "BlackKite PATCH",
        }
        self.assertMessageEqual(
            0, self._create_event_dict(**expected), compare_raw=False
        )

    def test_parse_application_security_finding(self):
        self.input_message = self._create_report_dict(APPLICATION_SECURITY)

        self.run_bot()

        expected = {
            "classification.taxonomy": "vulnerable",
            "classification.type": "potentially-unwanted-accessible",
            "identifier": "bk-appsec",
            "event_description.text": (
                "Cleartext Transmission of Sensitive Information. "
                "Not encrypted communication on xxx."
            ),
            "feed.documentation": "https://cyber.riskscore.cards/kb/APPSEC-014",
            "extra.feed_event_id": 658443,
            "source.ip": None,
            "feed.code": "blackkite-appsec",
            "feed.name": "BlackKite APPSEC",
        }
        self.assertMessageEqual(
            0, self._create_event_dict(**expected), compare_raw=False
        )

    def test_parse_credential_management_finding(self):
        self.input_message = self._create_report_dict(CREDENTIAL_MANAGEMENT)

        self.run_bot()

        expected = {
            "classification.taxonomy": "information-content-security",
            "classification.type": "data-leak",
            "classification.identifier": "leaked-credentials",
            "source.fqdn": "example.cert.at",
            "extra.monitored_asset": "cert.at",
            "feed.documentation": "https://cyber.riskscore.cards/kb/LEAK-003",
            "source.account": "user@example.cert.at",
            "extra.account": "user@example.cert.at",  # intentionally twice
            "extra.password": "PLAIN",  # BK doesn't provide us more info
            "extra.compromise_time_full": "2022-09-22T00:00:00",
            "extra.compromise_time": "2022-09",
            "extra.leak_source": "cert_com_leak",
            "source.ip": None,
            "extra.feed_event_id": 44823698,
            # This feed doesn't have a proper source time, use observation instead
            "time.source": datetime(2023, 1, 1, tzinfo=UTC).isoformat(),
            "feed.code": "blackkite-leak",
            "feed.name": "BlackKite LEAK",
        }
        self.assertMessageEqual(
            0, self._create_event_dict(**expected), compare_raw=False
        )
