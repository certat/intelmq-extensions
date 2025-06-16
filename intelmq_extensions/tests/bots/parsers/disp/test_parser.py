"""Tests for DISPParserBot

SPDX-FileCopyrightText: 2023 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import json
import unittest
from copy import deepcopy
from datetime import datetime

import intelmq.lib.message as message
from dateutil.tz import UTC
from intelmq.lib.test import skip_internet

from intelmq_extensions.bots.parsers.disp.parser import DISPParserBot

from ....base import BotTestCase


class TestDISPParserBot(BotTestCase, unittest.TestCase):
    @classmethod
    def set_bot(cls):
        cls.bot_reference = DISPParserBot
        cls.sysconfig = {
            "default_fields": {
                "classification.taxonomy": "information-content-security",
                "classification.type": "data-leak",
                "classification.identifier": "leaked-credentials",
                "comment": "A comment",
            }
        }

    def _create_report_dict(self, credentials, id_: str = "id-1", **kwargs):
        incident_data = {
            "id": id_,
            "creationDate": 1693391274125,
            "publishedDate": 1693391312517,
            "title": "Credentials compromised by malware-1 botnet",
            "category": "Information discovery",
            "type": "Credentials",
            "detectionDate": 1693391031733,
            "validationDate": 1693391274125,
            "updateDate": 1693391446948,
            "riskLevel": "High",
            "tags": [
                "family: malware-1",
                "type: InfoStealer",
            ],
            "relatedAssets": ["example.at"],
        }
        default_credentials = {
            "malware": "malware-1",
            "date": "",
            "application": "Some App XXX",
            "url": "https://some.example.at/",
            "username": "my-user-1",
            "password": "pas*****",
        }
        credentials_data = []
        for credential in credentials:
            c_data = deepcopy(default_credentials)
            c_data.update(credential)
            credentials_data.append(c_data)
        evidence_data = {"credentials": credentials_data}

        raw = {"incident": incident_data, "evidences": evidence_data}
        data = {
            "feed.name": "Test Bot",
            "feed.accuracy": 100.0,
            "feed.code": "feed-code",
            "time.observation": datetime(2023, 1, 1, tzinfo=UTC).isoformat(),
        }
        data.update(kwargs)
        report = message.Report(data, harmonization=self.harmonization)
        report.add("raw", json.dumps(raw))
        return report.to_dict(with_type=True)

    def _create_event_dict(
        self,
        username: str = "my-user-1",
        password: str = "pas*****",
        fqdn: str = "some.example.at",
        url: str = "https://some.example.at/",
        urlpath: str = "/",
        full_url: str = "hxxps://some.example.at/",
        compromise_time: str = "",
        incident_data: dict = None,
        evidences_data: dict = None,
        compromise_time_full: str = None,
        ip: str = None,
        **kwargs,
    ):
        data = {
            "classification.identifier": "leaked-credentials",
            "classification.taxonomy": "information-content-security",
            "classification.type": "data-leak",
            "comment": "A comment",
            "event_description.text": "Credentials compromised by malware-1 botnet",
            "source.fqdn": fqdn,
            "source.urlpath": urlpath,
            "source.url": url,
            "source.ip": ip,
            "source.account": username,
            "extra.account": username,  # Intentionally copied
            "extra.password": password,
            "extra.compromise_time": compromise_time,
            "extra.compromise_time_full": compromise_time_full,
            "extra.application": "Some App XXX",
            "extra.full_url": full_url,
            "extra.feed_event_id": "id-1",
            "malware.name": "malware-1",
            "feed.code": "feed-code",
            "feed.name": "Test Bot",
            "feed.accuracy": 100.0,
            "extra.monitored_asset": "example.at",  # Domain we monitor in DISP
            "time.observation": datetime(2023, 1, 1, tzinfo=UTC).isoformat(),
        }
        data.update(kwargs)
        event = message.Event(data, harmonization=self.harmonization)
        event.add(
            "time.source",
            datetime.fromtimestamp(1693391274125 // 1000, tz=UTC).isoformat(),
        )
        event.add(
            "raw", json.dumps({"incident": incident_data, "evidences": evidences_data})
        )
        return event.to_dict(with_type=True)

    def test_parsing_report_default(self):
        self.input_message = self._create_report_dict(
            [
                {
                    "malware": "malware-1",
                    "date": "",
                    "application": "Some App XXX",
                    "url": "https://some.example.at/",
                    "username": "my-user-1",
                    "password": "pas*****",
                },
                {
                    "malware": "malware-1",
                    "date": "09.27.2021 16:17:18",
                    "application": "Some App XXX",
                    "url": "https://example.at/some/sub/page",
                    "username": "my-user-2",
                    "password": "lea*******",
                },
            ],
        )

        self.run_bot()

        self.assertMessageEqual(
            0,
            self._create_event_dict(username="my-user-1", password="pas*****"),
            compare_raw=False,
        )
        self.assertMessageEqual(
            1,
            self._create_event_dict(
                username="my-user-2",
                password="lea*******",
                fqdn="example.at",
                url="https://example.at/[REDACTED]",
                urlpath="/[REDACTED]",
                full_url="hxxps://example.at/some/sub/page",
                compromise_time="2021-09",
                compromise_time_full="09.27.2021 16:17:18",
            ),
            compare_raw=False,
        )

    def test_compromise_time_settings(self):
        report = self._create_report_dict([{"date": "09.27.2021 16:17:18"}])

        self.input_message = deepcopy(report)
        self.run_bot(parameters={"compromise_time_format": "original"})
        self.assertMessageEqual(
            0,
            self._create_event_dict(
                compromise_time="09.27.2021 16:17:18",
                compromise_time_full="09.27.2021 16:17:18",
            ),
            compare_raw=False,
        )

        self.input_message = deepcopy(report)
        self.run_bot(parameters={"compromise_time_format": ""})
        self.assertMessageEqual(
            0,
            self._create_event_dict(
                compromise_time="",
                compromise_time_full="09.27.2021 16:17:18",
            ),
            compare_raw=False,
        )

        self.input_message = deepcopy(report)
        self.run_bot(parameters={"compromise_time_format": "%Y-%m-%d"})
        self.assertMessageEqual(
            0,
            self._create_event_dict(
                compromise_time="2021-09-27",
                compromise_time_full="09.27.2021 16:17:18",
            ),
            compare_raw=False,
        )

        self.input_message = self._create_report_dict([{"date": "invalid"}])
        self.run_bot(
            parameters={"compromise_time_format": "%Y-%m-%d"}, allowed_warning_count=1
        )
        self.assertMessageEqual(
            0,
            self._create_event_dict(
                compromise_time="",
                compromise_time_full="invalid",
            ),
            compare_raw=False,
        )

    def test_redacting_url_settings(self):
        report = self._create_report_dict(
            [{"url": "https://some.example.at/my/sub?url=1"}]
        )

        self.input_message = deepcopy(report)
        self.run_bot(parameters={"redact_url_path": True})
        self.assertMessageEqual(
            0,
            self._create_event_dict(
                fqdn="some.example.at",
                url="https://some.example.at/[REDACTED]",
                urlpath="/[REDACTED]",
                full_url="hxxps://some.example.at/my/sub?url=1",
            ),
            compare_raw=False,
        )

        self.input_message = deepcopy(report)
        self.run_bot(parameters={"redact_url_path": False})
        self.assertMessageEqual(
            0,
            self._create_event_dict(
                fqdn="some.example.at",
                url="https://some.example.at/my/sub",
                urlpath="/my/sub",
                full_url="hxxps://some.example.at/my/sub?url=1",
            ),
            compare_raw=False,
        )

    @skip_internet()
    def test_resolve_ip_settings(self):
        report = self._create_report_dict([{"url": "https://cert.at/"}])

        self.input_message = deepcopy(report)
        self.run_bot(parameters={"resolve_ip": True})
        self.assertMessageEqual(
            0,
            self._create_event_dict(
                fqdn="cert.at",
                ip="131.130.249.234",
                url="https://cert.at/",
                full_url="hxxps://cert.at/",
            ),
            compare_raw=False,
        )

        self.input_message = deepcopy(report)
        self.run_bot(parameters={"resolve_ip": False})
        self.assertMessageEqual(
            0,
            self._create_event_dict(
                fqdn="cert.at",
                ip="",
                url="https://cert.at/",
                full_url="hxxps://cert.at/",
            ),
            compare_raw=False,
        )
