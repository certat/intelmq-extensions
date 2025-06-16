"""Tests for DISP Collector

SPDX-FileCopyrightText: 2023 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import json
import unittest
from unittest import mock

import intelmq.lib.message as message
import requests
from freezegun import freeze_time

from intelmq_extensions.bots.collectors.disp.collector import DISPCollectorBot

from ....base import BotTestCase
from .base import DISP_APIMockMixIn


@freeze_time("2023-09-19 12:18")
class TestDISPCollectorBot(BotTestCase, DISP_APIMockMixIn, unittest.TestCase):
    @classmethod
    def set_bot(cls):
        cls.bot_reference = DISPCollectorBot
        cls.sysconfig = {
            "api_url": "https://disp.example.at/v1",
            "auth_token": "XXX",
            "oauth_clientid": "client1",
            "oauth_clientsecret": "secret1",
            "ouath_url": "https://oauthip.example.at/v1",
            "mark_as_read": False,
            "wait_for_evidences": True,
            "check_last": "7 days",
            "code": "feed-code",
        }

    def catch_http_session(self):
        session = requests.Session()
        session_mock = mock.patch(
            "intelmq_extensions.bots.collectors.disp.collector.create_request_session",
            return_value=session,
        )
        session_mock.start()
        self.addCleanup(session_mock.stop)
        return session

    def setUp(self) -> None:
        super().setUp()
        session = self.catch_http_session()
        self.setup_api_mock(session=session)
        self._mock_incidents()

    def test_no_incidents(self):
        self.run_bot()

        self.assertOutputQueueLen(0)
        self.assertEqual(1, self.requests.call_count)

    def test_ignore_incidents_without_evidences(self):
        self.add_incident(evidence_id=None)

        self.run_bot()

        self.assertOutputQueueLen(0)
        self.assertEqual(1, self.requests.call_count)

    def test_generate_event_without_waiting_for_evidence(self):
        self.add_incident(evidence_id=None)

        self.run_bot(parameters={"wait_for_evidences": False})

        self.assertOutputQueueLen(1)

    def _create_report_dict(self, incident_data: str, evidence_data: str, **kwargs):
        report = message.Report(kwargs, harmonization=self.harmonization)
        data = {"incident": incident_data, "evidences": evidence_data}
        report.add("feed.name", "Test Bot")
        report.add("feed.accuracy", 100.0)
        report.add("feed.code", "feed-code")
        report.add("raw", json.dumps(data))
        return report.to_dict(with_type=True)

    def test_generate_event(self):
        incident_id, incident_data = self.add_incident(evidence_id="file-1")
        self.mock_evidence(incident_id, "file-1", {"my": "evidence"})

        self.run_bot()

        self.assertOutputQueueLen(1)
        self.assertMessageEqual(
            0, self._create_report_dict(incident_data, {"my": "evidence"})
        )

    def test_mark_as_read(self):
        incident_id, _ = self.add_incident(evidence_id="file-1")
        self.mock_evidence(incident_id, "file-1", {"my": "evidence"})
        self.mock_request(f"incident/read?id={incident_id}&read=true", method="post")

        self.run_bot(parameters={"mark_as_read": True})

        self.assertOutputQueueLen(1)
        self.assertIn("incident/read", self.requests.last_request.path)
        self.assertIn(f"id={incident_id}&read=true", self.requests.last_request.query)

    def test_mask_password(self):
        incident_id, incident_data = self.add_incident(evidence_id="file-1")
        self.mock_evidence(
            incident_id,
            "file-1",
            {
                "credentials": [
                    {"password": "123"},
                    {"password": "ab"},
                    {"password": ""},
                    {"password": "mysuperpassword"},
                ]
            },
        )

        self.run_bot()

        self.assertOutputQueueLen(1)
        self.assertMessageEqual(
            0,
            self._create_report_dict(
                incident_data,
                {
                    "credentials": [
                        {"password": "***"},
                        {"password": "**"},
                        {"password": ""},
                        {"password": "mys************"},
                    ]
                },
            ),
        )
