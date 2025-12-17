"""Tests for Modat Collector

SPDX-FileCopyrightText: 2025 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import json
import unittest
from unittest import mock

import intelmq.lib.message as message
import requests
from requests_mock import MockerCore

from intelmq_extensions.bots.collectors.modat.collector import ModatCollectorBot

from ....base import BotTestCase


class TestModatCollectorBot(BotTestCase, unittest.TestCase):
    @classmethod
    def set_bot(cls):
        cls.bot_reference = ModatCollectorBot
        cls.sysconfig = {
            "query": "test-query",
            "type": "host",
            "api_key": "secure-api-key",
            "code": "feed-code",
        }

    def mock_http_session(self):
        session = requests.Session()
        session_mock = mock.patch(
            "intelmq_extensions.bots.collectors.modat.collector.create_request_session",
            return_value=session,
        )
        session_mock.start()
        self.addCleanup(session_mock.stop)

        self.requests = MockerCore(session=session)
        self.requests.start()
        self.addCleanup(self.requests.stop)

    def setUp(self):
        super().setUp()
        self.mock_http_session()

    def mock_request(
        self,
        path: str,
        expected_query: str = "test-query",
        expected_page: int = 1,
        expected_page_size: int = 10,
        **kwargs,
    ):
        def check_request(request):
            if request.headers.get("Authorization", "") != "Bearer secure-api-key":
                return False
            if request.json()["query"] != expected_query:
                return False
            if request.json()["page"] != expected_page:
                return False
            if request.json()["page_size"] != expected_page_size:
                return False
            return True

        self.requests.post(
            f"https://api.magnify.modat.io/{path}",
            status_code=200,
            additional_matcher=check_request,
            **kwargs,
        )

    def _create_report_dict(self, data, **kwargs):
        report = message.Report(kwargs, harmonization=self.harmonization)
        report.add("feed.name", "Test Bot")
        report.add("feed.accuracy", 100.0)
        report.add("feed.code", "feed-code")
        report.add("raw", json.dumps(data))
        return report.to_dict(with_type=True)

    def test_query_hosts(self):
        self.mock_request(
            "host/search/v1",
            json={
                "page_nr": 1,
                "total_pages": 1,
                "total_records": 4,
                "page": [{"ip": "ip1"}, {"ip": "ip2"}],
            },
        )
        self.mock_request(
            "host/search/v1",
            json={
                "page_nr": 2,
                "total_pages": 1,
                "total_records": 4,
                "page": [{"ip": "ip3"}, {"ip": "ip4"}],
            },
            expected_page=2,
        )

        self.run_bot()

        self.assertOutputQueueLen(2)
        self.assertMessageEqual(
            0, self._create_report_dict([{"ip": "ip1"}, {"ip": "ip2"}])
        )
        self.assertMessageEqual(
            1, self._create_report_dict([{"ip": "ip3"}, {"ip": "ip4"}])
        )
        self.assertEqual(2, self.requests.call_count)
