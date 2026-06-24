"""Tests for eCrime.ch Collector

SPDX-FileCopyrightText: 2026 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import json
import unittest
from unittest import mock

import intelmq.lib.message as message
import requests
from freezegun import freeze_time
from requests_mock import MockerCore

from intelmq_extensions.bots.collectors.ecrimech.collector import ECrimeCHCollectorBot

from ....base import BotTestCase

MOCK_RESPONSE = {
    "status": "200",
    "message": "OK",
    "date": 1782307434,
    "results": 2,
    "data": [
        {
            "id": 10001,
            "first_seen": "2026-06-23 08:00:00.000000+00:00",
            "last_seen": "2026-06-24 10:00:00.000000+00:00",
            "leak_site": "MockLeakSite",
            "leak_title": "Mock Corp",
            "country": "Austria",
            "sector": "Technology",
            "name": "Mock Corp GmbH",
            "website": "https://www.mock-corp.example/",
            "employees": "11-50 employees",
            "revenue": "$10 Million",
            "stock_symbol": None,
            "leak_url": "",
            "duplicate": None,
            "data_leak": None,
            "last_update": "2026-06-24 09:00:00.000000+00:00",
            "extra": "{'description': 'A mock company for testing purposes'}",
            "logo": "https://ecrime.ch/image/logos/mock1.jpg",
            "city": "Wien",
            "state": None,
            "revenue_number": 10000000,
            "status": [
                {"name": "initial", "date": 1782200000},
                {"name": "enriched", "date": 1782200100},
            ],
            "links": [],
            "keyword": "false",
        },
        {
            "id": 10002,
            "first_seen": "2026-06-23 14:00:00.000000+00:00",
            "last_seen": "2026-06-24 11:00:00.000000+00:00",
            "leak_site": "AnotherLeakSite",
            "leak_title": "Test Services",
            "country": "Austria",
            "sector": "Construction",
            "name": "Test Services AG",
            "website": "https://test-services.example/",
            "employees": "51-200 employees",
            "revenue": None,
            "stock_symbol": None,
            "leak_url": "",
            "duplicate": None,
            "data_leak": 1,
            "last_update": "2026-06-23 14:10:00.000000+00:00",
            "extra": "{'description': 'Another mock company for testing'}",
            "logo": "https://ecrime.ch/image/logos/mock2.jpg",
            "city": "Graz",
            "state": "Steiermark",
            "revenue_number": 0,
            "status": [
                {"name": "initial", "date": 1782210000},
                {"name": "data_leak", "date": 1782210000},
                {"name": "enriched", "date": 1782210200},
            ],
            "links": [],
            "keyword": "false",
        },
    ],
}


@freeze_time("2026-06-24 12:00")
class TestECrimeCHCollectorBot(BotTestCase, unittest.TestCase):
    @classmethod
    def set_bot(cls):
        cls.bot_reference = ECrimeCHCollectorBot
        cls.sysconfig = {
            "api_key": "test-api-key",
            "from_delta": {"days": -1},
            "to_delta": {"days": 0},
            "country": "Austria",
        }

    def mock_http_session(self):
        session = requests.Session()
        session_mock = mock.patch(
            "intelmq_extensions.bots.collectors.ecrimech.collector.create_request_session",
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

    def mock_request(self, status_code=200, **kwargs):
        def check_request(request):
            if request.headers.get("X-API-Key", "") != "test-api-key":
                return False
            return True

        self.requests.post(
            "https://ecrime.ch/api/v1/events/list/from/2026-06-23/to/2026-06-24/",
            status_code=status_code,
            additional_matcher=check_request,
            **kwargs,
        )

    def _create_report_dict(self, data, **kwargs):
        report = message.Report(kwargs, harmonization=self.harmonization)
        report.add("feed.name", "Test Bot")
        report.add("feed.accuracy", 100.0)
        report.add("raw", json.dumps(data))
        return report.to_dict(with_type=True)

    def test_query_events(self):
        self.mock_request(json=MOCK_RESPONSE)

        self.run_bot()

        self.assertOutputQueueLen(1)
        self.assertMessageEqual(0, self._create_report_dict(MOCK_RESPONSE["data"]))
        self.assertEqual(1, self.requests.call_count)
        self.assertIn("country=Austria", self.requests.last_request.text)

    def test_query_without_filters(self):
        self.mock_request(json=MOCK_RESPONSE)

        self.run_bot(parameters={"country": None})

        self.assertOutputQueueLen(1)
        self.assertEqual("", self.requests.last_request.text or "")

    def test_error_response(self):
        self.mock_request(status_code=500, text="Internal Server Error")

        self.run_bot(allowed_error_count=2)

        self.assertOutputQueueLen(0)
