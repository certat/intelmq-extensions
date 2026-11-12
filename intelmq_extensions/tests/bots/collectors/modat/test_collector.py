"""Tests for Modat Collector

SPDX-FileCopyrightText: 2025 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import json
import unittest
from unittest import mock

import intelmq.lib.message as message
import requests
from freezegun import freeze_time
from intelmq.lib.exceptions import ConfigurationError
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

    def mock_sleep(self):
        time_mock = mock.patch(
            "intelmq_extensions.bots.collectors.modat.collector.time"
        )
        self.time_mock = time_mock.start()
        self.addCleanup(time_mock.stop)

    def setUp(self):
        super().setUp()
        self.mock_http_session()
        self.mock_sleep()

    def mock_request(
        self,
        path: str,
        expected_query: str = "test-query",
        expected_page: int = 1,
        expected_page_size: int = 10,
        status_code: int = 200,
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

        if "response_list" not in kwargs:
            kwargs["status_code"] = status_code

        self.requests.post(
            f"https://api.magnify.modat.io/{path}",
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

    def test_query_services(self):
        service_1 = {"ip": "ip1", "service": {"port": 22, "protocol": "ssh"}}
        service_2 = {"ip": "ip1", "service": {"port": 443, "protocol": "http"}}
        self.mock_request(
            "service/search/v1",
            json={
                "page_nr": 1,
                "total_pages": 1,
                "total_records": 2,
                "page": [service_1, service_2],
                "facets": {},
            },
        )

        self.run_bot(parameters={"type": "service"})

        self.assertOutputQueueLen(1)
        self.assertMessageEqual(0, self._create_report_dict([service_1, service_2]))
        self.assertEqual(1, self.requests.call_count)

    def test_unsupported_type(self):
        with self.assertRaises(ConfigurationError):
            self.run_bot(parameters={"type": "dns"})

    def test_rate_limit_uses_retry_after_seconds(self):
        self.mock_request(
            "host/search/v1",
            response_list=[
                {"status_code": 429, "headers": {"Retry-After": "3"}},
                {
                    "status_code": 200,
                    "json": {
                        "page_nr": 1,
                        "total_pages": 1,
                        "total_records": 1,
                        "page": [{"ip": "ip1"}],
                    },
                },
            ],
        )

        self.run_bot()

        self.assertOutputQueueLen(1)
        self.assertMessageEqual(0, self._create_report_dict([{"ip": "ip1"}]))
        self.assertEqual(2, self.requests.call_count)
        self.time_mock.sleep.assert_called_once_with(3.0)

    @freeze_time("2025-06-01 12:00:00")
    def test_rate_limit_uses_retry_after_http_date(self):
        self.mock_request(
            "host/search/v1",
            response_list=[
                {
                    "status_code": 429,
                    "headers": {"Retry-After": "Sun, 01 Jun 2025 12:00:42 GMT"},
                },
                {
                    "status_code": 200,
                    "json": {
                        "page_nr": 1,
                        "total_pages": 1,
                        "total_records": 1,
                        "page": [{"ip": "ip1"}],
                    },
                },
            ],
        )

        self.run_bot()

        self.assertOutputQueueLen(1)
        self.time_mock.sleep.assert_called_once_with(42.0)

    def test_rate_limit_without_hint_uses_error_retry_delay(self):
        self.mock_request(
            "host/search/v1",
            response_list=[
                {"status_code": 429},
                {
                    "status_code": 200,
                    "json": {
                        "page_nr": 1,
                        "total_pages": 1,
                        "total_records": 1,
                        "page": [{"ip": "ip1"}],
                    },
                },
            ],
        )

        self.run_bot(parameters={"error_retry_delay": 7})

        self.assertOutputQueueLen(1)
        self.assertEqual(2, self.requests.call_count)
        self.time_mock.sleep.assert_called_once_with(7)

    def test_rate_limit_unparsable_hint_uses_error_retry_delay(self):
        self.mock_request(
            "host/search/v1",
            response_list=[
                {"status_code": 429, "headers": {"Retry-After": "soon-ish"}},
                {
                    "status_code": 200,
                    "json": {
                        "page_nr": 1,
                        "total_pages": 1,
                        "total_records": 1,
                        "page": [{"ip": "ip1"}],
                    },
                },
            ],
        )

        self.run_bot(parameters={"error_retry_delay": 7}, allowed_warning_count=1)

        self.assertOutputQueueLen(1)
        self.time_mock.sleep.assert_called_once_with(7)
        self.assertLogMatches(
            "Cannot parse Retry-After value 'soon-ish'", levelname="WARNING"
        )

    def test_rate_limit_retries_exhausted(self):
        self.mock_request(
            "host/search/v1",
            status_code=429,
            headers={"Retry-After": "2"},
        )

        # rate limit exhausted, error response, bot exception
        self.run_bot(parameters={"rate_limit_retries": 2}, allowed_error_count=3)

        self.assertOutputQueueLen(0)
        # first try + 2 retries
        self.assertEqual(3, self.requests.call_count)
        self.assertEqual(2, self.time_mock.sleep.call_count)
        self.assertLogMatches(
            "Modat rate limit still exceeded after 2 retries.", levelname="ERROR"
        )
