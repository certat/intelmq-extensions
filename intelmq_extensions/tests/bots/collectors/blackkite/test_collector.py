"""Tests for BlackKite Collector

SPDX-FileCopyrightText: 2023 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import json
import unittest
from unittest import mock

import intelmq.lib.message as message
import requests

from intelmq_extensions.bots.collectors.blackkite.collector import BlackKiteCollectorBot

from ....base import BotTestCase
from .base import BlackKite_APIMockMixIn


class TestBlackKiteCollectorBot(BotTestCase, BlackKite_APIMockMixIn, unittest.TestCase):
    @classmethod
    def set_bot(cls):
        cls.bot_reference = BlackKiteCollectorBot
        cls.sysconfig = {
            "url": "https://blackkite.example.at/v1",
            "client_id": "client1",
            "client_secret": "secret1",
            "code": "feed-code",
            "categories": {"PATCH": {}},
        }

    def catch_http_session(self):
        session = requests.Session()
        session_mock = mock.patch(
            "intelmq_extensions.bots.collectors.blackkite.collector.create_request_session",
            return_value=session,
        )
        session_mock.start()
        self.addCleanup(session_mock.stop)
        return session

    def setUp(self) -> None:
        super().setUp()
        session = self.catch_http_session()
        self.setup_api_mock(session=session)

    def test_static_check_validates_filters(self):
        correct_params = {
            "severities": ["Info", "Low", "Medium", "High", "Critical"],
            "statuses": [
                "Active",
                "FalsePositive",
                "Suppressed",
                "Acknowledged",
                "Deleted",
            ],
            "outputs": ["Info", "Passed", "Warning", "Failed"],
            "categories": {
                "PATCH": {
                    "statuses": ["Active"],
                    "severities": ["Critical"],
                    "include": ["PATCH-001"],
                },
                "APPSEC": {},
                "DNS": {"outputs": ["Failed"]},
                "LEAK": None,
            },
        }
        self.assertIsNone(self.bot_reference.check(correct_params))

    def test_static_check_invalid_params(self):
        invalid_params = {
            "severities": ["Some", "Other"],
            "statuses": ["NonActive"],
            "outputs": ["Other"],
            "categories": {
                "PATCH": {
                    "include": ["PATCH-001"],
                    "exclude": ["PATCH-002"],
                },
                "DNS": {
                    "statuses": ["NonActive"],
                },
                "FRADOM": {
                    "outputs": ["Failed"],
                },
                "non-existing": {},
                "SMTP": {"not-existing-key": []},
            },
        }
        results = self.bot_reference.check(invalid_params)
        self.assertEqual(8, len([r for r in results if r[0] == "error"]))

    def _create_report_dict(self, company_data: dict, finding_data: dict, **kwargs):
        report = message.Report(kwargs, harmonization=self.harmonization)
        data = {"company": company_data, "finding": finding_data}
        report.add("feed.name", "Test Bot")
        report.add("feed.accuracy", 100.0)
        report.add("feed.code", "feed-code")
        report.add("raw", json.dumps(data))
        return report.to_dict(with_type=True)

    def _mock_companies(self, number: int = 2):
        self.mock_request(
            "companies",
            json=[{"CompanyId": id_ + 1} for id_ in range(number)],
            headers={"X-Total-Items": str(number)},
        )

    def test_get_data_for_all_companies(self):
        self._mock_companies()
        self.mock_request(
            "companies/1/findings/patchmanagement?" "status=Active&severity=Critical",
            json=[{"FindingId": 1}, {"FindingId": 2}],
        )
        self.mock_request(
            "companies/2/findings/patchmanagement?&status=Active&severity=Critical",
            json=[{"FindingId": 3}],
        )

        self.run_bot()

        self.assertOutputQueueLen(3)
        self.assertMessageEqual(
            0, self._create_report_dict({"CompanyId": 1}, {"FindingId": 1})
        )
        self.assertMessageEqual(
            1, self._create_report_dict({"CompanyId": 1}, {"FindingId": 2})
        )
        self.assertMessageEqual(
            2, self._create_report_dict({"CompanyId": 2}, {"FindingId": 3})
        )

    def test_single_exception_doesnt_stop_processing(self):
        self._mock_companies()
        self.mock_request(
            "companies/1/findings/patchmanagement?status=Active&severity=Critical",
            status_code=500,
        )
        self.mock_request(
            "companies/1/findings/applicationsecurity?status=Active&severity=Critical",
            json=[{"FindingId": 1}],
        )
        self.mock_request(
            "companies/2/findings/patchmanagement?status=Active&severity=Critical",
            json=[{"FindingId": 2}],
        )
        self.mock_request(
            "companies/2/findings/applicationsecurity?status=Active&severity=Critical",
            json=[{"FindingId": 3}],
        )

        self.run_bot(
            parameters={**self.sysconfig, "categories": {"PATCH": {}, "APPSEC": {}}},
            allowed_error_count=2,  # log from collector + from client
        )

        self.assertOutputQueueLen(3)
        self.assertMessageEqual(
            0, self._create_report_dict({"CompanyId": 1}, {"FindingId": 1})
        )
        self.assertMessageEqual(
            1, self._create_report_dict({"CompanyId": 2}, {"FindingId": 2})
        )
        self.assertMessageEqual(
            2, self._create_report_dict({"CompanyId": 2}, {"FindingId": 3})
        )

    def test_overriding_filters(self):
        self._mock_companies(1)
        self.mock_request(
            "companies/1/findings/patchmanagement?status=Acknowledged&severity=Critical",
            json=[{"FindingId": 1}],
        )
        self.mock_request(
            "companies/1/findings/applicationsecurity?status=Active&severity=Low,Critical",
            headers={"X-Total-Items": "1"},
            json=[{"FindingId": 2}],
        )

        self.run_bot(
            parameters={
                **self.sysconfig,
                "severities": ["Critical"],
                "statuses": ["Active"],
                "categories": {
                    "PATCH": {"statuses": ["Acknowledged"]},
                    "APPSEC": {"severities": ["Low", "Critical"]},
                },
            }
        )

        self.assertOutputQueueLen(2)
        self.assertMessageEqual(
            0, self._create_report_dict({"CompanyId": 1}, {"FindingId": 1})
        )
        self.assertMessageEqual(
            1, self._create_report_dict({"CompanyId": 1}, {"FindingId": 2})
        )

    def test_category_with_no_settings(self):
        self._mock_companies(1)
        self.mock_request(
            "companies/1/findings/patchmanagement?status=Active&severity=Critical",
            json=[{"FindingId": 1}],
        )

        self.run_bot(
            parameters={
                **self.sysconfig,
                "categories": {
                    "PATCH": None,
                },
            }
        )

        self.assertOutputQueueLen(1)
        self.assertMessageEqual(
            0, self._create_report_dict({"CompanyId": 1}, {"FindingId": 1})
        )

    def test_include_and_exclude_findings(self):
        self._mock_companies(1)
        self.mock_request(
            "companies/1/findings/patchmanagement",
            json=[
                {"ControlId": "PATCH-001"},
                {"ControlId": "PATCH-002"},
                {"ControlId": "PATCH-003"},
            ],
        )
        self.mock_request(
            "companies/1/findings/applicationsecurity",
            headers={"X-Total-Items": "1"},
            json=[
                {"ControlId": "APPSEC-001"},
                {"ControlId": "APPSEC-002"},
                {"ControlId": "APPSEC-003"},
            ],
        )

        self.run_bot(
            parameters={
                **self.sysconfig,
                "categories": {
                    "PATCH": {"include": ["PATCH-001", "PATCH-003"]},
                    "APPSEC": {"exclude": ["APPSEC-003"]},
                },
            }
        )

        self.assertOutputQueueLen(4)
        self.assertMessageEqual(
            0, self._create_report_dict({"CompanyId": 1}, {"ControlId": "PATCH-001"})
        )
        self.assertMessageEqual(
            1, self._create_report_dict({"CompanyId": 1}, {"ControlId": "PATCH-003"})
        )
        self.assertMessageEqual(
            2, self._create_report_dict({"CompanyId": 1}, {"ControlId": "APPSEC-001"})
        )
        self.assertMessageEqual(
            3, self._create_report_dict({"CompanyId": 1}, {"ControlId": "APPSEC-002"})
        )

    def test_acknowledge_findings(self):
        self._mock_companies(1)
        self.mock_request(
            "companies/1/findings/credentialmanagement",
            json=[
                {"ControlId": "LEAK-001", "FindingId": 1},
                {"ControlId": "LEAK-002", "FindingId": 2},
            ],
            headers={"X-Total-Items": "2"},
        )
        self.mock_request(
            "companies/1/findings/1", json={"Status": "Acknowledged"}, method="patch"
        )
        self.mock_request(
            "companies/1/findings/2", json={"Status": "Acknowledged"}, method="patch"
        )

        self.run_bot(
            parameters={**self.sysconfig, "categories": {"LEAK": {"acknowledge": True}}}
        )

        self.assertEqual(2 + 2, self.requests.call_count)
