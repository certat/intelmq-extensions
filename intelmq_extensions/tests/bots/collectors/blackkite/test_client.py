"""Testing BlackKite API client

SPDX-FileCopyrightText: 2023 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

from unittest import TestCase

import requests

from intelmq_extensions.bots.collectors.blackkite._client import (
    BlackKiteClient,
    Output,
    Severity,
    Status,
)

from .....lib.blackkite import Category
from .base import BlackKite_APIMockMixIn


class BlackKiteClientTestCase(BlackKite_APIMockMixIn, TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.config = {
            "url": "https://blackkite.example.at/v1",
            "client_id": "client1",
            "client_secret": "secret1",
        }
        self.setup_api_mock(
            **self.config,
            session=requests.Session(),
        )

        self.client = BlackKiteClient(session=self.session, page_size=10, **self.config)

    def test_get_paginated_response_1_page(self):
        self.mock_request(
            "companies/?page_number=1&page_size=10",
            json=[{"CompanyId": 1}, {"CompanyId": 2}],
            headers={"X-Total-Items": "2"},
        )

        responses = list(self.client.get_paginated("companies/"))
        self.assertEqual([{"CompanyId": 1}, {"CompanyId": 2}], responses)

    def test_get_paginated_response_3_pages(self):
        self.mock_request(
            "incident/?page_number=1&page_size=10",
            json=[{"CompanyId": 1}, {"CompanyId": 2}],
            headers={"X-Total-Items": "23"},
        )
        self.mock_request(
            "incident/?page_number=2&page_size=10",
            json=[{"CompanyId": 3}, {"CompanyId": 4}],
            headers={"X-Total-Items": "23"},
        )
        self.mock_request(
            "incident/?page_number=3&page_size=10",
            json=[{"CompanyId": 5}],
            headers={"X-Total-Items": "23"},
        )

        responses = list(self.client.get_paginated("incident/"))
        self.assertEqual(
            [
                {"CompanyId": 1},
                {"CompanyId": 2},
                {"CompanyId": 3},
                {"CompanyId": 4},
                {"CompanyId": 5},
            ],
            responses,
        )

    def test_get_status(self):
        self.mock_request("status", json={"IsValid": True})

        self.assertEqual({"IsValid": True}, self.client.status())

    def test_get_companies(self):
        self.mock_request(
            "companies?page_number=1&page_size=10",
            json=[{"CompanyId": 1}, {"CompanyId": 2}],
            headers={"X-Total-Items": "2"},
        )

        responses = list(self.client.companies())
        self.assertEqual([{"CompanyId": 1}, {"CompanyId": 2}], responses)

    def test_list_findings_default(self):
        self.mock_request(
            (
                "companies/1/findings/patchmanagement?page_number=1&page_size=10"
                "&status=Active&severity=Critical"
            ),
            headers={"X-Total-Items": "2"},
            json=[{"FindingId": 1}, {"FindingId": 2}],
        )

        result = list(self.client.list_findings("patchmanagement", company_id=1))
        self.assertEqual([{"FindingId": 1}, {"FindingId": 2}], result)

    def test_list_findings_custom_filters(self):
        self.mock_request(
            (
                "companies/1/findings/dnshealth?page_number=1&page_size=10"
                "&status=Active,Deleted&severity=Critical,High&output=Failed,Warning,Passed"
            ),
            headers={"X-Total-Items": "2"},
            json=[{"FindingId": 1}, {"FindingId": 2}],
        )

        result = list(
            self.client.list_findings(
                "dnshealth",
                company_id=1,
                statuses=[Status.ACTIVE, Status.DELETED],
                severities=[Severity.CRITICAL, Severity.HIGH],
                outputs=[Output.FAILED, Output.WARNING, Output.PASSED],
            )
        )
        self.assertEqual([{"FindingId": 1}, {"FindingId": 2}], result)

    def test_get_category_findings_ignore_output_when_not_supported(self):
        self.mock_request(
            (
                "companies/1/findings/patchmanagement?page_number=1&page_size=10"
                "&status=Active,Deleted&severity=Critical,High"
            ),
            headers={"X-Total-Items": "2"},
            json=[{"FindingId": 1}, {"FindingId": 2}],
            complete_qs=True,
        )

        result = list(
            self.client.get_findings_from_category(
                Category.PatchManagement,
                company_id=1,
                statuses=[Status.ACTIVE, Status.DELETED],
                severities=[Severity.CRITICAL, Severity.HIGH],
                outputs=[Output.FAILED, Output.WARNING, Output.PASSED],
            )
        )
        self.assertEqual([{"FindingId": 1}, {"FindingId": 2}], result)

    def test_acknowledge_finding(self):
        self.mock_request(
            "companies/1/findings/2", json={"Status": "Acknowledged"}, method="patch"
        )

        self.client.acknowledge_finding(1, 2)

        self.assertEqual(1, self.requests.call_count)
