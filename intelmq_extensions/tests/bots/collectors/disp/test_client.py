"""Testing DISP Collector

SPDX-FileCopyrightText: 2023 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

from datetime import datetime, timezone
from unittest import TestCase

import requests

from intelmq_extensions.bots.collectors.disp._client import DISPClient

from .base import DISP_APIMockMixIn


class DISPClientTestCase(DISP_APIMockMixIn, TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.config = {
            "api_url": "https://disp.example.at/v1",
            "auth_token": "XXX",
            "oauth_clientid": "client1",
            "oauth_clientsecret": "secret1",
            "oauth_url": "https://oauthip.example.at/v1",
        }
        self.setup_api_mock(
            url=self.config["api_url"],
            auth_token=self.config["auth_token"],
            oauth_clientid=self.config["oauth_clientid"],
            oauth_clientsecret=self.config["oauth_clientsecret"],
            oauth_url=self.config["oauth_url"],
            session=requests.Session(),
        )

        self.client = DISPClient(session=self.session, **self.config)

    def test_get_simple_response(self):
        self.mock_request(
            "incident/",
            json={"id": "some-id"},
        )

        response = self.client.get("incident/")
        self.assertEqual({"id": "some-id"}, response)

    def test_get_paginated_response_1_page(self):
        self.mock_request(
            "incident/?page=0&size=10",
            json={
                "content": [{"id": "id-1"}, {"id": "id-2"}],
                "last": True,
            },
        )

        responses = list(self.client.get_paginated("incident/"))
        self.assertEqual([{"id": "id-1"}, {"id": "id-2"}], responses)

    def test_get_paginated_response_3_pages(self):
        self.mock_request(
            "incident/?page=0&size=10",
            json={
                "content": [{"id": "id-1"}, {"id": "id-2"}],
                "last": False,
            },
        )
        self.mock_request(
            "incident/?page=1&size=10",
            json={
                "content": [{"id": "id-3"}],
                "last": False,
            },
        )
        self.mock_request(
            "incident/?page=2&size=10",
            json={
                "content": [{"id": "id-4"}],
                "last": True,
            },
        )

        responses = list(self.client.get_paginated("incident/"))
        self.assertEqual(
            [{"id": "id-1"}, {"id": "id-2"}, {"id": "id-3"}, {"id": "id-4"}], responses
        )

    def test_get_incidents(self):
        after = datetime(2023, 1, 1, 19, 10, tzinfo=timezone.utc)

        self.mock_request(
            "incident/?query=validationDate%20%3E%201672600200000%20AND%20UNREAD&page=0&size=10",
            json={"content": [{"id": "id-1"}]},
        )
        self.mock_request(
            "incident/?query=validationDate%20%3E%201672600200000&page=0&size=10",
            json={"content": [{"id": "id-2"}]},
        )
        self.mock_request(
            "incident/?query=NOT%20SOMETHING&page=0&size=10",
            json={"content": [{"id": "id-3"}]},
        )

        self.assertEqual([{"id": "id-1"}], list(self.client.incidents(after, True)))
        self.assertEqual([{"id": "id-2"}], list(self.client.incidents(after, False)))
        self.assertEqual(
            [{"id": "id-3"}], list(self.client.incidents(query="NOT SOMETHING"))
        )

    def test_get_evidence(self):
        # For credential tracking, the expected file is in JSON format.
        # For other incidents (not covered now), the format may differ
        self.mock_request("incident/id-1/file/f-1", text='{"credentials": []}')

        result = self.client.download_evidence_json("id-1", "f-1")

        self.assertEqual({"credentials": []}, result)

    def test_mark_read(self):
        self.mock_request("incident/read?id=id-1&read=true", method="post")

        self.client.mark_incident_read("id-1")

        self.assertEqual(1, self.requests.call_count)

    def test_raise_on_connection_issue(self):
        self.mock_request("/", status_code=500)

        with self.assertRaises(RuntimeError):
            self.client.get("/")

        self.mock_request("/", method="post", status_code=500)

        with self.assertRaises(RuntimeError):
            self.client.post("/")
