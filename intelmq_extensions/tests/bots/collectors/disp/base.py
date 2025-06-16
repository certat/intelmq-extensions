"""Base for DISP client and collector tests

SPDX-FileCopyrightText: 2023 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

from datetime import datetime, timedelta

import requests
from requests_mock import MockerCore

from ....lib.base import OAuthAccess_APIMockMixIn

_DEFAULT_TAGS = ["_BotnetCreds", "family: Redline", "type: InfoStealer", "_Parsed"]
_DEFAULT_ASSETS = ["nic.at"]


class DISP_APIMockMixIn(OAuthAccess_APIMockMixIn):
    def setup_api_mock(
        self,
        url: str = "https://disp.example.at/v1",
        auth_token: str = "XXX",
        oauth_clientid: str = "client1",
        oauth_clientsecret: str = "secret1",
        oauth_url: str = "https://oauthip.example.at/v1",
        session: requests.Session = None,
    ):
        self._api_url = url
        self._auth_token = auth_token
        self.session = session
        self.requests = MockerCore(session=self.session)
        self.requests.start()
        self.addCleanup(self.requests.stop)

        self.setup_oauth_mock(
            oauth_clientid=oauth_clientid,
            oauth_clientsecret=oauth_clientsecret,
            oauth_url=oauth_url,
            oauth_scope="https://gateway.disp.deloitte.com/.default",
            oauth_grant_type="client_credentials",
            session=self.session,
        )

        self._incident_counter = 0
        self._incidents = []

    def create_requests_mock(self):
        # create nested requests mock to separate tested requests
        mocker = MockerCore(session=self.session, real_http=True)
        mocker.start()
        self.addCleanup(mocker.stop)
        return mocker

    def mock_request(
        self, path: str, mocker: MockerCore = None, method: str = "get", **kwargs
    ):
        mocker = mocker or self.requests
        mocking_method = getattr(mocker, method)
        mocking_method(
            f"{self._api_url}/{path}",
            request_headers={
                "Authorization": f"Bearer {self._auth_token}",
                "OAuth": self.mocked_access_token,
            },
            **kwargs,
        )

    def add_incident(
        self,
        *,
        viewed: bool = False,
        validation_date: datetime = None,
        title: str = "Credentials compromised by a botnet",
        category: str = "Information discovery",
        type_: str = "Credentials",
        tags: list = None,
        related_assets: list = None,
        evidence_id: str = None,
        other: dict = None,
    ):
        """Add mocked incident to the API responses, but only selected used fields fields"""
        incident_id = f"incident-{self._incident_counter}"
        self._incident_counter += 1
        if tags is None:
            tags = _DEFAULT_TAGS
        if related_assets is None:
            related_assets = _DEFAULT_ASSETS
        if validation_date is None:
            validation_date = datetime.utcnow() - timedelta(days=1)

        incident = {
            "id": incident_id,
            "metadata": {
                "viewed": viewed,
            },
            "validationDate": int(validation_date.timestamp() * 1000),
            "title": title,
            "category": category,
            "type": type_,
            "tags": tags,
            "relatedAssets": related_assets,
            "url": f"https://disp.app/document/incident/{incident_id}",
        }

        if evidence_id:
            incident.update(
                {
                    "evidences": [
                        {"idStoredFile": evidence_id, "name": f"{incident_id}.json.txt"}
                    ]
                }
            )
        else:
            incident.update({"evidences": []})

        if other:
            incident.update(other)

        self._incidents.append(incident)
        return incident_id, incident

    def mock_evidence(
        self,
        incident_id: str,
        file_id: str,
        data: dict = None,
        mocker: MockerCore = None,
    ):
        mocker = mocker or self.requests
        self.mock_request(
            f"incident/{incident_id}/file/{file_id}", json=data, mocker=mocker
        )

    def _mock_incidents(self, mocker: MockerCore = None, after: datetime = None):
        after = after or datetime.utcnow() - timedelta(days=7)
        mocker = mocker or self.requests
        self.mock_request(
            (
                f"incident/?query=validationDate%20%3E%20{int(after.timestamp() * 1000)}"
                "%20AND%20UNREAD&page=0&size=10"
            ),
            mocker=mocker,
            json={
                "content": self._incidents,
                "last": True,
            },
        )
