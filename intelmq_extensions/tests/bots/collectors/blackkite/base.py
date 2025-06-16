"""Base for BlackKite tests

SPDX-FileCopyrightText: 2023 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import requests
from requests_mock import MockerCore

from ....lib.base import OAuthAccess_APIMockMixIn


class BlackKite_APIMockMixIn(OAuthAccess_APIMockMixIn):
    def setup_api_mock(
        self,
        url: str = "https://blackkite.example.at/v1",
        client_id: str = "client1",
        client_secret: str = "secret1",
        session: requests.Session = None,
    ):
        self._url = url
        self.session = session
        self.requests = MockerCore(session=self.session)
        self.requests.start()
        self.addCleanup(self.requests.stop)

        self.setup_oauth_mock(
            oauth_clientid=client_id,
            oauth_clientsecret=client_secret,
            oauth_url=f"{url}/oauth/token",
            session=self.session,
        )

    def mock_request(
        self, path: str, mocker: MockerCore = None, method: str = "get", **kwargs
    ):
        mocker = mocker or self.requests
        mocking_method = getattr(mocker, method)
        mocking_method(
            f"{self._url}/{path}",
            request_headers={
                "Authorization": f"Bearer {self.mocked_access_token}",
            },
            **kwargs,
        )
