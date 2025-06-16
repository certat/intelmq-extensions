"""Base for testing APIs with OAuth token

SPDX-FileCopyrightText: 2023 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import json
from base64 import urlsafe_b64encode
from datetime import datetime, timedelta
from urllib.parse import parse_qs

import requests
from requests_mock import MockerCore


def _get_form_matcher(expected: dict):
    def _matcher(request: requests.Request):
        sent_data = parse_qs(request.body)
        for key, value in sent_data.items():
            if len(value) == 1:
                sent_data[key] = value[0]
        return expected == sent_data

    return _matcher


class OAuthAccess_APIMockMixIn:
    def setup_oauth_mock(
        self,
        oauth_clientid: str = "client1",
        oauth_clientsecret: str = "secret1",
        oauth_url: str = "https://oauthip.example.at/v1",
        oauth_scope: str = "",
        oauth_grant_type: str = "client_credentials",
        session: requests.Session = None,
    ):
        self._oauth_clientid = oauth_clientid
        self._oauth_clientsecret = oauth_clientsecret
        self._oauth_url = oauth_url
        self._oauth_scope = oauth_scope
        self._oauth_grant_type = oauth_grant_type
        self.__session = session
        self._mock_access_token()

    def _mock_access_token(self):
        self.auth_requests = MockerCore(session=self.__session, real_http=True)
        self.auth_requests.start()
        self.addCleanup(self.auth_requests.stop)

        expected = {
            "scope": self._oauth_scope,
            "client_id": self._oauth_clientid,
            "client_secret": self._oauth_clientsecret,
            "grant_type": self._oauth_grant_type,
        }
        expected = dict(filter(lambda kv: kv[1], expected.items()))
        self.mocked_access_token = self.gen_fake_token()

        def _gen_response(*_, **__):
            return {
                "token_type": "Bearer",
                "expires_in": 3599,
                "ext_expires_in": 3599,
                "access_token": self.mocked_access_token,
            }

        # TODO: matcher

        self.auth_requests.post(
            url=self._oauth_url,
            json=_gen_response,
            additional_matcher=_get_form_matcher(expected),
        )

    @staticmethod
    def gen_fake_token(expiry: datetime = None):
        expiry = expiry or (datetime.utcnow() + timedelta(hours=1))
        data = urlsafe_b64encode(
            json.dumps({"exp": int(expiry.timestamp())}).encode()
        ).decode()
        return f"xxxxx.{data}.xxx"
