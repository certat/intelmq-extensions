"""Client to access the DISP API

SPDX-FileCopyrightText: 2023 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import logging
from datetime import datetime
from urllib.parse import quote, urlencode

import requests

from intelmq_extensions.lib.api_helpers import DEFAULT_REFRESH_WINDOW, OAuthAccessMixin

_SCOPE = "https://gateway.disp.deloitte.com/.default"
_GRANT_TYPE = "client_credentials"


default_logger = logging.getLogger(__name__)


class DISPClient(OAuthAccessMixin):
    def __init__(
        self,
        api_url: str,
        auth_token: str,
        oauth_clientid: str,
        oauth_clientsecret: str,
        oauth_url: str,
        session: requests.Session,
        refresh_before: int = DEFAULT_REFRESH_WINDOW,
        logger: logging.Logger = default_logger,
    ) -> None:
        self.api_url = api_url
        self.auth_token = auth_token
        self._access_token = None
        self._session = session
        self._page_size = 10
        self.logger = logger

        self.init_oauth(
            oauth_clientid=oauth_clientid,
            oauth_clientsecret=oauth_clientsecret,
            oauth_url=oauth_url,
            oauth_scope=_SCOPE,
            oauth_grant_type=_GRANT_TYPE,
            logger=self.logger,
            refresh_before=refresh_before,
            session=self._session,
        )

    def _auth(self):
        return {
            "Authorization": f"Bearer {self.auth_token}",
            "OAuth": self.access_token,
        }

    def get(self, path: str, params: dict = None):
        response = self._session.get(
            f"{self.api_url}/{path}",
            params=params,
            headers=self._auth(),
        )
        if not response.ok:
            self.logger.error(
                "Request %s failed with error %s, message: %s",
                path,
                response.status_code,
                response.text,
            )
            raise RuntimeError(f"Request to {path} failed with {response.status_code}")
        return response.json()

    def post(self, path: str, params: dict = None) -> requests.Response:
        response = self._session.post(
            f"{self.api_url}/{path}", params=params, headers=self._auth()
        )
        if not response.ok:
            self.logger.error(
                "Request %s failed with error %s, message: %s",
                path,
                response.status_code,
                response.text,
            )
            raise RuntimeError(f"Request to {path} failed with {response.status_code}")
        return response

    def get_paginated(self, path: str, params: dict = None):
        last = False
        page = 0
        params = params or {}
        while not last:
            # TODO: Use 'nextLink'
            params.update({"page": page, "size": self._page_size})
            response = self.get(path, params)
            last = response.get("last", True)
            for element in response.get("content", []):
                yield element
            page += 1

    def incidents(
        self, after: datetime = None, only_unread: bool = False, query: str = None
    ):
        if not query:
            conditions = []
            if after:
                long_timestamp = int(after.timestamp() * 1000)
                conditions.append(f"validationDate > {long_timestamp}")
            if only_unread:
                conditions.append("UNREAD")
            query = " AND ".join(conditions)
        # DISP rejects default encoding with + as space
        query = urlencode({"query": query}, quote_via=quote)

        return self.get_paginated(f"incident/?{query}")

    def download_evidence_json(self, incident_id: str, file_id: str):
        return self.get(f"incident/{incident_id}/file/{file_id}")

    def mark_incident_read(self, incident_id: str):
        self.post("incident/read", params={"id": incident_id, "read": True})
