"""Common helpers to speak with APIs

SPDX-FileCopyrightText: 2023 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import base64
import json
import logging
import time
from contextlib import contextmanager
from datetime import datetime, timedelta
from threading import RLock

import requests
from dateutil.tz import UTC

default_logger = logging.getLogger(__name__)
# refresh access token when it's about to expire in 10 minutes
DEFAULT_REFRESH_WINDOW = 10


class OAuthAccessMixin:
    def init_oauth(
        self,
        oauth_clientid: str,
        oauth_clientsecret: str,
        oauth_url: str,
        session: requests.Session,
        oauth_scope: str = "",
        oauth_grant_type: str = "client_credentials",
        logger: logging.Logger = default_logger,
        refresh_before: int = DEFAULT_REFRESH_WINDOW,
        limiter: "RateLimiter" = None,
    ) -> None:
        self._oauth_clientid = oauth_clientid
        self._oauth_clientsecret = oauth_clientsecret
        self._oauth_url = oauth_url
        self._oauth_scope = oauth_scope
        self._oauth_grant_type = oauth_grant_type
        self._refresh_before = refresh_before
        self._access_token = None
        self.__logger = logger
        self.__session = session
        self.__limiter = limiter or RateLimiter(0, 0)

    @property
    def access_token(self):
        if self._access_token:
            _, data, __ = self._access_token.split(".")
            # Add additional padding to overcome the library issue when it's stripped
            data = json.loads(base64.urlsafe_b64decode(data + "==="))
            expiration = datetime.fromtimestamp(data["exp"], tz=UTC)
            refreshing_time = datetime.now(tz=UTC) + timedelta(
                minutes=self._refresh_before
            )
            self.__logger.debug(
                "Comparing %s with expiration %s from access token.",
                refreshing_time,
                expiration,
            )
            if refreshing_time > expiration:
                self._access_token = None

        if not self._access_token:
            self.__logger.debug("Refreshing OAuth access token.")
            with self.__limiter.call():
                self._access_token = self.__session.post(
                    self._oauth_url,
                    data={
                        "scope": self._oauth_scope,
                        "grant_type": self._oauth_grant_type,
                        "client_id": self._oauth_clientid,
                        "client_secret": self._oauth_clientsecret,
                    },
                ).json()["access_token"]
        return self._access_token


class RateLimiter:
    def __init__(self, max_call: int, period_seconds: int):
        self.max_call = max_call
        self.period = period_seconds
        self._last_reset = time.monotonic()
        self._counter = 0
        self._lock = RLock()

    @contextmanager
    def call(self):
        if not self.period:
            yield
            return

        while True:
            with self._lock:
                now = time.monotonic()
                if now - self._last_reset > self.period:
                    self._counter = 0
                    self._last_reset = now

                if self._counter < self.max_call:
                    self._counter += 1
                    yield
                    break
            time.sleep(now - self._last_reset)
