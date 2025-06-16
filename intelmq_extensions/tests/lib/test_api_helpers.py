"""Tests for API helpers

SPDX-FileCopyrightText: 2023 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import time
from datetime import datetime, timedelta
from unittest import TestCase

import requests
from dateutil.tz import UTC

from intelmq_extensions.lib.api_helpers import OAuthAccessMixin, RateLimiter

from .base import OAuthAccess_APIMockMixIn


class OAuthAccessMixinTestCase(OAuthAccess_APIMockMixIn, TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.oauth_config = {
            "oauth_clientid": "client1",
            "oauth_clientsecret": "secret1",
            "oauth_url": "https://oauthip.example.at/v1",
            "oauth_scope": "my_scope",
            "oauth_grant_type": "my_type",
        }

        self.session = requests.Session()
        self.setup_oauth_mock(
            **self.oauth_config,
            session=self.session,
        )
        self.mixin = OAuthAccessMixin()
        self.mixin.init_oauth(session=self.session, **self.oauth_config)

    def test_get_access_token(self):
        self.assertIn(".xxx", self.mixin.access_token)
        self.assertEqual(1, self.auth_requests.call_count)

    def test_refresh_access_token(self):
        # the client has a valid token
        valid_token = self.gen_fake_token(datetime.now(tz=UTC) + timedelta(minutes=30))
        self.mixin._access_token = valid_token

        # current token is used without calling the IdP
        self.assertEqual(valid_token, self.mixin.access_token)
        self.assertEqual(0, self.auth_requests.call_count)

        # but when token is about to be expired, the new one is requested
        self.mixin._access_token = self.gen_fake_token(
            datetime.utcnow() + timedelta(minutes=5)
        )
        self.assertEqual(self.mocked_access_token, self.mixin.access_token)
        self.assertEqual(1, self.auth_requests.call_count)


class RateLimiterTestCase(TestCase):
    def setUp(self) -> None:
        self.limiter = RateLimiter(2, 1)

    def test_call_in_limit(self):
        counter = 0
        start = time.monotonic_ns()

        with self.limiter.call():
            counter += 1
        with self.limiter.call():
            counter += 1

        stop = time.monotonic_ns()

        self.assertEqual(2, counter)
        self.assertLess(stop - start, 10**9)

    def test_call_exceed_limit(self):
        counter = 0

        start = time.monotonic_ns()
        with self.limiter.call():
            counter += 1
        with self.limiter.call():
            counter += 1
        middle = time.monotonic_ns()
        with self.limiter.call():
            counter += 1
        stop = time.monotonic_ns()

        self.assertEqual(3, counter)
        self.assertGreater(stop - start, 10**9)
        # Ensure there was a waiting time between second and 3rd call
        self.assertGreater(stop - middle, middle - start)

    def test_call_no_limit(self):
        counter = 0
        limiter = RateLimiter(2, period_seconds=0)

        start = time.monotonic_ns()
        with limiter.call():
            counter += 1
        with limiter.call():
            counter += 1
        with limiter.call():
            counter += 1
        stop = time.monotonic_ns()

        self.assertEqual(3, counter)
        self.assertLess(stop - start, 10**9)

    def test_call_nested(self):
        """Ensure the limiter is safe to eventually nest"""
        counter = 0
        start = time.monotonic_ns()

        with self.limiter.call():
            counter += 1
            with self.limiter.call():
                counter += 1
                with self.limiter.call():
                    counter += 1

        stop = time.monotonic_ns()

        self.assertEqual(3, counter)
        self.assertGreater(stop - start, 10**9)
