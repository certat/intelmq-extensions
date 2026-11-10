"""Collector of data from Modat API

SPDX-FileCopyrightText: 2025 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later

https://api.magnify.modat.io/docs

Parameters:

api_key
# TODO: multiple queries in one bot?
query
type [service|host]

# with defaults
url = "https://api.magnify.modat.io/"
page_size = 10
max_results = 100
rate_limit_retries = 5  # how many times to retry a request answered with HTTP 429

# Standard Collector parameters
name: Optional[str] = None
accuracy: int = 100
code: Optional[str] = None
provider: Optional[str] = None
documentation: Optional[str] = None
"""

import json
import math
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin

from intelmq.lib.bot import CollectorBot
from intelmq.lib.utils import create_request_session


class ModatCollectorBot(CollectorBot):
    url: str = "https://api.magnify.modat.io/"
    page_size = 10
    max_results = 100
    rate_limit_retries: int = 5

    api_key: str
    query: str
    type: str  # service|host

    def init(self):
        self.set_request_parameters()
        self.session = create_request_session(self)
        self.session.headers = {"Authorization": f"Bearer {self.api_key}"}

    def process(self):
        page = 1
        collected_results = 0
        total_available = self.page_size

        if self.type == "host":
            url = urljoin(self.url, "/host/search/v1")
        else:
            url = urljoin(self.url, "/service/search/v1")

        while (
            total_available > collected_results and collected_results < self.max_results
        ):
            result = self._post(
                url,
                json={"page": page, "page_size": self.page_size, "query": self.query},
            )
            if result.status_code != 200:
                self.logger.error("Modat responded with error %d.", result.status_code)
                self.logger.debug("Modat response: %s.", result.text)
                raise RuntimeError(
                    f"Cannot retrieve data from Modat (HTTP {result.status_code})."
                )

            data = result.json()
            report = self.new_report()
            report.add("raw", json.dumps(data["page"]))
            self.send_message(report)

            page += 1
            collected_results += len(data["page"])
            total_available = data["total_records"]

    def _post(self, url: str, **kwargs):
        """POST to the API, waiting and retrying when rate limited (HTTP 429)"""
        retries = 0
        while True:
            result = self.session.post(url, **kwargs)
            if result.status_code != 429:
                return result
            if retries >= self.rate_limit_retries:
                self.logger.error(
                    "Modat rate limit still exceeded after %d retries.", retries
                )
                return result

            retries += 1
            delay = self._get_retry_delay(result)
            self.logger.info(
                "Modat rate limit exceeded, waiting %.1f seconds before retry %d/%d.",
                delay,
                retries,
                self.rate_limit_retries,
            )
            time.sleep(delay)

    def _get_retry_delay(self, response) -> float:
        """Get waiting time from the Retry-After header, or fall back to error_retry_delay

        Retry-After can be either a number of seconds or an HTTP date (RFC 9110).
        """
        retry_after = response.headers.get("Retry-After", "").strip()
        if not retry_after:
            self.logger.debug("No Retry-After hint, falling back to error_retry_delay.")
            return self.error_retry_delay

        try:
            delay = float(retry_after)
            if math.isfinite(delay):
                return max(0.0, delay)
        except ValueError:
            try:
                retry_at = parsedate_to_datetime(retry_after)
                if retry_at.tzinfo is None:
                    retry_at = retry_at.replace(tzinfo=timezone.utc)
                return max(
                    0.0, (retry_at - datetime.now(tz=timezone.utc)).total_seconds()
                )
            except (TypeError, ValueError, IndexError):
                pass

        self.logger.warning(
            "Cannot parse Retry-After value %r, falling back to error_retry_delay.",
            retry_after,
        )
        return self.error_retry_delay

    # @staticmethod
    # def check(parameters: dict) -> list[list[str]] or None:
    #     pass


BOT = ModatCollectorBot
