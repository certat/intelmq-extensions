"""Client to access the BlackKite library

SPDX-FileCopyrightText: 2023 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import logging
import math
from enum import Enum
from typing import Iterator, Sequence

import requests

from intelmq_extensions.lib.api_helpers import (
    DEFAULT_REFRESH_WINDOW,
    OAuthAccessMixin,
    RateLimiter,
)

from ....lib.blackkite import Category

default_logger = logging.getLogger(__name__)


class Status(str, Enum):
    ACTIVE = "Active"
    FALSE_POSITIVE = "FalsePositive"
    SUPPRESSED = "Suppressed"
    ACKNOWLEDGED = "Acknowledged"
    DELETED = "Deleted"


class Severity(str, Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Output(str, Enum):
    INFO = "Info"
    PASSED = "Passed"
    WARNING = "Warning"
    FAILED = "Failed"


_DEFAULT_STATUSES = [Status.ACTIVE]
_DEFAULT_SEVERITY = [Severity.CRITICAL]

CATEGORIES_WITH_OUTPUT = [
    Category.DNSHealth,
    Category.ApplicationSecurity,
    Category.EmailSecurity,
    Category.NetworkSecurity,
    Category.DDoSResiliency,
    Category.SSLTLSstrength,
    Category.InformationDisclosure,
]


class BlackKiteClient(OAuthAccessMixin):
    def __init__(
        self,
        url: str,
        client_id: str,
        client_secret: str,
        refresh_before: str = DEFAULT_REFRESH_WINDOW,
        session: requests.Session = None,
        logger: logging.Logger = default_logger,
        limit_requests: int = 60,
        limit_period: int = 60,
        page_size: int = 100,
    ) -> None:
        self.url = url
        self.logger = logger
        self._session = session
        self._page_size = page_size

        self.limiter = RateLimiter(limit_requests, limit_period)
        self.init_oauth(
            oauth_url=f"{url}/oauth/token",
            oauth_clientid=client_id,
            oauth_clientsecret=client_secret,
            session=session,
            logger=logger,
            refresh_before=refresh_before,
            limiter=self.limiter,
        )

    def get(self, path: str, params: dict = None, raw: bool = False):
        with self.limiter.call():
            response = self._session.get(
                f"{self.url}/{path}",
                params=params,
                headers={"Authorization": f"Bearer {self.access_token}"},
            )
        if not response.ok:
            self.logger.error(
                "Request %s failed with error %s, message: %s.",
                path,
                response.status_code,
                response.text,
            )
            raise RuntimeError(f"Request to {path} failed with {response.status_code}")
        return response if raw else response.json()

    def get_paginated(self, path: str, params: dict = None) -> Iterator[dict]:
        last = False
        page = 1
        params = params or {}
        while not last:
            params.update({"page_number": page, "page_size": self._page_size})
            response = self.get(path, params, raw=True)

            total_items = int(response.headers.get("X-Total-Items", "0"))
            last = page >= math.ceil(total_items / self._page_size)

            for element in response.json():
                yield element
            page += 1

    def list_findings(
        self,
        path: str,
        company_id: int,
        severities: Sequence[Severity] = None,
        statuses: Sequence[Status] = None,
        outputs: Sequence[Output] = None,
    ) -> Iterator[dict]:
        severities = severities or _DEFAULT_SEVERITY
        statuses = statuses or _DEFAULT_STATUSES

        params = {"status": ",".join(statuses), "severity": ",".join(severities)}
        if outputs:
            params["output"] = ",".join(outputs)

        return self.get_paginated(f"companies/{company_id}/findings/{path}", params)

    def status(self) -> dict:
        return self.get("status")

    def companies(self) -> Iterator[dict]:
        return self.get_paginated("companies")

    def get_findings_from_category(
        self,
        category: Category,
        company_id: int,
        severities: Sequence[Severity] = None,
        statuses: Sequence[Status] = None,
        outputs: Sequence[Output] = None,
    ):
        if category not in CATEGORIES_WITH_OUTPUT:
            outputs = None
        return self.list_findings(
            category.name.lower(), company_id, severities, statuses, outputs
        )

    def acknowledge_finding(self, company_id: int, finding_id: int):
        with self.limiter.call():
            result = self._session.patch(
                f"{self.url}/companies/{company_id}/findings/{finding_id}",
                headers={"Authorization": f"Bearer {self.access_token}"},
                json={"Status": Status.ACKNOWLEDGED.value},
            )
            self.logger.debug("ACK finding %s, result: %s.", finding_id, result.text)
