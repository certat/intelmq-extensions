"""Collector of data from eCrime.ch API

SPDX-FileCopyrightText: 2026 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later

https://ecrime.ch/help/api/

At the moment, only POST /api/v1/events/list/from/{from}/to/{to}/
is supported

Parameters:

base_url = "https://ecrime.ch/api/v1"

api_key
from_delta: datetime.timedelta arguments for the `from` argument
to_delta: datetime.timedelta arguments for the `to` argument

Filters:
sector:
actor:
domain:
country:
employees

# Standard Collector parameters
name: Optional[str] = None
accuracy: int = 100
code: Optional[str] = None
provider: Optional[str] = "eCrime.ch"
documentation: Optional[str] = None
"""

import json
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin

from intelmq.lib.bot import CollectorBot
from intelmq.lib.utils import create_request_session

EVENTS_LIST_TPL = "events/list/from/{from_}/to/{to}/"


class ECrimeCHCollectorBot(CollectorBot):
    base_url = "https://ecrime.ch/api/v1/"

    from_delta: dict  # datetime.timedelta arguments for the `from` argument
    to_delta: dict  # datetime.timedelta

    sector: str = None
    actor: str = None
    domain: str = None
    country: str = None
    employees: str = None

    def init(self):
        self.set_request_parameters()
        self.session = create_request_session(self)
        self.session.headers = {"X-API-Key": self.api_key}

        self._from_delta = timedelta(**self.from_delta)
        self._to_delta = timedelta(**self.to_delta)

    def process(self):
        params = {}
        for param_name in ("sector", "actor", "domain", "country", "employees"):
            if getattr(self, param_name, ""):
                params[param_name] = getattr(self, param_name)

        now = datetime.now(tz=timezone.utc)
        path = EVENTS_LIST_TPL.format(
            from_=(now + self._from_delta).date(),
            to=(now + self._to_delta).date(),
        )
        url = urljoin(self.base_url, path)

        result = self.session.post(
            url,
            data=params,
        )
        if result.status_code != 200:
            self.logger.error("eCrime.ch responded with error %d.", result.status_code)
            self.logger.debug("eCrime.ch response: %s.", result.text)
            raise RuntimeError(
                "Cannot retrieve data from cCrime.ch %s: %s." % (url, result.text)
            )

        data = result.json()
        report = self.new_report()
        report.add("raw", json.dumps(data["data"]))
        self.send_message(report)

    # @staticmethod
    # def check(parameters: dict) -> list[list[str]] or None:
    #     pass


BOT = ECrimeCHCollectorBot
