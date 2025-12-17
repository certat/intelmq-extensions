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

# Standard Collector parameters
name: Optional[str] = None
accuracy: int = 100
code: Optional[str] = None
provider: Optional[str] = None
documentation: Optional[str] = None
"""

import json
from urllib.parse import urljoin

from intelmq.lib.bot import CollectorBot
from intelmq.lib.utils import create_request_session


class ModatCollectorBot(CollectorBot):
    url: str = "https://api.magnify.modat.io/"
    page_size = 10
    max_results = 100

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
            result = self.session.post(
                url,
                json={"page": page, "page_size": self.page_size, "query": self.query},
            )
            if result.status_code != 200:
                self.logger.error("Modat responded with error %d.", result.status_code)
                self.logger.debug("Modat response: %s.", result.text)
                raise RuntimeError(
                    "Cannot retrieve data from Modat.", detail=result.text
                )

            data = result.json()
            report = self.new_report()
            report.add("raw", json.dumps(data["page"]))
            self.send_message(report)

            page += 1
            collected_results += len(data["page"])
            total_available = data["total_records"]

    # @staticmethod
    # def check(parameters: dict) -> list[list[str]] or None:
    #     pass


BOT = ModatCollectorBot
