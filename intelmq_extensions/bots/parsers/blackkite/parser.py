"""Parser for BlackKite feeds

SPDX-FileCopyrightText: 2023 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import json
from dataclasses import dataclass
from typing import Union

import intelmq.lib.message as message
from intelmq.lib import utils
from intelmq.lib.bot import ParserBot

from intelmq_extensions.lib.blackkite import Category

from ._transformers import TRANSFORMERS_MAPPER


@dataclass
class PreparedData:
    raw_report: str
    company: dict
    event_data: dict


class BlackKiteParserBot(ParserBot):
    def init(self):
        pass

    def parse(self, report: message.Report):
        raw_report = utils.base64_decode(report.get("raw"))
        self._current_line = raw_report

        data = json.loads(raw_report)
        company = data["company"]
        finding = data["finding"]

        category = Category(finding["ControlId"].split("-")[0])
        for event_data in TRANSFORMERS_MAPPER[category].to_events_data(finding):
            self._current_line = PreparedData(raw_report, company, event_data)
            yield self._current_line

    def parse_line(self, data: PreparedData, report: message.Report):
        event = self.new_event(report)
        event.add("raw", data.raw_report)

        event.add("extra.monitored_asset", data.company.get("DomainName"))
        event.add("extra.blackkite_company_id", data.company.get("CompanyId"))

        for key, value in data.event_data.items():
            event.add(key, value, overwrite=True)

        if "time.source" not in event:
            event.add("time.source", event.get("time.observation"))

        return event

    def recover_line(self, line: Union[str, None, PreparedData] = None) -> str:
        if isinstance(line, str):
            return super().recover_line(line)
        return super().recover_line(line.raw_report)


BOT = BlackKiteParserBot
