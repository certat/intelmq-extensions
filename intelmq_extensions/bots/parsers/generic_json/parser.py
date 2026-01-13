# SPDX-FileCopyrightText: 2016 by Bundesamt für Sicherheit in der Informationstechnik,
# 2016-2021 nic.at GmbH, 2024 Tim de Boer, 2025 Institute for Common Good Technology
#
# SPDX-License-Identifier: AGPL-3.0-or-later
# TODO: merge with the upstream bot
# TODO: support nested dicts
"""
JSON Parser Bot
Retrieves a base64 encoded JSON-String from raw and converts it into an
event, adding unknown fields as extra
"""

from json import dumps as json_dumps
from json import loads as json_loads

from intelmq.lib.bot import ParserBot
from intelmq.lib.message import MessageFactory
from intelmq.lib.utils import base64_decode


class JSONGenericParserBot(ParserBot):
    """Parse IntelMQ-JSON data"""

    splitlines: bool = False
    multiple_events: bool = False

    def init(self):
        if self.multiple_events and self.splitlines:
            raise ValueError(
                (
                    "Modes 'splitlines' and 'multiple_events' "
                    "are not possible at the same time. Please use either one."
                )
            )

    def process(self):
        report = self.receive_message()
        if self.multiple_events:
            lines = json_loads(base64_decode(report["raw"]))
        elif self.splitlines:
            lines = base64_decode(report["raw"]).splitlines()
        else:
            lines = [base64_decode(report["raw"])]

        for line in lines:
            event = self.new_event(report)
            if self.multiple_events:
                event.update(
                    MessageFactory.from_dict(
                        line, harmonization=self.harmonization, default_type="Event"
                    )
                )
                event["raw"] = json_dumps(line, sort_keys=True)
            else:
                if not isinstance(line, dict):
                    line_dict = json_loads(line)
                else:
                    line_dict = line

                type_harmonization = self.harmonization.get(
                    line_dict.get("__type", "Event").lower()
                )

                for k in list(line_dict.keys()):
                    if k == "__type":
                        continue
                    if k not in type_harmonization and not k.startswith("extra."):
                        line_dict[f"extra.{k}"] = line_dict[k]
                        del line_dict[k]

                event.update(
                    MessageFactory.from_dict(
                        line_dict,
                        harmonization=self.harmonization,
                        default_type="Event",
                    )
                )
                event.add("raw", line, overwrite=False)
            event.add(
                "classification.type", "undetermined", overwrite=False
            )  # set to undetermined if input has no classification
            self.send_message(event)
        self.acknowledge_message()


BOT = JSONGenericParserBot
