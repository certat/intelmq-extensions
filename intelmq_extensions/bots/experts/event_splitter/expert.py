"""Event Splitter can produce multiple events from a one, based
on event's tag.

Currently implemented with intention of splitting CVE events.

SPDX-FileCopyrightText: 2023 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import re

from intelmq.lib.bot import ExpertBot


class EventSplitterExpertBot(ExpertBot):
    look_in: str = "extra.tag"
    copy_to: list[str] = ["classification.identifier", "extra.vulnerabilities"]
    regex: str = ""  # has to match one group meaning matched duplication value

    def init(self):
        self.matcher = re.compile(self.regex)

    def process(self):
        event = self.receive_message()

        lookup_data = event.get(self.look_in, "")
        matches = self.matcher.findall(lookup_data)
        if not matches:
            self.send_message(event)
        else:
            for matched in matches:
                self.logger.debug("Found: %s.", matched)
                sub_event = self.new_event(event)
                for key in self.copy_to:
                    sub_event.add(key, matched, overwrite=True)
                self.send_message(sub_event)

        self.acknowledge_message()


BOT = EventSplitterExpertBot
