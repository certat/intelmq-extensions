"""Event Group Splitter can split events based on tag groups,
and automatically recognize new groups.

The bot is designed with an intention to handle ShadowServer Compromise Website report.

SPDX-FileCopyrightText: 2024 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import itertools
import json
import re

from intelmq.lib.bot import ExpertBot


class EventGroupSplitterExpertBot(ExpertBot):
    look_in: str = "extra.tag"
    copy_to: list[str] = ["classification.identifier", "extra.vulnerabilities"]
    regex: str = ""  # has to match one group meaning matched duplication value
    ignore: list[str] = []  # tags to ignore
    # path to a JSON file holding groups; the file will be updated with new groups
    # the structure is a dict with keys as feed codes, and values as list of list of tags
    # e.g.:
    # {
    #   "feed-1": [["t1", "t2"], ["t1", "t3"]],
    #   "feed-2": [["t6"]]
    # }
    groups_file: str = None
    # whether groups should be analysed separately for every feed or not;
    # if not, the bot will not use "new group" path for events matching
    # group already seen in any other feed
    treat_feeds_separately: bool = True

    def init(self):
        self.matcher = re.compile(self.regex)

        self._tag_groups: dict[str, list[list[str]]] = []
        self._reload_groups()

    def _reload_groups(self, dump_current=False):
        if dump_current:
            with open(self.groups_file, "w+") as f:
                json.dump(
                    {
                        feed: [list(g) for g in groups]
                        for feed, groups in self._tag_groups.items()
                    },
                    f,
                    indent=4,
                )

        with open(self.groups_file) as f:
            new_groups = json.load(f)

        self._tag_groups = {
            feed: sorted(
                (set(group) for group in groups), key=lambda g: len(g), reverse=True
            )
            for feed, groups in new_groups.items()
        }

    def process(self):
        event = self.receive_message()

        lookup_data = event.get(self.look_in, "")
        matches = self.matcher.findall(lookup_data)
        if not matches:
            self.send_message(event)
        else:
            matches = [m for m in matches if m not in self.ignore]
            matches_set = set(matches)
            feed = event.get("feed.code", "")
            if self.treat_feeds_separately:
                feed_groups = self._tag_groups.get(feed, [])
            else:
                feed_groups = itertools.chain(*self._tag_groups.values())

            for group in feed_groups:
                if not matches_set >= group:
                    # The group is not in event's tags
                    continue
                self._generate_event(event, group)

                # Tags can be duplicated in event. Respect it.
                for tag in group:
                    matches.remove(tag)
                matches_set = set(matches)

                if not matches:
                    break

            # Something is left - new group
            if matches:
                new_group = set(matches)
                self.logger.info("New tag group was discovered: %s.", new_group)
                self._generate_event(event, new_group, new_group=True)

                if feed not in self._tag_groups:
                    self._tag_groups[feed] = list()
                self._tag_groups[feed].append(new_group)
                self._reload_groups(dump_current=True)

        self.acknowledge_message()

    def _generate_event(self, event, group: set, new_group: bool = False):
        grouped_value = "-".join(sorted(group))
        self.logger.debug("Found: %s.", group)
        sub_event = self.new_event(event)
        for key in self.copy_to:
            sub_event.add(key, grouped_value, overwrite=True)
        self.send_message(sub_event)
        if new_group:
            self.send_message(sub_event, path="new_tag_groups", path_permissive=True)


BOT = EventGroupSplitterExpertBot
