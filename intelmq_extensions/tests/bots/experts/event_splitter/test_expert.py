"""Testing events splitter

SPDX-FileCopyrightText: 2023 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import unittest

from intelmq_extensions.bots.experts.event_splitter.expert import EventSplitterExpertBot

from ....base import BotTestCase

INPUT = {
    "__type": "Event",
    "classification.identifier": "zeus",
    "classification.type": "infected-system",
    "notify": False,
    "source.asn": 1,
    "source.ip": "192.0.2.1",
    "feed.name": "Example Feed",
}


class TestEventSplitterExpertBot(BotTestCase, unittest.TestCase):
    @classmethod
    def set_bot(cls):
        cls.bot_reference = EventSplitterExpertBot
        cls.sysconfig = {
            "look_in": "extra.tag",
            "copy_to": ["classification.identifier", "extra.vulnerabilities"],
            "regex": r"(cve-\d\d\d\d-[\d]+)",
        }

    def test_no_tags_sent_original_message(self):
        self.input_message = INPUT

        self.run_bot()

        self.assertOutputQueueLen(1)
        self.assertMessageEqual(0, INPUT)

    def test_no_matched_tags_sent_original_message(self):
        message = {**INPUT, "extra.tag": "some,different,tags"}
        self.input_message = message

        self.run_bot()

        self.assertOutputQueueLen(1)
        self.assertMessageEqual(0, message)

    def test_only_one_matched_apply_copy_to(self):
        message = {**INPUT, "extra.tag": "cve-2023-00000"}
        self.input_message = message

        self.run_bot()

        self.assertOutputQueueLen(1)
        self.assertMessageEqual(
            0,
            {
                **message,
                "classification.identifier": "cve-2023-00000",
                "extra.vulnerabilities": "cve-2023-00000",
            },
        )

    def test_multiple_matched_tags(self):
        message = {
            **INPUT,
            "extra.tag": "cve-2023-00000,other,cve-2023-00001,some,tag,cve-2023-00002",
        }
        self.input_message = message

        self.run_bot()

        self.assertOutputQueueLen(3)
        self.assertMessageEqual(
            0,
            {
                **message,
                "classification.identifier": "cve-2023-00000",
                "extra.vulnerabilities": "cve-2023-00000",
            },
        )
        self.assertMessageEqual(
            1,
            {
                **message,
                "classification.identifier": "cve-2023-00001",
                "extra.vulnerabilities": "cve-2023-00001",
            },
        )

        self.assertMessageEqual(
            2,
            {
                **message,
                "classification.identifier": "cve-2023-00002",
                "extra.vulnerabilities": "cve-2023-00002",
            },
        )
