"""Testing events splitter

SPDX-FileCopyrightText: 2024 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import json
import unittest

from intelmq_extensions.bots.experts.event_group_splitter.expert import (
    EventGroupSplitterExpertBot,
)

from ....base import BotTestCase

INPUT = {
    "__type": "Event",
    "classification.identifier": "zeus",
    "classification.type": "infected-system",
    "notify": False,
    "source.asn": 1,
    "source.ip": "192.0.2.1",
    "feed.name": "Example Feed",
    "feed.code": "feed-1",
}


class TestEventGroupSplitter(BotTestCase, unittest.TestCase):
    "Test cases prepared to handle tagging in ShadowServer Compromised Website report"

    @classmethod
    def set_bot(cls):
        cls.bot_reference = EventGroupSplitterExpertBot
        cls.sysconfig = {
            "look_in": "extra.tag",
            "copy_to": ["classification.identifier"],
            "regex": r"([a-zA-Z0-9\-]+)[;]{0,1}",
            "ignore": ["tag2", "tag4"],
            "groups_file": None,
        }

    def setUp(self) -> None:
        super().setUp()
        self.create_dynamic_groups_file()

    def create_dynamic_groups_file(self):
        self.groups_file_path = f"{self.tmp_dir}/groups.json"
        groups = {
            "feed-1": [
                ["citrix", "injected-code"],
                ["backdoor-activity", "ivanti-connect-secure"],
                ["ivanti-connect-secure", "credential-stealer", "injected-code"],
            ],
            "feed-3": [["test"]],
        }
        with open(self.groups_file_path, "w+") as f:
            json.dump(groups, f)

    def test_ignore_selected_tags(self):
        message = {
            **INPUT,
            "extra.tag": "tag1,tag2,tag3,tag4",
        }
        self.input_message = message

        self.run_bot(parameters={"groups_file": self.groups_file_path})

        self.assertOutputQueueLen(1)
        self.assertMessageEqual(
            0,
            {
                **message,
                "classification.identifier": "tag1-tag3",
            },
        )

    def test_handle_configured_groups(self):
        message = {
            **INPUT,
            "extra.tag": "citrix;injected-code;backdoor-activity;ivanti-connect-secure",
        }
        self.input_message = message

        self.run_bot(parameters={"groups_file": self.groups_file_path})

        self.assertOutputQueueLen(2)
        self.assertMessageEqual(
            0,
            {
                **message,
                "classification.identifier": "citrix-injected-code",
            },
        )
        self.assertMessageEqual(
            1,
            {
                **message,
                "classification.identifier": "backdoor-activity-ivanti-connect-secure",
            },
        )

    def test_generate_new_groups(self):
        message = {
            **INPUT,
            "extra.tag": "injected-code;cisco;backdoor-activity;ivanti-connect-secure",
        }
        self.input_message = message

        self.run_bot(parameters={"groups_file": self.groups_file_path})

        self.assertOutputQueueLen(2)
        self.assertMessageEqual(
            0,
            {
                **message,
                "classification.identifier": "backdoor-activity-ivanti-connect-secure",
            },
        )
        self.assertMessageEqual(
            1,
            {
                **message,
                "classification.identifier": "cisco-injected-code",
            },
        )

    def test_generate_new_groups_when_duplicates(self):
        message = {
            **INPUT,
            "extra.tag": "citrix;injected-code;injected-code;cisco",
        }
        self.input_message = message

        self.run_bot(parameters={"groups_file": self.groups_file_path})

        self.assertOutputQueueLen(2)
        self.assertMessageEqual(
            0,
            {
                **message,
                "classification.identifier": "citrix-injected-code",
            },
        )
        self.assertMessageEqual(
            1,
            {
                **message,
                "classification.identifier": "cisco-injected-code",
            },
        )

        with open(self.groups_file_path) as f:
            new_groups = json.load(f)["feed-1"]
        self.assertEqual(4, len(new_groups))
        self.assertIn(set(["cisco", "injected-code"]), (set(g) for g in new_groups))

    def test_new_groups_are_kept(self):
        message = {
            **INPUT,
            "extra.tag": "injected-code;cisco",
        }
        self.input_message = message

        self.run_bot(parameters={"groups_file": self.groups_file_path})

        self.assertOutputQueueLen(1)
        self.assertMessageEqual(
            0,
            {
                **message,
                "classification.identifier": "cisco-injected-code",
            },
        )

        with open(self.groups_file_path) as f:
            new_groups = json.load(f)["feed-1"]
        self.assertIn(set(["cisco", "injected-code"]), (set(g) for g in new_groups))

        message = {
            **INPUT,
            "extra.tag": "cisco;injected-code;new-tag",
        }
        self.input_message = message

        self.run_bot(parameters={"groups_file": self.groups_file_path})
        self.assertOutputQueueLen(2)
        self.assertMessageEqual(
            0,
            {
                **message,
                "classification.identifier": "cisco-injected-code",
            },
        )
        self.assertMessageEqual(
            1,
            {
                **message,
                "classification.identifier": "new-tag",
            },
        )

        with open(self.groups_file_path) as f:
            new_groups = json.load(f)["feed-1"]
        self.assertEqual(5, len(new_groups))
        self.assertIn(set(["cisco", "injected-code"]), (set(g) for g in new_groups))
        self.assertIn(set(["new-tag"]), (set(g) for g in new_groups))

    def test_groups_are_separated_between_feeds(self):
        message = {
            **INPUT,
            "extra.tag": "citrix,injected-code",
            "feed.code": "feed-2",
        }
        self.input_message = message

        self.run_bot(parameters={"groups_file": self.groups_file_path})

        self.assertOutputQueueLen(1)
        self.assertMessageEqual(
            0,
            {
                **message,
                "classification.identifier": "citrix-injected-code",
            },
        )

        with open(self.groups_file_path) as f:
            new_groups = json.load(f)
        self.assertEqual(3, len(new_groups["feed-1"]))
        self.assertEqual(1, len(new_groups["feed-2"]))
        self.assertIn(
            set(["citrix", "injected-code"]), (set(g) for g in new_groups["feed-2"])
        )

    def test_groups_are_not_separated_between_feeds_if_set(self):
        message = {
            **INPUT,
            "extra.tag": "citrix,injected-code",
            "feed.code": "feed-2",
        }
        self.input_message = message

        self.prepare_bot(
            parameters={
                "groups_file": self.groups_file_path,
                "treat_feeds_separately": False,
            },
            destination_queues=["_default", "new_tag_groups"],
        )
        self.run_bot(prepare=False)

        self.assertOutputQueueLen(1)
        self.assertOutputQueueLen(0, "new_tag_groups")
        self.assertMessageEqual(
            0,
            {
                **message,
                "classification.identifier": "citrix-injected-code",
            },
        )

        with open(self.groups_file_path) as f:
            new_groups = json.load(f)
        self.assertEqual(3, len(new_groups["feed-1"]))
        self.assertNotIn("feed-2", new_groups)

    def test_events_with_new_tag_groups_are_sent_to_specific_path(self):
        message_with_old_tag = {**INPUT, "extra.tag": "citrix,injected-code"}
        self.input_message = message_with_old_tag

        self.prepare_bot(
            parameters={"groups_file": self.groups_file_path},
            destination_queues=["_default", "new_tag_groups"],
        )
        self.run_bot(prepare=False)

        self.assertOutputQueueLen(1)
        self.assertOutputQueueLen(0, "new_tag_groups")

        message_with_new_tags = {**INPUT, "extra.tag": "new,group"}
        self.input_message = message_with_new_tags

        self.prepare_bot(
            parameters={"groups_file": self.groups_file_path},
            destination_queues=["_default", "new_tag_groups"],
        )
        self.run_bot(prepare=False)

        self.assertOutputQueueLen(1)
        self.assertOutputQueueLen(1, "new_tag_groups")

        # new_tag_groups should be notified only once
        self.input_message = message_with_new_tags

        self.prepare_bot(
            parameters={"groups_file": self.groups_file_path},
            destination_queues=["_default", "new_tag_groups"],
        )
        self.run_bot(prepare=False)

        self.assertOutputQueueLen(1)
        self.assertOutputQueueLen(0, "new_tag_groups")
