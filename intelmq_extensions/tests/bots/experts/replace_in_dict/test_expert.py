# -*- coding: utf-8 -*-
"""
Testing ReplaceInDictExpertBot.
"""

import copy
import unittest

from intelmq.lib.exceptions import ConfigurationError

from intelmq_extensions.bots.experts.replace_in_dict.expert import (
    ReplaceInDictExpertBot,
)

from ....base import BotTestCase


class TestReplaceInDictExpertBot(BotTestCase, unittest.TestCase):
    """
    A TestCase for ReplaceInDictExpertBot.
    """

    @classmethod
    def set_bot(cls):
        cls.bot_reference = ReplaceInDictExpertBot
        cls.sysconfig = {
            "old_value": "\\u0000",
            "new_value": "[nullbyte]",
            "fields": "extra",
        }
        cls.default_input_message = {"__type": "Event"}

    def test_event_no_changes(self):
        message = {
            "__type": "Event",
            "time.observation": "2015-01-01T00:00:00+00:00",
            "extra.payload": "foo",
            "extra.name": "bar",
            "extra.firmwarerev": 1,
        }
        self.input_message = copy.deepcopy(message)
        self.run_bot()
        self.assertMessageEqual(0, message)

    def test_event_no_extra(self):
        message = {
            "__type": "Event",
            "time.observation": "2015-01-01T00:00:00+00:00",
            "feed.code": "foo",
        }
        self.input_message = copy.deepcopy(message)
        self.run_bot()
        self.assertMessageEqual(0, message)

    def test_event_changes_one_dict(self):
        message = {
            "__type": "Event",
            "time.observation": "2015-01-01T00:00:00+00:00",
            "extra.payload": "foo\\u0000bar\\u0000",
            "extra.name": "bar ok \\u0001 and not ok \\\\u0000",
            "extra.firmwarerev": 1,
            "feed.code": "foo",
        }
        self.input_message = copy.deepcopy(message)
        self.run_bot()

        message["extra.payload"] = "foo[nullbyte]bar[nullbyte]"
        message["extra.name"] = "bar ok \\u0001 and not ok \\[nullbyte]"
        self.assertMessageEqual(0, message)

    def test_event_multiple_dict_fail_if_not_jsondict(self):
        with self.assertRaises(ConfigurationError):
            self.run_bot(
                parameters={
                    "fields": "extra,output",
                }
            )

    def test_event_other_fields_not_modified(self):
        message = {
            "__type": "Event",
            "time.observation": "2015-01-01T00:00:00+00:00",
            "feed.code": "foo\\u0000",
        }
        self.input_message = copy.deepcopy(message)
        self.run_bot()

        self.assertMessageEqual(0, message)


if __name__ == "__main__":
    unittest.main()
