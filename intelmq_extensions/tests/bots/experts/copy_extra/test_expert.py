# -*- coding: utf-8 -*-
"""
Testing Copy Extra expert bot.
"""

import unittest

from intelmq_extensions.bots.experts.copy_extra.expert import CopyExtraExpertBot

from ....base import BotTestCase

INPUT = {
    "__type": "Event",
    "time.observation": "2015-01-01T00:00:00+00:00",
    "extra.deviceid": "foo",
    "extra.devicerev": "bar",
    "extra.firmwarerev": 1,
}
OUTPUT = INPUT.copy()
OUTPUT["shareable_extra_info"] = '{"deviceid": "foo", "firmwarerev": 1}'


class TestCopyExtraExpertBot(BotTestCase, unittest.TestCase):
    """
    A TestCase for CopyExtraExpertBot.
    """

    @classmethod
    def set_bot(cls):
        cls.bot_reference = CopyExtraExpertBot
        cls.sysconfig = {"keys": ["deviceid", "firmwarerev"]}
        cls.default_input_message = {"__type": "Event"}

    def test_events(self):
        """Test if correct Events have been produced."""
        self.input_message = INPUT
        self.run_bot()
        self.assertMessageEqual(0, OUTPUT)


if __name__ == "__main__":
    unittest.main()
