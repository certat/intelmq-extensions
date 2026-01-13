# -*- coding: utf-8 -*-
"""
Testing IBANExtractorExpertBot.
"""

import copy
import unittest

from intelmq_extensions.bots.experts.iban_extractor.expert import IBANExtractorExpertBot

from ....base import BotTestCase


class TestIBANExtractorExpertBot(BotTestCase, unittest.TestCase):
    @classmethod
    def set_bot(cls):
        cls.bot_reference = IBANExtractorExpertBot
        cls.default_input_message = {"__type": "Event"}

    def test_event_no_lookup(self):
        message = {
            "__type": "Event",
            "time.observation": "2015-01-01T00:00:00+00:00",
            "extra.payload": "foo",
            "extra.name": "bar",
            "extra.firmwarerev": 1,
        }
        self.input_message = copy.deepcopy(message)
        self.prepare_bot(destination_queues=["no_lookup_data", "not_found"])
        self.run_bot(prepare=False)
        self.assertMessageEqual(0, message, path="no_lookup_data")
        self.assertMessageEqual(0, message, path="not_found")

    def test_event_no_iban(self):
        message = {
            "__type": "Event",
            "time.observation": "2015-01-01T00:00:00+00:00",
            "extra.payload": "foo",
            "extra.name": "bar",
            "extra.firmwarerev": 1,
            "extra.text": "adfssdtfghjlkl",
        }
        self.input_message = copy.deepcopy(message)
        self.prepare_bot(destination_queues=["not_found"])
        self.run_bot(prepare=False)
        self.assertMessageEqual(0, message, path="not_found")

    def test_iban(self):
        message = {
            "__type": "Event",
            "time.observation": "2015-01-01T00:00:00+00:00",
            "extra.payload": "foo",
            "extra.name": "bar",
            "extra.firmwarerev": 1,
            "extra.text": (
                "This is a message with an \n"
                "artificially generated IBAN number AT 0820111 1532 9734423 \n "
                "but it still should be valid"
            ),
        }
        self.input_message = copy.deepcopy(message)
        self.run_bot()
        message["extra.iban"] = "AT082011115329734423"
        message["extra.bank"] = "Erste Bank der oesterreichischen Sparkassen AG"
        message["extra.bic"] = "GIBAATWWXXX"
        message["extra.iban_hash"] = (
            "942b348fcca86b81f7465308e2b1b3cb6aaad1c218f9110699ab47cb34b6b1b8"
        )
        message["source.geolocation.cc"] = "AT"
        self.assertMessageEqual(0, message)


if __name__ == "__main__":
    unittest.main()
