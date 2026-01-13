# SPDX-FileCopyrightText: 2016 Sebastian Wagner
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# -*- coding: utf-8 -*-
import base64
import os
import unittest
from json import dumps as json_dumps
from json import loads as json_loads

import intelmq.lib.test as test

from intelmq_extensions.bots.parsers.generic_json.parser import JSONGenericParserBot

ONELINE_REPORT = {
    "feed.name": "Test",
    "raw": (
        "eyJmZWVkLm5hbWUiOiAiVGVzdCBmZWVkIiwgInJhdyI6ICJabTl2WW"
        "1GeUNnPT0iLCAiX190eXBlIjogIkV2ZW50IiwgInRpbWUub2JzZXJ2YXRpb24iOiAiMjAxNS0wMS"
        "0wMVQwMDowMDowMCswMDowMCIsICJjbGFzc2lmaWNhdGlvbi50eXBlIjogInVua25vd24ifQ=="
    ),
    "__type": "Report",
    "time.observation": "2016-10-10T00:00:00+00:00",
}
EXAMPLE_EVENT = {
    "feed.name": "Test feed",
    "raw": "Zm9vYmFyCg==",
    "__type": "Event",
    "time.observation": "2015-01-01T00:00:00+00:00",
    "classification.type": "undetermined",
}
with open(os.path.join(os.path.dirname(__file__), "data.json"), "rb") as fh:
    RAW = base64.b64encode(fh.read()).decode()

MULTILINE_REPORT = {
    "feed.name": "Test feed",
    "raw": RAW,
    "__type": "Report",
}
MULTILINE_EVENTS = [
    {
        "feed.name": "Test feed",
        "raw": base64.b64encode(
            b'{"__type": "Event", "source.ip": "127.0.0.1", "classification.type": "c2-server"}'
        ).decode(),
        "__type": "Event",
        "classification.type": "c2-server",
        "source.ip": "127.0.0.1",
    },
    {
        "feed.name": "Test feed",
        "raw": base64.b64encode(
            b'{"__type": "Event", "source.ip": "127.0.0.2", "classification.type": "c2-server"}'
        ).decode(),
        "__type": "Event",
        "classification.type": "c2-server",
        "source.ip": "127.0.0.2",
    },
]
with open(os.path.join(os.path.dirname(__file__), "data2.json"), "rb") as fh:
    RAW2 = base64.b64encode(fh.read()).decode()

NO_DEFAULT_REPORT = {
    "feed.name": "Test feed",
    "raw": RAW2,
    "__type": "Report",
}
NO_DEFAULT_EVENT = MULTILINE_EVENTS[1].copy()
NO_DEFAULT_EVENT["raw"] = base64.b64encode(
    b'{"source.ip": "127.0.0.2", "classification.type": "c2-server"}\n'
).decode()

with open(os.path.join(os.path.dirname(__file__), "ncscnl.json"), "rb") as fh:
    NCSCNL_FILE = fh.read()
NCSCNL_RAW = base64.b64encode(NCSCNL_FILE).decode()
NCSC_EVENTS = json_loads(NCSCNL_FILE)
for i, event in enumerate(NCSC_EVENTS):
    NCSC_EVENTS[i]["raw"] = base64.b64encode(
        json_dumps(event, sort_keys=True).encode()
    ).decode()
    NCSC_EVENTS[i]["classification.type"] = "undetermined"
    NCSC_EVENTS[i]["feed.name"] = "NCSC.NL"
    NCSC_EVENTS[i]["__type"] = "Event"

NCSCNL_REPORT = {
    "feed.name": "NCSC.NL",
    "raw": NCSCNL_RAW,
    "__type": "Report",
}

with open(os.path.join(os.path.dirname(__file__), "generic_data.json"), "rb") as fh:
    GENERIC_RAW = base64.b64encode(fh.read()).decode()

MULTILINE_GENERIC_REPORT = {
    "feed.name": "Test feed",
    "raw": GENERIC_RAW,
    "__type": "Report",
}
MULTILINE_GENERIC_EVENTS = [
    {
        "feed.name": "Test feed",
        "raw": base64.b64encode(
            b'{"__type": "Event", "source.ip": "127.0.0.1", "notexists": "generic data"}'
        ).decode(),
        "__type": "Event",
        "extra.notexists": "generic data",
        "source.ip": "127.0.0.1",
        "classification.type": "undetermined",
    },
    {
        "feed.name": "Test feed",
        "raw": base64.b64encode(
            b'{"__type": "Event", "source.ip": "127.0.0.2", "somethingelse": '
            b'"hahaha", "extra.ok": "ok"}'
        ).decode(),
        "__type": "Event",
        "extra.somethingelse": "hahaha",
        "extra.ok": "ok",
        "source.ip": "127.0.0.2",
        "classification.type": "undetermined",
    },
]


class TestJSONParserBot(test.BotTestCase, unittest.TestCase):
    """
    A TestCase for a MalwareDomainListParserBot.
    """

    @classmethod
    def set_bot(cls):
        cls.bot_reference = JSONGenericParserBot
        cls.default_input_message = ONELINE_REPORT

    def test_oneline_report(self):
        """Test if correct Event has been produced."""
        self.run_bot()
        self.assertMessageEqual(0, EXAMPLE_EVENT)

    def test_multiline_report(self):
        """Test if correct Event has been produced."""
        self.input_message = MULTILINE_REPORT
        self.run_bot(parameters={"splitlines": True})
        self.assertMessageEqual(0, MULTILINE_EVENTS[0])
        self.assertMessageEqual(1, MULTILINE_EVENTS[1])

    def test_default_event(self):
        """Test if correct Event has been produced."""
        self.input_message = NO_DEFAULT_REPORT
        self.run_bot()
        self.assertMessageEqual(0, NO_DEFAULT_EVENT)

    def test_ncscnl(self):
        """A file containing a list of events (not per line)"""
        self.input_message = NCSCNL_REPORT
        self.run_bot(parameters={"multiple_events": True})
        self.assertMessageEqual(0, NCSC_EVENTS[0])
        self.assertMessageEqual(1, NCSC_EVENTS[1])
        self.assertMessageEqual(2, NCSC_EVENTS[2])

    def test_multiline_generic_report(self):
        """Test if correct Event has been produced."""
        self.input_message = MULTILINE_GENERIC_REPORT
        self.run_bot(parameters={"splitlines": True})
        self.assertMessageEqual(0, MULTILINE_GENERIC_EVENTS[0])
        self.assertMessageEqual(1, MULTILINE_GENERIC_EVENTS[1])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
