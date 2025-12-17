"""Tests for ModatParserBot

SPDX-FileCopyrightText: 2025 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import json
import unittest
from datetime import datetime

import intelmq.lib.message as message
from dateutil.tz import UTC

from intelmq_extensions.bots.parsers.modat.parser import ModatParserBot

from ....base import BotTestCase
from . import data


class TestModatParserBot(BotTestCase, unittest.TestCase):
    @classmethod
    def set_bot(cls):
        cls.bot_reference = ModatParserBot
        cls.sysconfig = {
            "default_fields": {
                "classification.taxonomy": "other",
                "classification.type": "other",
                "classification.identifier": "something",
            }
        }

    def _create_report_dict(self, raw, **kwargs):
        data = {
            "feed.name": "Test Bot",
            "feed.accuracy": 100.0,
            "feed.code": "feed-code",
            "time.observation": datetime(2023, 1, 1, tzinfo=UTC).isoformat(),
        }
        data.update(kwargs)
        report = message.Report(data, harmonization=self.harmonization)
        report.add("raw", json.dumps(raw))
        return report.to_dict(with_type=True)

    def _create_event_dict(
        self,
        extra: dict,
        # raw: dict,
        **kwargs,
    ):
        data = {
            "classification.identifier": "something",
            "classification.taxonomy": "other",
            "classification.type": "other",
            "time.observation": datetime(2023, 1, 1, tzinfo=UTC).isoformat(),
            "feed.accuracy": 100.0,
            "feed.code": "feed-code",
            "feed.name": "Test Bot",
        }
        data.update(kwargs)
        event = message.Event(data, harmonization=self.harmonization)
        event.add("extra", extra)
        # event.add(
        #     "raw", json.dumps(raw)
        # )
        return event.to_dict(with_type=True)

    def test_parsing_report_default(self):
        self.input_message = self._create_report_dict(data.RESPONSE_1)

        self.run_bot()

        self.assertMessageEqual(
            0,
            self._create_event_dict(
                **data.EVENT_1,
            ),
            compare_raw=False,
        )
        self.assertMessageEqual(
            1,
            self._create_event_dict(**data.EVENT_2),
            compare_raw=False,
        )
