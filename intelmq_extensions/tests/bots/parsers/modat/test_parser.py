"""Tests for ModatParserBot

SPDX-FileCopyrightText: 2025 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import json
import unittest
from copy import deepcopy
from datetime import datetime

import intelmq.lib.message as message
from dateutil.tz import UTC

from intelmq_extensions.bots.parsers.modat.parser import (
    SERVICE_MAPPED_FIELDS,
    ModatParserBot,
)

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
        extra: dict = None,
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
        if extra:
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

    def test_parsing_service_search(self):
        self.input_message = self._create_report_dict(data.SERVICE_RESPONSE_1)

        self.run_bot()

        self.assertOutputQueueLen(3)
        self.assertMessageEqual(
            0, self._create_event_dict(**data.SERVICE_EVENT_1), compare_raw=False
        )
        self.assertMessageEqual(
            1, self._create_event_dict(**data.SERVICE_EVENT_2), compare_raw=False
        )
        self.assertMessageEqual(
            2, self._create_event_dict(**data.SERVICE_EVENT_3), compare_raw=False
        )

    def test_service_excluded_fields_custom(self):
        self.input_message = self._create_report_dict(data.SERVICE_RESPONSE_1[:2])

        self.run_bot(
            parameters={
                "excluded_fields": ["tcp", "discovered_at", "http.files.sha256"]
            }
        )

        service_1 = deepcopy(data.SERVICE_RESPONSE_1[0]["service"])
        for field in SERVICE_MAPPED_FIELDS + ("tcp", "discovered_at"):
            service_1.pop(field)
        service_1.pop("http")
        service_1.pop("tls")
        event_1 = deepcopy(data.SERVICE_EVENT_1)
        event_1["extra"]["service"] = service_1
        self.assertMessageEqual(
            0, self._create_event_dict(**event_1), compare_raw=False
        )

        # descending into lists of dicts
        event_2 = self.get_output_queue()[1]
        files = json.loads(event_2)["extra.service"]["http"]["files"]
        self.assertEqual([{"path": "favicon.ico", "category": "favicon"}], files)
        self.assertIn("raw", json.loads(event_2)["extra.service"]["tls"])

    def test_service_excluded_fields_as_string(self):
        self.input_message = self._create_report_dict(data.SERVICE_RESPONSE_1[:1])

        self.run_bot(parameters={"excluded_fields": "banner, banner_hex,ssh"})

        event = deepcopy(data.SERVICE_EVENT_1)
        del event["extra"]["service"]["ssh"]
        self.assertMessageEqual(0, self._create_event_dict(**event), compare_raw=False)

    def test_service_excluded_fields_empty(self):
        self.input_message = self._create_report_dict(data.SERVICE_RESPONSE_1[:1])

        self.run_bot(parameters={"excluded_fields": []})

        extra_service = json.loads(self.get_output_queue()[0])["extra.service"]
        self.assertEqual("5353482d322e30", extra_service["banner_hex"])
        self.assertIn("key_exchange", extra_service["ssh"])
        self.assertNotIn("fingerprints", extra_service)
