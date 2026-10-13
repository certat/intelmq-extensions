"""Testing events splitter

SPDX-FileCopyrightText: 2023 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import unittest

from intelmq.lib.exceptions import ConfigurationError

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

    def test_keep_original_with_matches(self):
        message = {**INPUT, "extra.tag": "cve-2023-00000,other,cve-2023-00001"}
        self.input_message = message

        self.run_bot(parameters={"keep_original": True})

        self.assertOutputQueueLen(3)
        self.assertMessageEqual(0, message)
        self.assertMessageEqual(
            1,
            {
                **message,
                "classification.identifier": "cve-2023-00000",
                "extra.vulnerabilities": "cve-2023-00000",
            },
        )
        self.assertMessageEqual(
            2,
            {
                **message,
                "classification.identifier": "cve-2023-00001",
                "extra.vulnerabilities": "cve-2023-00001",
            },
        )

    def test_keep_original_no_matches_sent_once(self):
        message = {**INPUT, "extra.tag": "some,different,tags"}
        self.input_message = message

        self.run_bot(parameters={"keep_original": True})

        self.assertOutputQueueLen(1)
        self.assertMessageEqual(0, message)

    def test_keep_original_regex_matched(self):
        message = {**INPUT, "feed.code": "keep-me", "extra.tag": "cve-2023-00000"}
        self.input_message = message

        self.run_bot(
            parameters={
                "keep_original": True,
                "keep_original_look_in": "feed.code",
                "keep_original_regex": r"^keep-",
            }
        )

        self.assertOutputQueueLen(2)
        self.assertMessageEqual(0, message)
        self.assertMessageEqual(
            1,
            {
                **message,
                "classification.identifier": "cve-2023-00000",
                "extra.vulnerabilities": "cve-2023-00000",
            },
        )

    def test_keep_original_regex_not_matched(self):
        message = {**INPUT, "feed.code": "other", "extra.tag": "cve-2023-00000"}
        self.input_message = message

        self.run_bot(
            parameters={
                "keep_original": True,
                "keep_original_look_in": "feed.code",
                "keep_original_regex": r"^keep-",
            }
        )

        self.assertOutputQueueLen(1)
        self.assertMessageEqual(
            0,
            {
                **message,
                "classification.identifier": "cve-2023-00000",
                "extra.vulnerabilities": "cve-2023-00000",
            },
        )

    def test_keep_original_regex_field_missing(self):
        message = {**INPUT, "extra.tag": "cve-2023-00000"}
        self.input_message = message

        self.run_bot(
            parameters={
                "keep_original": True,
                "keep_original_look_in": "feed.code",
                "keep_original_regex": r"^keep-",
            }
        )

        self.assertOutputQueueLen(1)
        self.assertMessageEqual(
            0,
            {
                **message,
                "classification.identifier": "cve-2023-00000",
                "extra.vulnerabilities": "cve-2023-00000",
            },
        )

    def test_keep_original_regex_requires_keep_original(self):
        with self.assertRaises(ConfigurationError):
            self.run_bot(
                parameters={
                    "keep_original_look_in": "feed.code",
                    "keep_original_regex": r"^keep-",
                }
            )

    def test_keep_original_regex_requires_look_in(self):
        with self.assertRaises(ConfigurationError):
            self.run_bot(
                parameters={
                    "keep_original": True,
                    "keep_original_regex": r"^keep-",
                }
            )

    def test_keep_original_look_in_requires_regex(self):
        with self.assertRaises(ConfigurationError):
            self.run_bot(
                parameters={
                    "keep_original": True,
                    "keep_original_look_in": "feed.code",
                }
            )

    def test_keep_original_block_mode_matched_not_kept(self):
        message = {**INPUT, "feed.code": "keep-me", "extra.tag": "cve-2023-00000"}
        self.input_message = message

        self.run_bot(
            parameters={
                "keep_original": True,
                "keep_original_look_in": "feed.code",
                "keep_original_regex": r"^keep-",
                "keep_original_mode": "block",
            }
        )

        self.assertOutputQueueLen(1)
        self.assertMessageEqual(
            0,
            {
                **message,
                "classification.identifier": "cve-2023-00000",
                "extra.vulnerabilities": "cve-2023-00000",
            },
        )

    def test_keep_original_block_mode_not_matched_kept(self):
        message = {**INPUT, "feed.code": "other", "extra.tag": "cve-2023-00000"}
        self.input_message = message

        self.run_bot(
            parameters={
                "keep_original": True,
                "keep_original_look_in": "feed.code",
                "keep_original_regex": r"^keep-",
                "keep_original_mode": "block",
            }
        )

        self.assertOutputQueueLen(2)
        self.assertMessageEqual(0, message)
        self.assertMessageEqual(
            1,
            {
                **message,
                "classification.identifier": "cve-2023-00000",
                "extra.vulnerabilities": "cve-2023-00000",
            },
        )

    def test_keep_original_block_mode_field_missing_kept(self):
        message = {**INPUT, "extra.tag": "cve-2023-00000"}
        self.input_message = message

        self.run_bot(
            parameters={
                "keep_original": True,
                "keep_original_look_in": "feed.code",
                "keep_original_regex": r"^keep-",
                "keep_original_mode": "block",
            }
        )

        self.assertOutputQueueLen(2)
        self.assertMessageEqual(0, message)

    def test_keep_original_invalid_mode(self):
        with self.assertRaises(ConfigurationError):
            self.run_bot(
                parameters={
                    "keep_original": True,
                    "keep_original_look_in": "feed.code",
                    "keep_original_regex": r"^keep-",
                    "keep_original_mode": "deny",
                }
            )

    def test_keep_original_block_mode_requires_regex(self):
        with self.assertRaises(ConfigurationError):
            self.run_bot(
                parameters={
                    "keep_original": True,
                    "keep_original_mode": "block",
                }
            )

    def test_static_check_valid_config(self):
        self.assertIsNone(self.bot_reference.check(self.sysconfig))
        self.assertIsNone(
            self.bot_reference.check(
                {
                    **self.sysconfig,
                    "keep_original": True,
                    "keep_original_look_in": "feed.code",
                    "keep_original_regex": r"^keep-",
                    "keep_original_mode": "block",
                }
            )
        )

    def test_static_check_invalid_config(self):
        cases = [
            {"regex": r"(cve-"},
            {
                "keep_original": True,
                "keep_original_look_in": "feed.code",
                "keep_original_regex": r"(keep-",
            },
            {
                "keep_original": True,
                "keep_original_look_in": "feed.code",
                "keep_original_regex": r"^keep-",
                "keep_original_mode": "deny",
            },
            {"keep_original_look_in": "feed.code", "keep_original_regex": r"^keep-"},
            {"keep_original": True, "keep_original_regex": r"^keep-"},
            {"keep_original": True, "keep_original_look_in": "feed.code"},
            {"keep_original": True, "keep_original_mode": "block"},
        ]
        for params in cases:
            with self.subTest(params=params):
                results = self.bot_reference.check({**self.sysconfig, **params})
                self.assertEqual(1, len(results))
                self.assertEqual("error", results[0][0])

    def test_static_check_reports_all_errors(self):
        results = self.bot_reference.check(
            {
                **self.sysconfig,
                "regex": r"(cve-",
                "keep_original_regex": r"^keep-",
                "keep_original_mode": "deny",
            }
        )
        # invalid regex, invalid mode, keep_original disabled, missing look_in
        self.assertEqual(4, len([r for r in results if r[0] == "error"]))
