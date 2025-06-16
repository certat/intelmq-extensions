# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import json
import os
import os.path
import unittest
from copy import deepcopy
from unittest import mock

import intelmq.lib.test as test
import pkg_resources

from intelmq_extensions.bots.experts.squelcher.expert import SquelcherExpertBot

from ....base import POSTGRES_CONFIG, BotTestCase

INPUT1 = {
    "__type": "Event",
    "classification.identifier": "zeus",
    "classification.type": "infected-system",
    "notify": False,
    "source.asn": 1,
    "source.ip": "192.0.2.1",
    "feed.name": "Example Feed",
}

INPUT2 = INPUT1.copy()
INPUT2["classification.identifier"] = "https"
INPUT2["classification.type"] = "vulnerable-system"
OUTPUT2 = INPUT2.copy()
OUTPUT2["notify"] = True

INPUT3 = INPUT1.copy()
INPUT3["classification.identifier"] = "https"
INPUT3["classification.type"] = "vulnerable-system"
INPUT3["source.ip"] = "192.0.2.4"

INPUT4 = INPUT3.copy()
INPUT4["classification.identifier"] = "openresolver"
INPUT4["notify"] = True

INPUT5 = INPUT4.copy()
INPUT5["source.ip"] = "198.51.100.5"
OUTPUT5 = INPUT5.copy()
OUTPUT5["notify"] = False

INPUT6 = INPUT4.copy()
INPUT6["source.ip"] = "198.51.100.45"
OUTPUT6 = INPUT6.copy()
OUTPUT6["notify"] = False

INPUT7 = INPUT1.copy()
INPUT7["notify"] = True
INPUT7["source.fqdn"] = "example.com"
del INPUT7["source.ip"]
OUTPUT7 = INPUT7.copy()

INPUT8 = INPUT1.copy()
del INPUT8["notify"]
del INPUT8["source.asn"]
OUTPUT8 = INPUT8.copy()
OUTPUT8["notify"] = False

INPUT_INFINITE = {
    "__type": "Event",
    "classification.identifier": "zeus",
    "classification.type": "infected-system",
    "source.asn": 12312,
    "source.ip": "192.0.2.1",
}
OUTPUT_INFINITE = INPUT_INFINITE.copy()
OUTPUT_INFINITE["notify"] = False

INPUT_RANGE = {
    "__type": "Event",
    "classification.identifier": "zeus",
    "classification.type": "infected-system",
    "source.asn": 789,
    "source.ip": "10.0.0.10",
}

INPUT9 = INPUT1.copy()
INPUT9["extra.additionalmetadata"] = ["foobar"]

INPUT10 = INPUT1.copy()
INPUT10["notify"] = True

INPUT11 = INPUT1.copy()
INPUT11["extra.malware.variants"] = ["foo", "bar"]


# TODO: move test case to the use the test DB helper


@test.skip_database()
@test.skip_exotic()
class TestSquelcherExpertBot(BotTestCase, unittest.TestCase):
    """
    A TestCase for SquelcherExpertBot.
    """

    @classmethod
    def set_bot(cls):
        cls.bot_reference = SquelcherExpertBot
        cls.default_input_message = INPUT1
        if not os.environ.get("INTELMQ_TEST_DATABASES"):
            return
        cls.sysconfig = {
            "configuration_path": pkg_resources.resource_filename(
                "intelmq_extensions", "etc/squelcher.conf"
            ),
            "overwrite": True,
            "sending_time_interval": "2 years",
            "table": cls.TEST_EVENTS_TABLE,
            "logging_level": "DEBUG",
        }
        cls.sysconfig.update(POSTGRES_CONFIG)
        cls.con = cls.connect_database(POSTGRES_CONFIG)
        cls.con.autocommit = True
        cls.cur = cls.con.cursor()
        cls.truncate(cls)

    def truncate(self):
        self.cur.execute("TRUNCATE TABLE {}".format(self.sysconfig["table"]))

    def insert(
        self,
        classification_identifier,
        classification_type,
        notify,
        source_asn,
        source_ip,
        time_source,
        sent_at=None,
        report_id=None,
        feed_name="Example Feed",
        extra=None,
    ):
        if sent_at is not None:
            append = "LOCALTIMESTAMP + INTERVAL %s second"
        else:
            append = "%s"
        query = """
INSERT INTO {table}(
    "classification.identifier", "classification.type", notify, "source.asn",
    "source.ip", "time.source", "rtir_report_id", "sent_at", "feed.name", "extra"
) VALUES (%s, %s, %s, %s, %s,
    LOCALTIMESTAMP + INTERVAL %s second, %s,
    {append}, %s, %s)
""".format(table=self.sysconfig["table"], append=append)
        self.cur.execute(
            query,
            (
                classification_identifier,
                classification_type,
                notify,
                source_asn,
                source_ip,
                time_source,
                report_id,
                sent_at,
                feed_name,
                json.dumps(extra or dict()),
            ),
        )

    def test_ttl_1(self):
        "event exists in db -> squelch"
        self.insert("zeus", "infected-system", True, 1, "192.0.2.1", "0")
        self.input_message = INPUT1
        self.run_bot()
        self.truncate()
        self.assertLogMatches("Found TTL 604800 for", levelname="DEBUG")
        self.assertMessageEqual(0, INPUT1)

    def test_ttl_2(self):
        "event in db is too old -> notify"
        self.insert("https", "vulnerable-system", True, 1, "192.0.2.1", "- 01:45")
        self.input_message = INPUT2
        self.run_bot()
        self.truncate()
        self.assertLogMatches("Found TTL 3600 for", levelname="DEBUG")
        self.assertMessageEqual(0, OUTPUT2)

    def test_ttl_2h_squelch(self):
        "event is in db -> squelch"
        self.insert("https", "vulnerable-system", True, 1, "192.0.2.4", "- 01:45")
        self.input_message = INPUT3
        self.run_bot()
        self.truncate()
        self.assertLogMatches("Found TTL 7200 for", levelname="DEBUG")
        self.assertMessageEqual(0, INPUT3)

    def test_network_match(self):
        """event is in db without notify -> notify
        find ttl based on network test"""
        self.insert(
            "openresolver", "vulnerable-system", False, 1, "198.51.100.5", "- 20:00"
        )
        self.input_message = INPUT5
        self.run_bot()
        self.truncate()
        self.assertLogMatches("Found TTL 115200 for", levelname="DEBUG")
        self.assertMessageEqual(0, INPUT5)

    def test_network_match3(self):
        """event is in db -> squelch
        find ttl based on network test"""
        self.insert(
            "openresolver",
            "vulnerable-system",
            True,
            1,
            "198.51.100.5",
            "- 25:00",
            "- 25:00",
        )
        self.input_message = INPUT5
        self.run_bot()
        self.truncate()
        self.assertLogMatches("Found TTL 115200 for", levelname="DEBUG")
        self.assertMessageEqual(0, OUTPUT5)

    def test_address_match1(self):
        "event in db is too old -> notify"
        self.insert(
            "openresolver",
            "vulnerable-system",
            True,
            1,
            "198.51.100.45",
            "- 25:00",
            "- 25:00",
        )
        self.input_message = INPUT6
        self.run_bot()
        self.truncate()
        self.assertLogMatches("Found TTL 86400 for", levelname="DEBUG")
        self.assertMessageEqual(0, INPUT6)

    def test_address_match2(self):
        "event is in db -> squelch"
        self.insert(
            "openresolver",
            "vulnerable-system",
            True,
            1,
            "198.51.100.45",
            "- 20:00",
            "- 20:00",
        )
        self.input_message = INPUT6
        self.run_bot()
        self.truncate()
        self.assertLogMatches("Found TTL 86400 for", levelname="DEBUG")
        self.assertMessageEqual(0, OUTPUT6)

    def test_ttl_other_ident(self):
        "other event in db -> notify"
        self.insert(
            "https", "vulnerable-system", True, 1, "198.51.100.5", "- 01:45", "- 01:45"
        )
        self.input_message = INPUT4
        self.run_bot()
        self.truncate()
        self.assertLogMatches("Found TTL 7200 for", levelname="DEBUG")
        self.assertMessageEqual(0, INPUT4)

    def test_use_ttl_from_event(self):
        "Honour TTL from the event"
        input_msg = INPUT4.copy()
        input_msg["source.ip"] = "82.82.82.82"

        # Default TTL
        self.input_message = input_msg
        self.run_bot()
        self.truncate()
        self.assertLogMatches("Found TTL 604800 for", levelname="DEBUG")
        self.assertMessageEqual(0, input_msg)

        # Pre-defined TTL
        input_msg["extra.ttl"] = 10
        self.input_message = input_msg
        self.run_bot()
        self.truncate()
        self.assertLogMatches("Found TTL 10 for", levelname="DEBUG")
        self.assertMessageEqual(0, input_msg)

    def test_domain(self):
        "only domain -> notify true"
        self.input_message = INPUT7
        self.run_bot()
        self.truncate()
        self.assertNotRegexpMatchesLog("Found TTL")
        self.assertMessageEqual(0, OUTPUT7)

    def test_missing_asn(self):
        "no asn -> notify false"
        self.input_message = INPUT8
        self.run_bot()
        self.truncate()
        self.assertNotRegexpMatchesLog("Found TTL")
        self.assertMessageEqual(0, OUTPUT8)

    def test_domain_when_non_ip_filter(self):
        "only domain, but filtering without IP allowed -> process"
        self.input_message = INPUT7
        self.run_bot(parameters={"filter_ip_only": False, "source_fields": "feed.name"})
        self.truncate()
        self.assertRegexpMatchesLog("Found TTL 604800")  # default ttl
        self.assertMessageEqual(0, OUTPUT7)

    def test_missing_asn_when_non_ip_filter(self):
        "no asn, but filtering without IP allowed -> process"
        self.input_message = INPUT8
        self.run_bot(parameters={"filter_ip_only": False, "source_fields": "feed.name"})
        self.truncate()
        self.assertRegexpMatchesLog("Found TTL 604800")  # default ttl
        output = OUTPUT8.copy()
        output["notify"] = True
        self.assertMessageEqual(0, output)

    def test_infinite(self):
        "never notify with ttl -1"
        self.input_message = INPUT_INFINITE
        self.run_bot()
        self.truncate()
        self.assertLogMatches("Found TTL -1 for", levelname="DEBUG")
        self.assertMessageEqual(0, OUTPUT_INFINITE)

    def test_iprange(self):
        "test if mechanism checking IP ranges"
        self.input_message = INPUT_RANGE
        self.run_bot()
        self.truncate()
        self.assertLogMatches("Found TTL 72643 for", levelname="DEBUG")

    def test_unsent_notify(self):
        """event exists, but is older than 1 day and has not been sent -> notify"""
        self.insert(
            "openresolver",
            "vulnerable-system",
            True,
            1,
            "198.51.100.5",
            str(-25 * 3600),
        )
        self.sysconfig["sending_time_interval"] = "1 day"
        self.input_message = INPUT5
        self.run_bot()
        self.sysconfig["sending_time_interval"] = "2 days"
        self.truncate()
        self.assertLogMatches("Found TTL 115200 for", levelname="DEBUG")
        self.assertMessageEqual(0, INPUT5)

    def test_unsent_squelch(self):
        """event exists, is younger than 2 days and has not been sent -> squelch"""
        self.insert(
            "openresolver", "vulnerable-system", True, 1, "198.51.100.5", "- 86400"
        )
        self.input_message = INPUT5
        self.run_bot()
        self.truncate()
        self.assertLogMatches("Found TTL 115200 for", levelname="DEBUG")
        self.assertMessageEqual(0, OUTPUT5)

    def test_extra_list(self):
        """lists in extra data is handled."""
        self.insert("zeus", "infected-system", True, 1, "192.0.2.1", "0")
        self.input_message = INPUT9
        self.run_bot()
        self.truncate()
        self.assertMessageEqual(0, INPUT9)

    def test_overwrite_false(self):
        """check if notify is not overwritten if not allowed."""
        self.input_message = INPUT10
        self.sysconfig["overwrite"] = False
        self.run_bot()
        self.sysconfig["overwrite"] = True
        self.assertLogMatches(
            "Notify field present and not allowed to overwrite, skipping.",
            levelname="DEBUG",
        )
        self.assertMessageEqual(0, INPUT10)

    def test_hashable(self):
        self.input_message = INPUT11
        self.run_bot(
            parameters={
                "configuration_path": os.path.join(
                    os.path.dirname(__file__), "unhashable.config"
                )
            }
        )
        self.assertLogMatches("Found TTL 123 for", levelname="DEBUG")

    def test_open_report_ttl_squelch(self):
        "event with report exists in db -> squelch"
        self.insert("zeus", "infected-system", True, 1, "192.0.2.1", "0", report_id="1")
        self.input_message = INPUT1
        self.run_bot(parameters={"query": "open_report"})
        self.truncate()
        self.assertLogMatches("Found TTL 604800 for", levelname="DEBUG")
        self.assertMessageEqual(0, INPUT1)

    def test_open_report_ttl_too_old(self):
        "event in db is too old -> notify"
        self.insert(
            "https", "vulnerable-system", True, 1, "192.0.2.1", "- 01:45", report_id="1"
        )
        self.input_message = INPUT2
        self.run_bot(parameters={"query": "open_report"})
        self.truncate()
        self.assertLogMatches("Found TTL 3600 for", levelname="DEBUG")
        self.assertMessageEqual(0, OUTPUT2)

    def test_custom_sources_ttl_too_old(self):
        "event in db is too old, matched using custom field -> notify"
        # different IP
        self.insert("https", "vulnerable-system", True, 1, "0.0.0.0", "- 01:45")
        self.input_message = INPUT2
        self.run_bot(parameters={"source_fields": "feed.name,source.asn"})
        self.truncate()
        self.assertLogMatches("Found TTL 3600 for", levelname="DEBUG")
        self.assertMessageEqual(0, OUTPUT2)

    def test_custom_sources_ttl_squelch(self):
        "event with report exists in db -> squelch"
        self.insert("zeus", "infected-system", True, 1, "0.0.0.0", "0")
        self.input_message = INPUT1
        self.run_bot(parameters={"source_fields": "feed.name,source.asn"})
        self.truncate()
        self.assertLogMatches("Found TTL 604800 for", levelname="DEBUG")
        self.assertMessageEqual(0, INPUT1)

    def test_custom_sources_json_squelch(self):
        "event with report exists in db -> squelch"
        self.insert(
            "zeus",
            "infected-system",
            True,
            1,
            "0.0.0.0",
            "0",
            extra={"ident": "something"},
        )
        message = INPUT1.copy()
        message["extra.ident"] = "something"
        self.input_message = deepcopy(message)
        self.run_bot(parameters={"source_fields": "extra.ident"})
        self.truncate()
        self.assertLogMatches("Found TTL 604800 for", levelname="DEBUG")
        self.assertMessageEqual(0, message)

    def test_custom_sources_all_need_match(self):
        "all custom source fields need to match to squelch"
        self.insert("zeus", "infected-system", True, 2, "0.0.0.0", "0")
        self.insert(
            "zeus", "infected-system", True, 1, "0.0.0.0", "0", feed_name="Another"
        )
        self.input_message = INPUT1
        self.run_bot(parameters={"source_fields": "feed.name,source.asn"})
        self.truncate()
        self.assertLogMatches("Found TTL 604800 for", levelname="DEBUG")
        output = INPUT1.copy()
        output["notify"] = True
        self.assertMessageEqual(0, output)

    def test_when_source_field_is_null(self):
        "Squelcher should compare against null values"
        self.insert("zeus", "infected-system", True, 2, "0.0.0.0", "0", report_id=None)
        self.input_message = INPUT1

        self.run_bot(parameters={"source_fields": "feed.name,rtir_report_id"})
        self.truncate()
        self.assertLogMatches("Found TTL 604800 for", levelname="DEBUG")

        # Notify: False - the same feed name and both events has lack of report id
        self.assertMessageEqual(0, INPUT1)

    def test_when_json_source_field_is_null(self):
        self.insert("zeus", "infected-system", True, 2, "0.0.0.0", "0")
        self.input_message = INPUT1

        self.run_bot(parameters={"source_fields": "feed.name,extra.something"})
        self.truncate()
        self.assertLogMatches("Found TTL 604800 for", levelname="DEBUG")

        # Notify: False - the same feed name and both events has lack of extra.something
        self.assertMessageEqual(0, INPUT1)

    def test_static_bot_check_method(self, *args, **kwargs):
        with mock.patch(
            "intelmq.lib.utils.load_configuration", new=test.mocked_config()
        ):
            super().test_static_bot_check_method()

    @classmethod
    def tearDownClass(cls):
        if not os.environ.get("INTELMQ_TEST_DATABASES"):
            return
        cls.truncate(cls)
        cls.cur.close()
        cls.con.close()


class TestSquelcherExpertBotHelper(unittest.TestCase):
    def test_convert_config_list(self):
        self.config = [
            [
                {"extra.malware.variants": ["foo", "bar"]},
                {"ttl": 10},
            ]
        ]
        SquelcherExpertBot.convert_config(self)
        self.assertEqual(
            self.config,
            [
                [
                    {"extra.malware.variants": ("foo", "bar")},
                    {"ttl": 10},
                ]
            ],
        )

    def test_convert_config_dict(self):
        self.config = [
            [
                {"extra.malware.variants": {"foo": "bar"}},
                {"ttl": 10},
            ]
        ]
        SquelcherExpertBot.convert_config(self)
        self.assertEqual(
            self.config,
            [
                [
                    {"extra.malware.variants": (("foo", "bar"),)},
                    {"ttl": 10},
                ]
            ],
        )


if __name__ == "__main__":
    unittest.main()
