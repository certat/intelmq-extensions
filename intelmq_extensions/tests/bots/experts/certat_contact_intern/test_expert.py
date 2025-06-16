# -*- coding: utf-8 -*-
"""
Testing certat_contact
"""
import os
import unittest

import intelmq.lib.test as test

from intelmq_extensions.bots.experts.certat_contact_intern.expert import (
    CERTatContactExpertBot,
)

from ....base import POSTGRES_CONFIG, BotTestCase

if os.environ.get("INTELMQ_TEST_DATABASES"):
    import psycopg2
    from psycopg2 import sql

INPUT1 = {
    "__type": "Event",
    "source.asn": 64496,
    "time.observation": "2015-01-01T00:00:00+00:00",
    "feed.code": "another-feed-code",
}
OUTPUT1 = {
    "__type": "Event",
    "source.asn": 64496,
    "source.abuse_contact": "cert@example.com",
    "feed.code": "another-feed-code",
    "time.observation": "2015-01-01T00:00:00+00:00",
    "destination_visible": True,
}
INPUT2 = {
    "__type": "Event",
    "source.asn": 64496,
    "time.observation": "2015-01-01T00:00:00+00:00",
    "feed.code": "example-feed",
}
OUTPUT2 = {
    "__type": "Event",
    "source.asn": 64496,
    "source.abuse_contact": "cert@example.com",
    "time.observation": "2015-01-01T00:00:00+00:00",
    "feed.code": "example-feed",
    "destination_visible": False,
}
OUTPUT3 = {
    "__type": "Event",
    "source.asn": 64496,
    "source.abuse_contact": "cert@example.com",
    "time.observation": "2015-01-01T00:00:00+00:00",
    "feed.code": "example-feed",
    "destination_visible": True,
}
INPUT4 = {
    "__type": "Event",
    "source.asn": 64497,
    "time.observation": "2015-01-01T00:00:00+00:00",
    "feed.code": "another-feed-code",
}
OUTPUT4 = {
    "__type": "Event",
    "source.asn": 64497,
    "time.observation": "2015-01-01T00:00:00+00:00",
    "feed.code": "another-feed-code",
    "destination_visible": True,
}


@test.skip_database()
class TestCERTatContactExpertBot(BotTestCase, unittest.TestCase):
    """
    A TestCase for CERTatContactExpertBot.
    """

    @classmethod
    def set_bot(cls):
        cls.bot_reference = CERTatContactExpertBot
        cls.default_input_message = INPUT1
        if not os.environ.get("INTELMQ_TEST_DATABASES"):
            return
        cls.sysconfig = {
            "autocommit": True,
            "ascolumn": "asn",
            "column": "contact",
            "feed_code": "example-feed",
            "table": "test_contacts",
            "overwrite": False,
        }
        cls.sysconfig.update(POSTGRES_CONFIG)
        cls.con = psycopg2.connect(
            database=cls.sysconfig["database"],
            user=cls.sysconfig["user"],
            password=cls.sysconfig["password"],
            host=cls.sysconfig["host"],
            port=cls.sysconfig["port"],
            sslmode=cls.sysconfig["sslmode"],
        )
        cls.con.autocommit = True
        cls.cur = cls.con.cursor()
        cls.create_if_not_exists(cls)
        cls.truncate(cls)

    def create_if_not_exists(self):
        self.cur.execute(
            sql.SQL(
                "CREATE TABLE IF NOT EXISTS {} ({} integer, {} text, {} boolean);"
            ).format(
                sql.Identifier(self.sysconfig["table"]),
                sql.Identifier(self.sysconfig["ascolumn"]),
                sql.Identifier(self.sysconfig["column"]),
                sql.Identifier(
                    "can-see-tlp-amber_{}".format(self.sysconfig["feed_code"])
                ),
            ),
        )

    def truncate(self):
        self.cur.execute("TRUNCATE TABLE {}".format(self.sysconfig["table"]))

    def insert(self, asn, contact, tlp_amber):
        query = """
INSERT INTO {table}(
    "{ascolumn}", "{column}", "can-see-tlp-amber_{feed_code}"
) VALUES (%s, %s, %s)
""".format(
            table=self.sysconfig["table"],
            column=self.sysconfig["column"],
            feed_code=self.sysconfig["feed_code"],
            ascolumn=self.sysconfig["ascolumn"],
        )
        self.cur.execute(query, (asn, contact, tlp_amber))

    def test_simple(self):
        "simple query"
        self.insert(64496, "cert@example.com", False)
        self.input_message = INPUT1
        self.run_bot()
        self.assertMessageEqual(0, OUTPUT1)

    def test_special_feed(self):
        "query with special feed code"
        self.insert(64496, "cert@example.com", False)
        self.input_message = INPUT2
        self.run_bot()
        self.assertMessageEqual(0, OUTPUT2)

    def test_special_feed_amber(self):
        "query with special feed code"
        self.insert(64496, "cert@example.com", True)
        self.input_message = INPUT2
        self.run_bot()
        self.assertMessageEqual(0, OUTPUT3)

    def test_no_result_destination_visible(self):
        "check if destination_visible to set to true if there's no match in the DB"
        self.input_message = INPUT4
        self.run_bot()
        self.assertMessageEqual(0, OUTPUT4)

    def tearDown(self):
        self.truncate()
        super().tearDown()

    @classmethod
    def tearDownClass(cls):
        if not os.environ.get("INTELMQ_TEST_DATABASES"):
            return
        cls.truncate(cls)
        cls.cur.close()
        cls.con.close()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
