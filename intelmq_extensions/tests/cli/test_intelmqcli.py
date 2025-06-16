from intelmq.lib.test import skip_database

from intelmq_extensions.cli.intelmqcli import IntelMQCLIContoller

from ..base import CLITestCase


@skip_database()
class TestIntelMQCLI(CLITestCase):
    CLI_CONTROLLER = IntelMQCLIContoller

    def test_list_feeds(self):
        self.db_add_event({"feed.code": "my-feed"})
        self.db_add_event({"feed.code": "feed-2"})

        self.run_cli(["-l"])

        self.assertIn("my-feed\n", self.stdout)
        self.assertIn("feed-2\n", self.stdout)

    def test_add_event_description_to_text(self):
        self.add_boilerplate(
            "test", "my generic description and \n{event_descriptions}"
        )
        self.add_boilerplate("event-description-divider", "\n ### \n")
        self.db_add_event(
            {
                "feed.code": "feed1",
                "rtir_report_id": 10,
                "event_description.text": "descrpt1",
            }
        )
        self.db_add_event(
            {
                "feed.code": "feed1",
                "rtir_report_id": 10,
                "event_description.text": "description with \\n encoded new line",
            }
        )

        self.run_cli(["--batch", "--quiet"])

        self.assertRTTicketCount(2)

        text = self.get_rt_text(2)
        self.assertIn(
            "description with \n encoded new line",
            text,
        )
        self.assertIn("\n ### \n", text)
        self.assertIn("descrpt1", text)

    def test_add_event_description_to_text_default_divider(self):
        self.add_boilerplate(
            "test", "my generic description and \n{event_descriptions}"
        )
        self.db_add_event(
            {
                "feed.code": "feed1",
                "rtir_report_id": 10,
                "event_description.text": "descrpt1",
            }
        )
        self.db_add_event(
            {
                "feed.code": "feed1",
                "rtir_report_id": 10,
                "event_description.text": "description with \\n encoded new line",
            }
        )

        self.run_cli(["--batch", "--quiet"])

        self.assertRTTicketCount(2)

        text = self.get_rt_text(2)
        self.assertIn("\n --- \n", text)


@skip_database()
class TestConstituencySupport(CLITestCase):
    CLI_CONTROLLER = IntelMQCLIContoller

    def setUp(self) -> None:
        super().setUp()
        self.config.update({"constituency": {"key": "energy"}})

        self.add_boilerplate("test", "some_body")

        self.event_ids = [
            self.db_add_event(
                {"feed.code": "feed1", "constituency": "energy", "rtir_report_id": 10}
            ),
            self.db_add_event(
                {"feed.code": "feed2", "constituency": "energy", "rtir_report_id": 20}
            ),
            self.db_add_event(
                {"feed.code": "feed3", "constituency": "national", "rtir_report_id": 30}
            ),
            self.db_add_event(
                {"feed.code": "feed4", "constituency": "national", "rtir_report_id": 40}
            ),
            self.db_add_event(
                {"feed.code": "feed5", "constituency": None, "rtir_report_id": 50}
            ),
        ]

    def test_all_list_feeds(self):
        """intelmqcli ignore constituency when listing - FIXME"""
        self.run_cli(["-l"])

        self.assertEqual(5, len(self.stdout))

    def test_run_create_reports(self):
        self.run_cli(["--batch", "--quiet"])

        self.assertInLogs("All taxonomies: test")

        # 1 new incident + 1 new investigation
        # events have the same abuse contact and taxonomy, so they are processed together
        self.assertRTTicketCount(2)

        for event_id in self.event_ids[:2]:
            event = self.db_get_event(event_id)
            self.assertEqual(event["rtir_incident_id"], 1)
            self.assertEqual(event["rtir_investigation_id"], 2)
            self.assertIsNotNone(event["sent_at"])

        # Other events untouched
        for event_id in self.event_ids[2:]:
            event = self.db_get_event(event_id)
            self.assertIsNone(event["rtir_incident_id"])
            self.assertIsNone(event["rtir_investigation_id"])
            self.assertIsNone(event["sent_at"])

    def test_creating_attachment_removes_new_lines_from_description(self):
        self.db_add_event(
            {
                "feed.code": "feed2",
                "constituency": "energy",
                "rtir_report_id": 20,
                "event_description.text": (
                    "Some very long description \n with \n\n multiple \n new lines."
                ),
            }
        )

        self.run_cli(["--batch", "--quiet"])

        self.assertInLogs("All taxonomies: test")

        self.assertRTTicketCount(2)

        _, content_io, __ = self.get_rt_attachment(investigation_id=2)
        content: str = content_io.getvalue()
        self.assertIn(
            "Some very long description   with    multiple   new lines.", content
        )
