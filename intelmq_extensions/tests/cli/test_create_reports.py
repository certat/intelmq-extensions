from intelmq.lib.test import skip_database

from intelmq_extensions.cli.create_reports import IntelMQCLIContoller

from ..base import CLITestCase


@skip_database()
class TestCreatingReports(CLITestCase):
    CLI_CONTROLLER = IntelMQCLIContoller

    def setUp(self) -> None:
        super().setUp()
        self.event_ids = [
            self.db_add_event({"feed.code": "feed1", "constituency": "energy"}),
            self.db_add_event({"feed.code": "feed2", "constituency": "energy"}),
            self.db_add_event({"feed.code": "feed3", "constituency": "national"}),
            self.db_add_event({"feed.code": "feed4", "constituency": "national"}),
            self.db_add_event({"feed.code": "feed5", "constituency": None}),
        ]

    def test_list_open_feeds(self):
        self.config.update({"constituency": {"key": "energy"}})

        self.run_cli(["-l"])

        self.assertEqual(2, len(self.stdout))
        self.assertIn("feed1\n", self.stdout)
        self.assertIn("feed2\n", self.stdout)

        self.config.update({"constituency": {"key": "national", "default": True}})

        self.run_cli(["-l"])
        self.assertEqual(3, len(self.stdout))
        self.assertIn("feed3\n", self.stdout)
        self.assertIn("feed4\n", self.stdout)
        self.assertIn("feed5\n", self.stdout)

    def test_run_create_reports(self):
        self.config.update({"constituency": {"key": "energy"}})

        self.run_cli([])

        self.assertInLogs("Handling feedcode 'feed1'")
        self.assertInLogs("Handling feedcode 'feed2'")
        self.assertRTTicketCount(2)

        event_feed1 = self.db_get_event(self.event_ids[0])
        self.assertEqual(event_feed1["rtir_report_id"], 1)

        event_feed2 = self.db_get_event(self.event_ids[1])
        self.assertEqual(event_feed2["rtir_report_id"], 2)

        self.assertIn("Owner", self.rt_mock.create_ticket.call_args.kwargs)

    def test_create_internal_only_notifications(self):
        self.config.update({"constituency": {"key": "national", "default": True}})
        id_1 = self.db_add_event(
            {"feed.code": "internal-only"},
            notify=True,
            abuse_contact="",
            cc="PL",
            extra={"monitored_asset": "something"},
        )
        id_2 = self.db_add_event(
            {"feed.code": "internal-only2"}, notify=True, abuse_contact="", cc="AT"
        )
        id_3 = self.db_add_event(
            {"feed.code": "internal-only2"},
            notify=True,
            abuse_contact="",
            cc="US",
            extra={"monitored_asset": "something"},
        )

        self.run_cli(
            [
                "--internal-notify",
                "--monitored-assets",
                "--feed",
                "internal-only",
                "internal-only2",
            ]
        )

        self.assertRTTicketCount(2)
        self.assertEqual(self.db_get_event(id_1)["rtir_report_id"], 1)
        for event_id in [id_2, id_3]:
            event = self.db_get_event(event_id)
            self.assertEqual(event["rtir_report_id"], 2)

        self.assertNotIn("Owner", self.rt_mock.create_ticket.call_args.kwargs)

        # Other events are untouched
        for event_id in self.event_ids:
            event = self.db_get_event(event_id)
            self.assertIsNone(event["rtir_report_id"])
