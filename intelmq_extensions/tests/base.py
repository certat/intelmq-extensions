import contextlib
import copy
import io
import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import intelmq.lib.message as message
import intelmq.lib.test as test
import intelmq.lib.utils as utils
import pkg_resources
import psycopg2
from intelmq import CONFIG_DIR, RUNTIME_CONF_FILE
from intelmq.lib.harmonization import DateTime
from psycopg2 import sql
from rt import Rt

from intelmq_extensions.cli import lib

from ..cli.utils import merge_harmonization

ADDITIONAL_HARMONIZATION = ["contrib/constituency.harmonization.part.json"]
# DB_FIELDS = []  # selection of fields to save in DB when using test entries creation

POSTGRES_CONFIG = {
    "host": os.getenv("INTELMQ_TEST_DATABASE_HOST", "localhost"),
    "port": os.getenv("INTELMQ_TEST_DATABASE_PORT", 5432),
    "database": "intelmq",
    "user": "intelmq",
    "password": "intelmq",
    "sslmode": "allow",
    "text_table": "boilerplates_tests",  # TODO: move to tables config
}


def mocked_config_from_extensions(
    bot_id="test-bot", sysconfig={}, group=None, module=None
):
    """The only one difference with original is the package used to load resources"""

    def mocked(conf_file):
        if conf_file == RUNTIME_CONF_FILE:
            return {
                bot_id: {
                    "description": "Instance of a bot for automated unit tests.",
                    "group": group,
                    "module": module,
                    "name": "Test Bot",
                    "parameters": sysconfig,
                }
            }
        elif conf_file.startswith(CONFIG_DIR):
            confname = os.path.join("etc/", os.path.split(conf_file)[-1])
            fname = pkg_resources.resource_filename("intelmq_extensions", confname)
            with open(fname) as fpconfig:
                return json.load(fpconfig)
        else:
            return utils.load_configuration(conf_file)

    return mocked


test.mocked_config = mocked_config_from_extensions


def load_harmonization():
    harmonization = pkg_resources.resource_filename(
        "intelmq_extensions", "etc/harmonization.conf"
    )
    extensions = []
    for file in ADDITIONAL_HARMONIZATION:
        with open(pathlib.Path(__file__).parent.parent.parent / file) as f:
            extensions.append(json.load(f))
    return merge_harmonization(extensions, harmonization)


class TestCaseMixin:
    harmonization = load_harmonization()

    TEST_EVENTS_TABLE = "tests"
    TEST_TEXT_TABLE = "boilerplates_tests"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._tmp_dir = None

    @property
    def tmp_dir(self):
        if not self._tmp_dir:
            self._tmp_dir = tempfile.mkdtemp(prefix="intelmq_extensions_test_")
        return self._tmp_dir

    def tearDown(self):
        if self._tmp_dir:
            shutil.rmtree(self._tmp_dir)

        super().tearDown()

    def new_event(self):
        return message.Event(harmonization=self.harmonization)

    def get_mocked_logger(self, logger):
        def log(name, *args, **kwargs):
            logger.handlers = self.logger_handlers_backup
            return logger

        return log

    @staticmethod
    def connect_database(config: dict):
        connection = psycopg2.connect(
            database=config["database"],
            user=config["user"],
            password=config["password"],
            host=config["host"],
            port=config["port"],
            sslmode=config["sslmode"],
        )
        connection.autocommit = True
        return connection

    def db_add_event(
        self,
        data: dict,
        cc: str = "AT",
        fqdn: str = "test.at",
        notify: bool = True,
        taxonomy: str = "test",
        abuse_contact: str = "tes@test.at",
        extra: dict = None,
    ) -> int:
        """Adds event to the test DB. Some common fields required by CLI have default values

        data: any dict representing an event
        """
        extra = extra or dict()
        event = message.Event(harmonization=self.harmonization)
        event.add("source.geolocation.cc", cc)
        event.add("source.fqdn", fqdn)
        event.add("classification.taxonomy", taxonomy)
        event.add("source.abuse_contact", abuse_contact)
        event.add("notify", notify)
        event.add("time.source", DateTime.generate_datetime_now())

        event.update(data)

        keys = list(event.keys()) + ["extra"]
        values = list(event.values()) + [json.dumps(extra)]
        inserted_id = self._db_insert(self.TEST_EVENTS_TABLE, keys, values)
        self._clear_db_events.append(inserted_id)

        for key, value in extra.items():
            event.add(f"extra.{key}", value)

        return inserted_id

    def _db_insert(self, table: str, keys, values, return_key: str = "id"):
        query = sql.SQL("INSERT INTO {} ({}) VALUES ({}) RETURNING {};").format(
            sql.Identifier(table),
            sql.SQL(",").join(map(sql.Identifier, keys)),
            sql.SQL(",").join([sql.SQL("%s")] * len(keys)),
            sql.Identifier(return_key),
        )
        self.cur.execute(query, list(values))
        inserted_id = self.cur.fetchone()[return_key]

        return inserted_id

    def db_get_event(self, event_id: int):
        query = sql.SQL("SELECT * from {} WHERE id=%s").format(
            sql.Identifier(self.TEST_EVENTS_TABLE)
        )
        self.cur.execute(query, (event_id,))
        return self.cur.fetchone()

    def db_delete(self, table, ids: list, id_field: str = "id"):
        query = sql.SQL("DELETE FROM {} WHERE {} = ANY(%s);").format(
            sql.Identifier(table),
            sql.Identifier(id_field),
        )
        self.cur.execute(query, (ids,))

    def add_boilerplate(self, key: str, body: str):
        self._db_insert(
            self.TEST_TEXT_TABLE, ["key", "body"], [key, body], return_key="key"
        )
        self.addCleanup(
            lambda: self.db_delete(self.TEST_TEXT_TABLE, [key], id_field="key")
        )

    def assertInLogs(self, msg_part):
        self.log_stream: io.StringIO
        self.log_stream.seek(0)
        self.assertTrue(
            any(msg_part in line for line in self.log_stream),
            f"'{msg_part}' not found in captured logs",
        )


class BotTestCase(TestCaseMixin, test.BotTestCase):
    """Provides test class with additional changes required for extension bots"""


class CLITestCase(TestCaseMixin, unittest.TestCase):
    """Provides helpers needed to test the intelmqcli"""

    CLI_CONTROLLER: lib.IntelMQCLIContollerTemplate = None

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()

        cls.db_connection = cls.connect_database(POSTGRES_CONFIG)
        cls.cur = cls.db_connection.cursor(
            cursor_factory=psycopg2.extras.RealDictCursor
        )

    def setUp(self) -> None:
        super().setUp()

        self.config = {
            "database": copy.deepcopy(POSTGRES_CONFIG),
            "log_path": None,  # Do not log tests to files
            "log_level": "DEBUG",
            "rt": {
                "uri": "",
                "user": None,
                "password": None,
                "incident_report_requestor": "test-intelmq",
                "zip_threshold": 10000,
            },
            "filter": {"cc": "AT", "fqdn": ".at|.wien"},
            "tables": {
                "events": self.TEST_EVENTS_TABLE,
                "v_events_filtered": self.TEST_EVENTS_TABLE,
                "boilerplates": self.TEST_TEXT_TABLE,
            },
        }

        self.log_stream = io.StringIO(newline="\n")
        self.logger = utils.log(
            self.id(),
            log_path=False,
            stream=self.log_stream,
            log_format_stream=utils.LOG_FORMAT,
            log_level=self.config["log_level"],
        )
        self.logger_handlers_backup = self.logger.handlers

        self._clear_db_events = []
        self.addCleanup(
            lambda: self.db_delete(self.TEST_EVENTS_TABLE, self._clear_db_events)
        )

        self._prepare_rt_mock()
        rt_patch = mock.patch(
            "intelmq_extensions.cli.lib.rt.Rt", return_value=self.rt_mock
        )
        rt_patch.start()
        self.addCleanup(rt_patch.stop)

    def _prepare_rt_mock(self):
        self.rt_mock = mock.Mock(spec_set=Rt(""))
        self._rt_ticket_id = 0
        self._rt_comment_id = 0

        def _assign_id(id_name: str):
            current = getattr(self, id_name)
            setattr(self, id_name, current + 1)
            return current + 1

        self.rt_mock.create_ticket = mock.Mock(
            spec=Rt.create_ticket,
            side_effect=lambda *_, **__: _assign_id("_rt_ticket_id"),
        )
        self.rt_mock.comment = mock.Mock(
            spec=Rt.comment, side_effect=lambda *_, **__: _assign_id("_rt_comment_id")
        )

    def assertRTTicketCount(self, count: int):
        self.assertEqual(self._rt_ticket_id, count)

    def get_rt_attachment(self, investigation_id):
        for call in self.rt_mock.reply.call_args_list:
            if call.args[0] == investigation_id:
                files = call.kwargs.get("files", [])
                return files[0] if files else None
        return None

    def get_rt_text(self, investigation_id):
        for call in self.rt_mock.reply.call_args_list:
            if call.args[0] == investigation_id:
                return call.kwargs.get("text", "")
        return None

    def _print_on_failure(self):
        if sys.version_info >= (3, 11):
            # Python 3.11 removed fields used here
            return
        # Based on: https://gist.github.com/hynekcer/1b0a260ef72dae05fe9611904d7b9675
        if hasattr(self._outcome, "errors"):
            result = self.defaultTestResult()
            self._feedErrorsToResult(result, self._outcome.errors)
        else:
            result = self._outcome.result

        passed = all(test != self for test, _ in result.errors + result.failures)
        if not passed:
            for captured in ["stderr", "stdout"]:
                if data := getattr(self, captured, None):
                    print(f"{'+' * 10} CLI {captured} {'+' * 10}")
                    print(*data if isinstance(data, list) else (data.getvalue(),))

    def tearDown(self) -> None:
        self._print_on_failure()

        super().tearDown()

    def run_cli(self, args: list, expect_code=0):
        with contextlib.redirect_stderr(io.StringIO()) as f_stderr:
            with contextlib.redirect_stdout(io.StringIO()) as f_stdout:
                with unittest.mock.patch(
                    "intelmq.lib.utils.log", self.get_mocked_logger(self.logger)
                ):
                    code = self.CLI_CONTROLLER(overridden_config=self.config).run(args)

        f_stdout.seek(0)
        self.stdout = f_stdout.readlines()
        f_stderr.seek(0)
        self.stderr = f_stderr.readlines()
        self.assertEqual(expect_code, int(code))
