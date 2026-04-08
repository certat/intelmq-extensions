"""Testing Cryptshare Downloader expert bot

SPDX-FileCopyrightText: 2026 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import base64
import unittest
from unittest import mock

import requests
from requests_mock import MockerCore

from intelmq_extensions.bots.experts.cryptshare_downloader.expert import (
    CryptshareDownloadExpertBot,
)

from ....base import BotTestCase

CRYPTSHARE_URL = "https://cryptshare.example.com"
TRANSFER_ID = "rvaaaaaaaa"
FILE_NAME_HINT = f"download;jsessionid=node0aaaaaaaaaa.node0?0&id={TRANSFER_ID}"

INPUT = {
    "__type": "Report",
    "feed.name": "cryptshare-test",
    "feed.accuracy": 100.0,
    "extra.file_name": FILE_NAME_HINT,
    # Raw content sent by the rt_collector - will be replaced by the
    # actual file content downloaded from Cryptshare.
    "raw": base64.b64encode(b"placeholder").decode(),
}


class TestCryptshareDownloadExpertBot(BotTestCase, unittest.TestCase):
    @classmethod
    def set_bot(cls):
        cls.bot_reference = CryptshareDownloadExpertBot
        cls.sysconfig = {
            "cryptshare_url": CRYPTSHARE_URL,
            "password": "Test123456789",
        }

    def mock_http_session(self):
        session = requests.Session()
        session_mock = mock.patch(
            "intelmq_extensions.bots.experts.cryptshare_downloader.expert.create_request_session",
            return_value=session,
        )
        session_mock.start()
        self.addCleanup(session_mock.stop)

        self.requests = MockerCore(session=session)
        self.requests.start()
        self.addCleanup(self.requests.stop)

    def mock_transfer(self, transfer_id: str, files: list):
        self.requests.get(
            f"{CRYPTSHARE_URL}/api/transfers/{transfer_id}/files",
            status_code=200,
            json={"data": files},
        )

    def mock_file(self, transfer_id: str, file_id: str, content: bytes):
        self.requests.get(
            f"{CRYPTSHARE_URL}/api/transfers/{transfer_id}/files/{file_id}",
            status_code=200,
            content=content,
        )

    def setUp(self):
        super().setUp()
        self.mock_http_session()

    def test_single_file_download(self):
        """A transfer with one file produces one Report with updated raw and file_name."""
        self.mock_transfer(
            TRANSFER_ID,
            [{"id": "f1", "fileName": "report.csv"}],
        )
        self.mock_file(TRANSFER_ID, "f1", b"col1,col2\nv1,v2\n")

        self.input_message = INPUT
        self.run_bot()

        expected = {
            **INPUT,
            "extra.file_name": "report.csv",
            "raw": base64.b64encode(b"col1,col2\nv1,v2\n").decode(),
            "extra.cryptshare_id": TRANSFER_ID,
        }
        self.assertMessageEqual(0, expected)
        # 1 listing + 1 download
        self.assertEqual(2, self.requests.call_count)

    def test_multiple_files_produce_multiple_reports(self):
        """A transfer with several files emits one Report per file."""
        self.mock_transfer(
            TRANSFER_ID,
            [
                {"id": "f1", "fileName": "first.csv"},
                {"id": "f2", "fileName": "second.json"},
            ],
        )
        self.mock_file(TRANSFER_ID, "f1", b"first-content")
        self.mock_file(TRANSFER_ID, "f2", b'{"k": "v"}')

        self.input_message = INPUT
        self.run_bot()

        self.assertMessageEqual(
            0,
            {
                **INPUT,
                "extra.file_name": "first.csv",
                "raw": base64.b64encode(b"first-content").decode(),
                "extra.cryptshare_id": TRANSFER_ID,
            },
        )
        self.assertMessageEqual(
            1,
            {
                **INPUT,
                "extra.file_name": "second.json",
                "raw": base64.b64encode(b'{"k": "v"}').decode(),
                "extra.cryptshare_id": TRANSFER_ID,
            },
        )
        # 1 listing + 2 downloads
        self.assertEqual(3, self.requests.call_count)

    # Unable to test this way as create_request_session is mocked -> to improve?
    # def test_required_headers_are_set(self):
    #     """The Cryptshare password and client id must be forwarded as headers."""
    #     self.mock_transfer(
    #         TRANSFER_ID,
    #         [{"id": "f1", "fileName": "x.txt"}],
    #     )
    #     self.mock_file(TRANSFER_ID, "f1", b"x")

    #     self.input_message = INPUT
    #     self.run_bot()

    #     for call in self.requests.request_history:
    #         self.assertEqual("Test123456789", call.headers.get("X-CS-Password"))
    #         self.assertEqual(1, call.headers.get("X-CS-MajorApiVersion"))
    #         self.assertEqual("15", call.headers.get("X-CS-MinimumMinorApiVersion"))
    #         self.assertEqual("api.rest", call.headers.get("X-CS-ProductKey"))
    #         # 50 is the minimum client ID length accepted by Cryptshare
    #         self.assertGreater(len(call.headers.get("X-CS-ClientId")) > 50)

    def test_required_headers_are_prepared(self):
        """The Cryptshare password and client id must be forwarded as headers."""
        # self.mock_transfer(
        #     TRANSFER_ID,
        #     [{"id": "f1", "fileName": "x.txt"}],
        # )
        # self.mock_file(TRANSFER_ID, "f1", b"x")

        # self.input_message = INPUT
        self.prepare_bot(prepare_source_queue=False)

        # for call in self.requests.request_history:
        self.assertEqual("Test123456789", self.bot.http_header.get("X-CS-Password"))
        self.assertEqual(1, self.bot.http_header.get("X-CS-MajorApiVersion"))
        self.assertEqual(15, self.bot.http_header.get("X-CS-MinimumMinorApiVersion"))
        self.assertEqual("api.rest", self.bot.http_header.get("X-CS-ProductKey"))
        # 50 is the minimum client ID length accepted by Cryptshare
        self.assertGreater(len(self.bot.http_header.get("X-CS-ClientId")), 50)

    def test_empty_transfer_emits_no_report(self):
        """An empty transfer is acknowledged without emitting downstream messages."""
        self.mock_transfer(TRANSFER_ID, [])

        self.input_message = INPUT
        self.run_bot(allowed_warning_count=1)

        self.assertEqual(0, len(self.get_output_queue()))
        self.assertEqual(1, self.requests.call_count)

    def test_missing_file_name_is_skipped(self):
        """Reports without extra.file_name are acknowledged and logged."""
        self.input_message = {
            "__type": "Report",
            "feed.name": "cryptshare-test",
            "raw": base64.b64encode(b"placeholder").decode(),
        }
        self.run_bot(allowed_warning_count=1)

        self.assertEqual(0, len(self.get_output_queue()))
        self.assertEqual(0, self.requests.call_count)
        self.assertInLogs("without extra.file_name")

    def test_unparseable_file_name_is_skipped(self):
        """A file_name that does not contain an ``id=`` parameter is skipped."""
        self.input_message = {
            **INPUT,
            "extra.file_name": "download;jsessionid=xyz?0",  # no id parameter
        }
        self.run_bot(allowed_error_count=1)

        self.assertEqual(0, len(self.get_output_queue()))
        self.assertEqual(0, self.requests.call_count)
        self.assertInLogs("Cannot extract Cryptshare transfer id")

    def test_feed_metadata_is_preserved(self):
        """Metadata from the incoming Report (feed.*) must be kept on emitted ones."""
        self.mock_transfer(
            TRANSFER_ID,
            [{"id": "f1", "fileName": "data.csv"}],
        )
        self.mock_file(TRANSFER_ID, "f1", b"data")

        self.input_message = INPUT
        self.run_bot()

        import json

        emitted = json.loads(self.get_output_queue()[0])
        self.assertEqual("cryptshare-test", emitted["feed.name"])
        self.assertEqual(100.0, emitted["feed.accuracy"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
