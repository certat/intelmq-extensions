import unittest
from unittest import mock

import requests
from requests_mock import MockerCore

from intelmq_extensions.bots.outputs.mattermost.output import MattermostOutputBot

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


class TestMattermostOutputBot(BotTestCase, unittest.TestCase):
    MM_URL = "https://my.mm.instance"
    BOT_TOKEN = "XYZ"
    CHANNEL = "channel-1"

    @classmethod
    def set_bot(cls):
        cls.bot_reference = MattermostOutputBot
        cls.sysconfig = {
            "mm_url": cls.MM_URL,
            "bot_token": cls.BOT_TOKEN,
            "channel_id": cls.CHANNEL,
            "author_name": None,
            "author_icon": None,
        }

    def mock_http_session(self):
        session = requests.Session()
        session_mock = mock.patch(
            "intelmq_extensions.bots.outputs.mattermost.output.create_request_session",
            return_value=session,
        )
        session_mock.start()
        self.addCleanup(session_mock.stop)

        self.requests = MockerCore(session=session)
        self.requests.start()
        self.addCleanup(self.requests.stop)

    def mock_request(
        self,
        message: str = None,
        attachment: dict = None,
        card: str = None,
        path: str = "api/v4/posts",
        method: str = "post",
        **kwargs,
    ):
        data = {"channel_id": self.CHANNEL}
        if message is not None:
            data["message"] = message
        data["props"] = {}
        if attachment is not None:
            data["props"]["attachments"] = [attachment]
        if card is not None:
            data["props"]["card"] = card
        mocking_method = getattr(self.requests, method)
        mocking_method(
            f"{self.MM_URL}/{path}",
            request_headers={
                "Authorization": f"Bearer {self.BOT_TOKEN}",
            },
            **kwargs,
        )
        return data

    def setUp(self):
        super().setUp()
        self.mock_http_session()

    def test_simple_static_message(self):
        expected_payload = self.mock_request(message="This is a static message")

        self.input_message = INPUT
        self.run_bot(parameters={"message": "This is a static message"})

        self.assertEqual(1, self.requests.call_count)
        self.assertEqual(expected_payload, self.requests.last_request.json())

    def test_get_info_from_event_if_allowed(self):
        expected_payload = self.mock_request(
            message="message zeus",
            attachment={
                "pretext": "pretext zeus",
                "text": "text zeus",
                "fallback": "fallback zeus",
                "title": "title zeus",
                "title_link": "title_link {ev[classification.identifier]}",
                "author_name": "author_name {ev[classification.identifier]}",
                "author_icon": "author_icon {ev[classification.identifier]}",
                "author_link": "author_link {ev[classification.identifier]}",
                "color": "color {ev[classification.identifier]}",
                "footer": "footer zeus",
                "fields": [
                    {"short": True, "title": "field title zeus", "value": "value zeus"}
                ],
            },
            card="card zeus",
        )

        self.input_message = INPUT
        self.run_bot(
            parameters={
                "message": "message {ev[classification.identifier]}",
                "card": "card {ev[classification.identifier]}",
                "pretext": "pretext {ev[classification.identifier]}",
                "text": "text {ev[classification.identifier]}",
                "fallback": "fallback {ev[classification.identifier]}",
                "title": "title {ev[classification.identifier]}",
                "title_link": "title_link {ev[classification.identifier]}",
                "author_name": "author_name {ev[classification.identifier]}",
                "author_icon": "author_icon {ev[classification.identifier]}",
                "author_link": "author_link {ev[classification.identifier]}",
                "color": "color {ev[classification.identifier]}",
                "footer": "footer {ev[classification.identifier]}",
                "fields": [
                    {
                        "short": True,
                        "title": "field title {ev[classification.identifier]}",
                        "value": "value {ev[classification.identifier]}",
                    }
                ],
            }
        )

        self.assertEqual(1, self.requests.call_count)
        self.assertEqual(expected_payload, self.requests.last_request.json())
