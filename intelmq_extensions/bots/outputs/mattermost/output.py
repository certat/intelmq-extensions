from copy import deepcopy

from intelmq.lib.bot import OutputBot
from intelmq.lib.utils import create_request_session


class MattermostOutputBot(OutputBot):
    mm_url: str
    bot_token: str
    channel_id: str

    message: str = None

    # https://developers.mattermost.com/integrate/reference/message-attachments/
    fallback: str = None
    pretext: str = None
    text: str = None

    title: str = None
    title_link: str = None

    author_name: str = "IntelMQ"
    author_icon: str = None
    author_link: str = None

    color: str = None

    fields: list[dict] = None

    footer: str = None

    # https://developers.mattermost.com/integrate/webhooks/incoming/#parameters
    card: str = None

    _template_fields = [
        "fallback",
        "message",
        "pretext",
        "text",
        "title",
        "value",
        "footer",
    ]
    _attachment_fields = [
        "fallback",
        "pretext",
        "text",
        "title",
        "title_link",
        "author_name",
        "author_icon",
        "author_link",
        "color",
        "fields",
        "footer",
    ]
    _is_attachment = False

    def init(self):
        self.set_request_parameters()
        self.session = create_request_session(self)

        if not self.message and not self.text:
            raise ValueError("Either message or text have to be configured")

        if any(getattr(self, f, None) for f in self._attachment_fields):
            self._is_attachment = True

    def process(self):
        event = self.receive_message()
        event.set_default_value()

        request_data = {"channel_id": self.channel_id, "props": {}}

        if self.message:
            request_data["message"] = self.message.format(ev=event)

        if self._is_attachment:
            request_data["props"]["attachments"] = [self._prepare_attachment(event)]

        if self.card:
            request_data["props"]["card"] = self.card.format(ev=event)

        result = self.session.post(
            f"{self.mm_url}/api/v4/posts",
            json=request_data,
            headers={"Authorization": f"Bearer {self.bot_token}"},
        )
        result.raise_for_status()

        self.acknowledge_message()

    def _prepare_attachment(self, event) -> dict:
        attachment = {}
        for field in self._attachment_fields:
            data = getattr(self, field, None)
            if data is None:
                continue
            if field == "fields":
                data: list[dict] = deepcopy(data)
                for item in data:
                    if "title" in item:
                        item["title"] = item["title"].format(ev=event)
                    if "value" in item:
                        item["value"] = item["value"].format(ev=event)
            elif field in self._template_fields:
                data = data.format(ev=event)

            attachment[field] = data
        return attachment


BOT = MattermostOutputBot
