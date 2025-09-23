# -*- coding: utf-8 -*-
"""
ReplaceInDict allow replacing pattern in any text field in a dict field(s)
"""

from intelmq.lib.bot import ExpertBot
from intelmq.lib.exceptions import ConfigurationError, KeyNotExists


class ReplaceInDictExpertBot(ExpertBot):
    old_value: str = None
    new_value: str = None
    fields: str = None  # actually str | list on newer Python

    def init(self):
        if isinstance(self.fields, str):
            self.fields = self.fields.split(",")
        for field in self.fields:
            definition = self.harmonization["event"][field]
            if definition["type"] != "JSONDict":
                raise ConfigurationError("Field is not a JSONDict", field)

    def process(self):
        event = self.receive_message()

        for field in self.fields:
            for name, value in event.finditems(f"{field}."):
                if isinstance(value, str):
                    try:
                        event.change(
                            name, value.replace(self.old_value, self.new_value)
                        )
                    except KeyNotExists:
                        # Safeguard for an edge case if we would get default value
                        # of an non-existing field
                        pass

        self.send_message(event)
        self.acknowledge_message()


BOT = ReplaceInDictExpertBot
