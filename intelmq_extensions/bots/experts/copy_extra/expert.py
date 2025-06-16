# -*- coding: utf-8 -*-
"""
Modify Expert bot let's you manipulate all fields with a config file.
"""
import json

from intelmq.lib.bot import Bot


class CopyExtraExpertBot(Bot):
    keys: list = []

    def process(self):
        event = self.receive_message()

        if "extra" in event:
            extra = json.loads(event["extra"])

            share = {key: extra[key] for key in self.keys if key in extra}
            if share:
                event.add("shareable_extra_info", share, overwrite=False)

        self.send_message(event)
        self.acknowledge_message()


BOT = CopyExtraExpertBot
