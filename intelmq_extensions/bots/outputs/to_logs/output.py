from intelmq.lib.bot import Bot


class ToLogOutput(Bot):
    def process(self):
        event = self.receive_message()
        jevent = event.to_json()
        self.logger.info("Got message %s", jevent)
        self.acknowledge_message()


BOT = ToLogOutput
