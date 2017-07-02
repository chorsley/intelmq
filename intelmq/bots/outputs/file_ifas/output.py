# -*- coding: utf-8 -*-
import io
import json

from intelmq.lib.bot import Bot


class FileIfasOutputBot(Bot):

    def init(self):
        self.logger.debug("Opening %r file.", self.parameters.file)
        self.file = io.open(self.parameters.file, mode='at', encoding="utf-8")
        self.logger.info("File %r is open.", self.parameters.file)

    def process(self):
        event = self.receive_message()
        event_d = event.to_dict(hierarchical=False)
        del event_d["raw"]
        if event_d.get("extra"):
            event_d["extra"] = json.loads(event_d["extra"])

        event_d = {"@fields": event_d}

        event_data = json.dumps(event_d)

        try:
            self.file.write(event_data)
            self.file.write("\n")
            self.file.flush()
        except FileNotFoundError:
            self.init()
        else:
            self.acknowledge_message()


BOT = FileIfasOutputBot
