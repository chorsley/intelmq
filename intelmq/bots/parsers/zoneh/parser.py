# -*- coding: utf-8 -*-
"""
ZoneH CSV defacement report parser
"""
import csv
import io
from urllib.parse import urlparse

from intelmq.lib import utils
from intelmq.lib.bot import ParserBot, RewindableFileHandle
from intelmq.lib.message import Event


# field name from Zone-H CSV on left, IntelMQ extra.* name on right
extra_field_map = {
    "accept_date": "accept_date",
    "attacker": "actor",
    "def_grade": "defacement_grade",
    "defacement_id": "zoneh_report_id",
    "hackmode": "compromise_method",
    "image": "mirror",
    "reason": "reason",
    "redefacement": "redefacement",
    "state": "publish_state",
    "system": "os.name",
    "type": "defacement_type",
    "web_server": "http_target",
}


class ZoneHParserBot(ParserBot):
    def process(self):
        report = self.receive_message()

        for row, raw in self.parse(report):
            event = Event(report)
            parsed_url = urlparse(row["domain"])
            extra = {}

            event.add('classification.identifier', "compromised-website")
            event.add('classification.type', 'compromised')
            event.add('event_description.text', 'defacement')
            event.add('time.source', row["add_date"] + ' UTC')
            event.add('raw', raw)
            event.add('source.ip', row["ip_address"], raise_failure=False)
            event.add('source.fqdn', parsed_url.netloc, raise_failure=False)
            event.add('source.geolocation.cc', row["country_code"],
                      raise_failure=False)
            event.add('protocol.application', parsed_url.scheme)
            # yes, the URL field is called 'domain'
            event.add('source.url', row["domain"], raise_failure=False)

            for (csv_field, imq_field) in extra_field_map.items():
                if row.get(csv_field):
                    extra[imq_field] = row.get(csv_field)

            if extra:
                event.add('extra', extra)
            self.send_message(event)
        self.acknowledge_message()

    def parse(self, report):
        raw_report = utils.base64_decode(report["raw"])
        # Temporary fix for https://github.com/certtools/intelmq/issues/967
        raw_report = raw_report.translate({0: None})
        fh = RewindableFileHandle(io.StringIO(raw_report))
        csvr = csv.DictReader(fh)

        # create an array of fieldnames,
        # those were automagically created by the dictreader
        self.fieldnames = csvr.fieldnames

        for row in csvr:
            # need fh to populate the raw field in main event handler
            yield row, fh.last_line


BOT = ZoneHParserBot
