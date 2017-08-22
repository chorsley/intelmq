# -*- coding: utf-8 -*-
"""
ASERT Arbor XML report parser
"""
import csv
import io
from urllib.parse import urlparse
import functools

from bs4 import BeautifulSoup

from intelmq.lib import utils
from intelmq.lib.bot import ParserBot, RewindableFileHandle
from intelmq.lib.message import Event


def lookup_obj(obj, attr_list, default=None):
    """
    obj: an object
    attr_list: a list of strings to look up against soup_obj in sequence
    """
    try:
        return functools.reduce(lambda x, y:
            getattr(x, y), [obj] + attr_list)
    except AttributeError:
        return default


ASERT_EVENTS = {
    "dos": {
        'classification.type': 'botnet drone',
        'classification.taxonomy': 'Malicious Code',
        'classification.identifier': 'botnet',
    }
}


class AsertArborParserBot(ParserBot):
    def process(self):
        report = self.receive_message()

        #self.logger.debug(report)

        for incident, raw in self.parse(report):
            self.logger.debug(incident)
            print(incident)
            event = Event(report)
            event.add("raw", raw)
            self.logger.debug(event)

            #impact = #incident.assessment.impact.attrs.get("type")
            impact = lookup_obj(incident, ["assessment", "impact", "attrs"]).get("type")

            if not impact:
                self.logger.info("event didn't have a impact")
                continue

            try:
                fields = ASERT_EVENTS[impact]
            except KeyError:
                self.logger.warn("Asert parser can't handle impact type {}, "
                                 "skipping incident".format(impact))
                continue

            for imq_key, imq_val in fields.items():
                event.add(imq_key, imq_val)

            #parsed_url = urlparse(row["domain"])
            #extra = {}

            #event.add('classification.identifier', "compromised-website")
            #event.add('classification.type', 'compromised')
            #event.add('event_description.text', 'defacement')
            #event.add('time.source', row["add_date"] + ' UTC')
            #event.add('raw', raw)
            #event.add('source.ip', row["ip_address"], raise_failure=False)
            #event.add('source.fqdn', parsed_url.netloc, raise_failure=False)
            #event.add('source.geolocation.cc', row["country_code"],
            #          raise_failure=False)
            #event.add('protocol.application', parsed_url.scheme)
            ## yes, the URL field is called 'domain'
            #event.add('source.url', row["domain"], raise_failure=False)
            #if row.get("accept_date"):
            #    extra["accepted_date"] = row.get("accept_date")
            #extra["actor"] = row.get("attacker")
            #extra["http_target"] = row.get("web_server")
            #extra["os.name"] = row["system"]
            #extra["compromise_method"] = row["hackmode"]
            #extra["zoneh_report_id"] = row["defacement_id"]
            #if extra:
            #    event.add('extra', extra)
            self.send_message(event)
        self.acknowledge_message()

    def parse(self, report):
        raw_report = utils.base64_decode(report["raw"])
        print(raw_report)
        # Temporary fix for https://github.com/certtools/intelmq/issues/967
        raw_report = raw_report.translate({0: None})

        soup = BeautifulSoup(raw_report, 'lxml')

        self.logger.debug("getting incidents")
        print("getting incidents")
        for incident in soup.find_all("incident"):
            print(incident)
            # need fh to populate the raw field in main event handler
            print("Got incident")
            self.logger.debug("got incident")
            # returns parser object + original XML for raw
            yield incident, str(incident)


BOT = AsertArborParserBot
