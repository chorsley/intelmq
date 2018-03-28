from xml.etree import ElementTree

from collections import OrderedDict

from intelmq.lib import utils
from intelmq.lib.bot import ParserBot
from intelmq.lib.exceptions import ConfigurationError

PHISHING = OrderedDict([
    ("line", "__IGNORE__"),
    ("id", "extra"),
    ("first", "__IGNORE__"),
    ("firsttime", "time.source"),
    ("last", "__IGNORE__"),
    ("lasttime", "__IGNORE__"),
    ("target", "event_description.target"),
    ("url", "source.url"),
    ("recent", "status"),  # can be 'down', 'toggle' or 'up'
    ("response", "extra"),
    ("ip", "source.ip"),
    ("review", "extra"),
    ("domain", "source.fqdn"),
    ("country", "source.geolocation.cc"),
    ("source", "source.registry"),
    ("email", "source.abuse_contact"),
    ("inetnum", "extra"),  # network range, probably source.network
    ("netname", "extra"),
    ("descr", "extra"),
])


class AbusechZeustrackerRSSParserBot(ParserBot):

    def parse(self, report):
        raw_report = utils.base64_decode(report.get('raw'))

        document = ElementTree.fromstring(raw_report)

        for entry in document.iter(tag='item'):
            entry_bytes = ElementTree.tostring(entry, encoding='utf-8', method='xml')
            entry_str = entry_bytes.decode("utf-8")
            # self.logger.info('entry_bytes {}!'.format(entry_str))
            yield entry_str

    def parse_line(self, entry_str, report):
        document = ElementTree.fromstring(entry_str)

        event = self.new_event(report)
        extra = {}

        title = document.find('title').text
        desc = document.find('title').text
        self.logger.info("title {}!".format(title))

        # event.add('feed.name', 'Abuse.ch Zeustracker')

        if extra:
            event.add('extra', extra)

        # event.add('classification.type', ctype)
        event.add('classification.type', 'c&c')
        event.add("raw", entry_str)
        self.logger.debug(event)
        yield event


BOT = AbusechZeustrackerRSSParserBot
