from xml.etree import ElementTree
import re

from collections import OrderedDict
import dateutil.parser
import pytz
import socket

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


def is_ip_address(s):
    for fam in [socket.AF_INET, socket.AF_INET6]:
        try:
            socket.inet_pton(fam, s)
            return True
        except socket.error:
            pass

    return False


class AbusechZeustrackerRSSParserBot(ParserBot):

    def parse(self, report):
        raw_report = utils.base64_decode(report.get('raw'))

        document = ElementTree.fromstring(raw_report)

        for entry in document.iter(tag='item'):
            entry_bytes = ElementTree.tostring(entry, encoding='utf-8',
                                               method='xml')
            entry_str = entry_bytes.decode("utf-8")
            yield entry_str

    def parse_line(self, entry_str, report):
        document = ElementTree.fromstring(entry_str)

        event = self.new_event(report)
        extra = {}

        title = document.find('title').text

        m = re.search(r'\((?P<source_time>[0-9\-: ]*?)\)', title)

        if m:
            try:
                source_time = dateutil.parser.parse(m.group('source_time'))
                event.add('time.source',
                          source_time.replace(tzinfo=pytz.utc).isoformat())
            except ValueError:
                pass

        desc = document.find('description').text

        # Host: 5.101.176.115, IP address: 5.101.176.115, SBL: Not listed, status: unknown, level: 4, Malware: Citadel, AS: 198068, country: EE
        m = re.match(r"""Host:\s(?P<fqdn>.*?),\sIP\saddress:\s(?P<ip>.*?)?,\s
                     SBL:\s(?P<sbl>.*?)?,\sstatus:\s(?P<status>.*?),\s
                     level:\s(?P<level>.*?)?,\sMalware:\s(?P<malware>.*?)?,\s
                     AS:\s(?P<asn>.*?)?,\scountry:\s(?P<cc>.*?)?$""", desc, re.X)

        if m:
            # we get IPs as hostnames, IntelMQ won't let us add as fqdn
            if not is_ip_address(m.group('fqdn')):
                event.add('source.fqdn', m.group('fqdn'))

            if m.group('ip'):
                event.add('source.ip', m.group('ip'))
            if m.group('sbl'):
                extra['sbl'] = m.group('sbl')
            if m.group('status'):
                event.add('status', m.group('status'))
            if m.group('level'):
                extra['level'] = m.group('level')
            try:
                if m.group('asn') and int(m.group('asn')) > 0:
                    event.add('source.asn', m.group('asn'))
            except TypeError:
                pass
            event.add('source.geolocation.cc', m.group('cc'))

        if extra:
            event.add('extra', extra)

        event.add('classification.type', 'c&c')
        event.add("raw", entry_str)
        # self.logger.info(event)
        yield event


BOT = AbusechZeustrackerRSSParserBot
