# -*- coding: utf-8 -*-
import os
import unittest

import intelmq.lib.utils as utils
import intelmq.lib.test as test
from intelmq.bots.parsers.abusech.parser_zeustracker_rss import \
    AbusechZeustrackerRSSParserBot

with open(os.path.join(os.path.dirname(__file__), 'zeustracker_sample.rss')) as handle:
    RSS_FILE = handle.read()

with open(os.path.join(os.path.dirname(__file__), 'zeustracker_sample.rss.base64')) as handle:
    BASE64_DATA = handle.read()

ZEUS_REPORT = {
    "feed.url": "https://zeustracker.abuse.ch/rss.php",
    "feed.name": "Abuse.ch Zeustracker",
    "__type": "Report",
    "raw": utils.base64_encode(RSS_FILE),
    "time.observation": "2015-11-02T13:11:43+00:00"
}

ZEUS_EVENTS = [
    {
            'classification.type': 'c&c server',
            'extra': '{}',
            'feed.name': 'Abuse.ch Zeustracker',
            'feed.url': 'https://zeustracker.abuse.ch/rss.php',
            'raw': BASE64_DATA,
            'source.fqdn': 'slap.alliancekl.com',
            'source.geolocation.cc': '',
            'source.ip': '',
            'status': 'offline',
            'time.observation': '2015-11-02T13:11:43+00:00',
            '__type': 'Event',
    },
    {
            'classification.type': 'c&c server',
            'extra': '{}',
            'feed.name': 'Abuse.ch Zeustracker',
            'feed.url': 'https://zeustracker.abuse.ch/rss.php',
            'raw': BASE64_DATA,
            'source.fqdn': 'flex.comonwealthplc.com',
            'source.geolocation.cc': '',
            'source.ip': '',
            'status': 'offline',
            'time.observation': '2015-11-02T13:11:43+00:00',
            '__type': 'Event',
    }
]


class TestAbusechZeustrackerRSSParserBot(test.BotTestCase, unittest.TestCase):
    """
    A TestCase for CleanMXParserBot.
    """

    @classmethod
    def set_bot(cls):
        cls.bot_reference = AbusechZeustrackerRSSParserBot
        cls.default_input_message = ZEUS_REPORT

    def test_zeus(self):
        #print(self.default_input_message)
        self.run_bot()
        self.assertMessageEqual(0, ZEUS_EVENTS[0])
        self.assertMessageEqual(1, ZEUS_EVENTS[1])


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
