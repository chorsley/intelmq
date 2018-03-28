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
            'classification.type': 'c&c',
            'extra': '{}',
            'feed.name': 'Abuse.ch Zeustracker',
            'feed.url': 'https://zeustracker.abuse.ch/rss.php',
            'source.fqdn': 'slap.alliancekl.com',
            'source.geolocation.cc': '',
            'source.ip': '',
            'status': 'offline',
            'time.source': '2017-11-07T07:14:59+00:00',
            'time.observation': '2015-11-02T13:11:43+00:00',
            '__type': 'Event',
            'raw': 'PGl0ZW0+Cjx0aXRsZT5zbGFwLmFsbGlhbmNla2wuY29tICgyMDE3LTExLTA3IDA3OjE0OjU5KTwvdGl0bGU+CjxsaW5rPmh0dHBzOi8vemV1c3RyYWNrZXIuYWJ1c2UuY2gvbW9uaXRvci5waHA/aG9zdD1zbGFwLmFsbGlhbmNla2wuY29tPC9saW5rPgo8ZGVzY3JpcHRpb24+SG9zdDogc2xhcC5hbGxpYW5jZWtsLmNvbSwgSVAgYWRkcmVzczogLCBTQkw6IE5vdCBsaXN0ZWQsIHN0YXR1czogb2ZmbGluZSwgbGV2ZWw6IDQsIE1hbHdhcmU6IENpdGFkZWwsIEFTOiAwLCBjb3VudHJ5OiA8L2Rlc2NyaXB0aW9uPgo8Z3VpZD5odHRwczovL3pldXN0cmFja2VyLmFidXNlLmNoL21vbml0b3IucGhwP2hvc3Q9c2xhcC5hbGxpYW5jZWtsLmNvbSZhbXA7aWQ9YTQ5MGY3Zjk0NDFjZjcxNjc5ZDdiOWRhNmQxODhkOGE8L2d1aWQ+CjwvaXRlbT4K',
    },
    {
            'classification.type': 'c&c',
            'extra': '{}',
            'feed.name': 'Abuse.ch Zeustracker',
            'feed.url': 'https://zeustracker.abuse.ch/rss.php',
            'source.fqdn': 'flex.comonwealthplc.com',
            'source.geolocation.cc': '',
            'source.ip': '',
            'status': 'offline',
            'time.source': '2017-10-23T09:31:03+00:00',
            'time.observation': '2015-11-02T13:11:43+00:00',
            '__type': 'Event',
            'raw': 'PGl0ZW0+Cjx0aXRsZT5mbGV4LmNvbW9ud2VhbHRocGxjLmNvbSAoMjAxNy0xMC0yMyAwOTozMTowMyk8L3RpdGxlPgo8bGluaz5odHRwczovL3pldXN0cmFja2VyLmFidXNlLmNoL21vbml0b3IucGhwP2hvc3Q9ZmxleC5jb21vbndlYWx0aHBsYy5jb208L2xpbms+CjxkZXNjcmlwdGlvbj5Ib3N0OiBmbGV4LmNvbW9ud2VhbHRocGxjLmNvbSwgSVAgYWRkcmVzczogLCBTQkw6IE5vdCBsaXN0ZWQsIHN0YXR1czogb2ZmbGluZSwgbGV2ZWw6IDQsIE1hbHdhcmU6IENpdGFkZWwsIEFTOiAwLCBjb3VudHJ5OiA8L2Rlc2NyaXB0aW9uPgo8Z3VpZD5odHRwczovL3pldXN0cmFja2VyLmFidXNlLmNoL21vbml0b3IucGhwP2hvc3Q9ZmxleC5jb21vbndlYWx0aHBsYy5jb20mYW1wO2lkPTcyZjkwY2Y5MjA4NGIyM2I2ZTJhY2I1OWYxYTA3NzJhPC9ndWlkPgo8L2l0ZW0+CjxpdGVtPgo=',
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
        self.run_bot()
        self.assertMessageEqual(0, ZEUS_EVENTS[0])
        self.assertMessageEqual(1, ZEUS_EVENTS[1])


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
