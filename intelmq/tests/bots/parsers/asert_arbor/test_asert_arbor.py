# -*- coding: utf-8 -*-

import os
import unittest

import intelmq.lib.test as test
import intelmq.lib.utils as utils
from intelmq.bots.parsers.asert_arbor.parser import AsertArborParserBot

with open(
    os.path.join(os.path.dirname(__file__), 'single.xml')
) as handle:
    SINGLE_FILE = handle.read()

ACCEPTED_REPORT = {
    "feed.name": "ZoneH Defacements",
    "raw": utils.base64_encode(SINGLE_FILE),
    "__type": "Report",
    "time.observation": "2015-01-01T00:00:00+00:00",
}

ACCEPTED_EVENT00 = {
    '__type': 'Event',
    'feed.name': 'ASERT Arbor',
    'classification.type': 'botnet drone',
    'classification.taxonomy': 'Malicious Code',
    'classification.identifier': 'botnet',
    'extra': '',
    'source.geolocation.cc': 'ZZ',
    'source.ip': '203.0.113.1',
    'time.observation': '2015-01-01T00:00:00+00:00',
    'time.source': '2016-01-01T11:56:00+00:00'
}


class TestAsertArborParserBot(test.BotTestCase, unittest.TestCase):
    """
    A TestCase for a AsertArborParserBot
    """

    @classmethod
    def set_bot(cls):
        cls.bot_reference = AsertArborParserBot
        cls.default_input_message = ACCEPTED_REPORT
        cls.sysconfig = {}

    def test_event(self):
        """ Test if correct Event has been produced. """
        self.run_bot()
        self.assertMessageEqual(0, ACCEPTED_EVENT00)


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
