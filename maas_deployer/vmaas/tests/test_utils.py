#
#
#

import unittest
from maas_deployer.vmaas import util


class TestUtil(unittest.TestCase):

    def test_flatten(self):
        inmap = {'foo': 'bar',
                 'baz': {
                     'one': 1,
                     'two': 2,
                     'three': {
                         'eh': 'a',
                         'bee': 'b',
                         'sea': 'c'},
                 }}

        outmap = util.flatten(inmap)

        expected = {'foo': 'bar',
                    'baz_one': 1,
                    'baz_two': 2,
                    'baz_three_eh': 'a',
                    'baz_three_bee': 'b',
                    'baz_three_sea': 'c'}
        self.assertEquals(outmap, expected)

    def test_retry_on_exception(self):
        count = [0]

        @util.retry_on_exception()
        def foo():
            count[0] += 1
            raise Exception

        self.assertRaises(Exception, foo)
        self.assertEqual(count[0], 5)
