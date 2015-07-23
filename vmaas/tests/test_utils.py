#
#
#

import unittest
from vmaas import util


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
