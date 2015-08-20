#
# Copyright 2015 Canonical, Ltd.
#
# Unit tests for util functions

import unittest
from maas_deployer.vmaas import util
from mock import patch


class UnitTestException(Exception):
    """
    Use this in tests rather than generic Exception to avoid unexpectedly
    catching exceptions that also inherit from Exception.
    """
    pass


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

    @patch('time.sleep', lambda arg: None)
    def test_retry_on_exception(self):
        count = [0]

        @util.retry_on_exception(exc_tuple=(UnitTestException,))
        def foo():
            count[0] += 1
            raise UnitTestException

        self.assertRaises(UnitTestException, foo)
        self.assertEqual(count[0], 5)
