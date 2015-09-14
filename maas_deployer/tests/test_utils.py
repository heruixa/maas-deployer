#
# Copyright 2015 Canonical, Ltd.
#
# Unit tests for util functions

import os
import shutil
import subprocess
import tempfile
import unittest

from maas_deployer.vmaas import util
from mock import patch

from maas_deployer.tests.utils import (
    UnitTestException,
)


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

    def test_execc_piped_stderr(self):
        tmpdir = tempfile.mkdtemp()
        try:
            # expect error
            cmd1 = ['ls', os.path.join(tmpdir, '1')]
            self.assertRaises(subprocess.CalledProcessError, util.execc, cmd1)

            open(os.path.join(tmpdir, '2'), 'w')

            # expect NO error
            cmd1 = ['ls', os.path.join(tmpdir, '2')]
            util.execc(cmd1)

            # expect error
            cmd1 = ['ls', os.path.join(tmpdir, '1')]
            cmd2 = ['ls', os.path.join(tmpdir, '2')]
            open(os.path.join(tmpdir, '2'), 'w')
            self.assertRaises(subprocess.CalledProcessError, util.execc,
                              cmd1, pipedcmds=[cmd2])

            # expect NO error
            cmd1 = ['ls', os.path.join(tmpdir, '2')]
            cmd2 = ['ls', os.path.join(tmpdir, '2')]
            open(os.path.join(tmpdir, '2'), 'w')
            util.execc(cmd1, pipedcmds=[cmd2])

            # test exception params
            cmd1 = ['ls', os.path.join(tmpdir, '1')]
            cmd2 = ['ls', os.path.join(tmpdir, '2')]
            open(os.path.join(tmpdir, '2'), 'w')
            try:
                util.execc(cmd1, pipedcmds=[cmd2])
            except subprocess.CalledProcessError as exc:
                self.assertEqual(exc.output,
                                 "ls: cannot access %s: No such file or "
                                 "directory\n" % (os.path.join(tmpdir, '1')))
                self.assertEqual(exc.returncode, 2)
            else:
                raise UnitTestException("Exception not raised")

        finally:
            shutil.rmtree(tmpdir)
