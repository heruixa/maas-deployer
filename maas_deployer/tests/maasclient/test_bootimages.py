#
# Copyright 2015 Canonical, Ltd.
#
# Unit tests for maasclient's bootimages

import unittest

from maas_deployer.vmaas.maasclient import bootimages


class TestBootImages(unittest.TestCase):

    def test_sequence_no(self):
        sequence = bootimages.sequence_no(1)
        for i in xrange(500, 1000000):
            sequence.next()
