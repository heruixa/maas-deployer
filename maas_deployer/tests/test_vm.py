#
# Copyright 2015 Canonical, Ltd.
#

import unittest
from maas_deployer.vmaas import vm
from mock import patch, MagicMock


VIRSH_LIST_ALL = """
Id    Name                           State
----------------------------------------------------
 15    maas-boot-vm-dc1               running
 17    maas                           running
 -     juju-boot-vm-dc1               shut off
 -     fooX                           shut off
"""


class TestVM(unittest.TestCase):

    @patch.object(vm, 'log', MagicMock())
    @patch.object(vm.Instance, 'assert_pool_exists', lambda *args: None)
    @patch.object(vm, 'cfg')
    @patch.object(vm, 'virsh')
    @patch.object(vm.libvirt, 'open', lambda *args: None)
    def test_instance_domain_exists(self, mock_virsh, mock_cfg):
        mock_cfg.use_existing = False
        mock_cfg.remote = None

        def fake_virsh(cmd):
            self.assertEqual(cmd, ['list', '--all'])
            return (VIRSH_LIST_ALL, '')

        mock_virsh.side_effect = fake_virsh
        inst = vm.Instance({})
        self.assertFalse(inst._domain_exists('foo'))
        self.assertTrue(inst._domain_exists('fooX'))
