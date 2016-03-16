#
# Copyright 2015 Canonical, Ltd.
#
# Unit tests for util functions

import unittest
import sys

from mock import (
    call,
    patch,
    Mock,
    MagicMock
)

sys.modules['apiclient'] = MagicMock()
from maas_deployer.vmaas import (
    engine,
    exception,
)


class TestEngine(unittest.TestCase):

    def test_get_node_tags(self):
        e = engine.DeploymentEngine
        node = {}
        self.assertEqual(e._get_node_tags(node), [])
        node = {'tags': 't1'}
        self.assertEqual(e._get_node_tags(node), ['t1'])
        # With extra whitespace
        node = {'tags': 't1 t2  t3 '}
        self.assertEqual(e._get_node_tags(node), ['t1', 't2', 't3'])

    def test_add_tags_to_node(self):
        e = engine.DeploymentEngine({}, 'test-env')
        client = MagicMock()
        client.add_tag = Mock()
        node = {'name': 'n1', 'tags': 't1 t2'}
        maas_node = {}
        e._add_tags_to_node(client, node, maas_node)
        client.add_tag.assert_has_calls([call('t1', maas_node),
                                         call('t2', maas_node)])

    @patch.object(engine.DeploymentEngine, '_add_tags_to_node')
    @patch.object(engine.DeploymentEngine, '_create_maas_tags')
    @patch.object(engine, 'MAASClient')
    def test_create_maas_nodes(self, mock_client, mock_create_maas_tags,
                               mock_add_tags_to_node):
        e = engine.DeploymentEngine({}, 'test-env')
        e._create_maas_nodes(mock_client, [])
        self.assertFalse(mock_create_maas_tags.called)
        self.assertFalse(mock_add_tags_to_node.called)

        maas_node = {}
        mock_client.get_nodes.return_value = []
        mock_client.create_node.side_effect = lambda n: maas_node

        mock_create_maas_tags.reset_mock()
        mock_add_tags_to_node.reset_mock()

        nodes = [{'name': 'n1'}, {'name': 'n2'}]
        e._create_maas_nodes(mock_client, nodes)
        mock_create_maas_tags.assert_has_calls([call(mock_client, nodes)])
        n0 = nodes[0]
        n0['hostname'] = n0['name']
        n1 = nodes[1]
        n1['hostname'] = n1['name']
        calls = [call(mock_client, n0, maas_node),
                 call(mock_client, n1, maas_node)]
        mock_add_tags_to_node.assert_has_calls(calls)

    @patch.object(engine, 'MAASClient')
    def test_create_maas_tags(self, mock_client):
        e = engine.DeploymentEngine({}, 'test-env')
        nodes = [{'name': 'n1'}, {'name': 'n2'}]
        e._create_maas_tags(mock_client, nodes)
        self.assertFalse(mock_client.create_tag.called)
        self.assertTrue(mock_client.get_tags.called)

        mock_client.reset_mock()
        nodes = [{'name': 'n1'}, {'name': 'n2', 'tags': 't1'}]
        e._create_maas_tags(mock_client, nodes)
        self.assertTrue(mock_client.create_tag.called)
        self.assertTrue(mock_client.get_tags.called)

    @patch.object(engine, 'MAASClient')
    def test_update_nodegroup(self, mock_client):
        e = engine.DeploymentEngine({}, 'test-env')
        nodegroup = {'uuid': 'fd623c43-6f5b-44fa-bc16-0f58a531063f'}
        maas_config = {'node_group': {'name': 'maas.demo'}}
        e.update_nodegroup(mock_client, nodegroup, maas_config)
        self.assertTrue(mock_client.update_nodegroup.called)

        maas_config = {'node_group': {'name': 'maas.demo', 'blah': 123}}
        self.assertRaises(exception.MAASDeployerConfigError,
                          e.update_nodegroup, mock_client, nodegroup,
                          maas_config)

    @patch.object(engine, 'MAASClient')
    def test_get_nodegroup(self, mock_client):
        nodegroups = [{"cluster_name": "Cluster master",
                       "status": 1,
                       "name": "maas",
                       "uuid": "d3e2db45-b5fb-4a25-a45e-7319b03a1ff5"},
                      {"cluster_name": "Alt",
                       "status": 1,
                       "name": "maas2",
                       "uuid": "c1575955-a6ca-43d8-a5dc-a2dc2c52e3ef"}]

        mock_client.get_nodegroups.return_value = nodegroups
        e = engine.DeploymentEngine({}, 'test-env')

        maas_config = {'node_group': {'name': 'maas.demo'}}
        nodegroup = e.get_nodegroup(mock_client, maas_config)
        self.assertEqual(nodegroup['uuid'], nodegroups[0]['uuid'])

        maas_config = {'node_group': {'name': 'maas.demo', 'uuid':
                                      nodegroups[1]['uuid']}}
        nodegroup = e.get_nodegroup(mock_client, maas_config)
        self.assertEqual(nodegroup['uuid'], nodegroups[1]['uuid'])

        maas_config = {'node_group': {'name': 'maas.demo', 'uuid': 'foo'}}
        self.assertRaises(exception.MAASDeployerValueError, e.get_nodegroup,
                          mock_client, maas_config)

    @patch.object(engine.util, 'execc')
    @patch.object(engine, 'MAASClient')
    def test_configure_boot_source(self, mock_client, mock_execc):
        maas_config = {'boot_source':
                       {"url": "http://myarchive/images/ephemeral/daily/"}}
        e = engine.DeploymentEngine({}, 'test-env')
        e.configure_boot_source(mock_client, maas_config)
