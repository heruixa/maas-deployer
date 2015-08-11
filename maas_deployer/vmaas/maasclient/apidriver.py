#
# Copyright 2015, Canonical Ltd
#

import bson
import json
import logging

from apiclient import maas_client as maas
from maas_deployer.vmaas.maasclient.driver import MAASDriver
from maas_deployer.vmaas.maasclient.driver import Response
from urllib2 import HTTPError

log = logging.getLogger('vmaas.main')
OK = 200


class APIDriver(MAASDriver):
    """
    A MAAS driver implementation which uses the MAAS API.
    """

    def __init__(self, api_url, api_key, *args, **kwargs):
        if api_url.find('/api/') < 0:
            api_url = api_url + '/api/1.0'
        super(APIDriver, self).__init__(api_url, api_key, *args, **kwargs)
        self._client = None
        self._oauth = None

    @property
    def client(self):
        """
        MAAS client

        :rtype: MAASClient
        """
        if self._client:
            return self._client

        self._client = maas.MAASClient(auth=self.oauth,
                                       dispatcher=maas.MAASDispatcher(),
                                       base_url=self.api_url)
        return self._client

    @property
    def oauth(self):
        """
        MAAS OAuth information for interacting with the MAAS API.

        :rtype: MAASOAuth
        """
        if self._oauth:
            return self._oauth

        if self.api_key:
            api_key = self.api_key.split(':')
            self._oauth = maas.MAASOAuth(consumer_key=api_key[0],
                                         resource_token=api_key[1],
                                         resource_secret=api_key[2])
            return self._oauth
        else:
            return None

    def _get(self, path, **kwargs):
        """
        Issues a GET request to the MAAS REST API, returning the data
        from the query in the python form of the json data.
        """
        try:
            response = self.client.get(path, **kwargs)
            payload = response.read()
            log.debug("Request %s results: [%s] %s", path, response.getcode(),
                      payload)

            if response.getcode() == OK:
                return Response(True, json.loads(payload))
            else:
                return Response(False, payload)
        except Exception as e:
            log.error("Error encountered: %s for %s with params %s",
                      e.message, path, str(kwargs))
            return Response(False, None)

    def _post(self, path, op, **kwargs):
        """
        Issues a POST request to the MAAS REST API.
        """
        try:
            response = self.client.post(path, op, **kwargs)
            payload = response.read()
            log.debug("Request %s results: [%s] %s", path, response.getcode(),
                      payload)

            if response.getcode() == OK:
                return Response(True, json.loads(payload))
            else:
                return Response(False, payload)
        except HTTPError as e:
            log.error("Error encountered: %s for %s with params %s",
                      str(e), path, str(kwargs))
            return Response(False, None)
        except Exception as e:
            # import pdb
            # pdb.set_trace()
            log.error("Request raised exception: %s", e)
            return Response(False, None)

    def _put(self, path, **kwargs):
        """
        Issues a PUT request to the MAAS REST API.
        """
        try:
            response = self.client.put(path, **kwargs)
            payload = response.read()
            log.debug("Request %s results: [%s] %s", path, response.getcode(),
                      payload)
            if response.getcode() == OK:
                return Response(True, payload)
            else:
                return Response(False, payload)
        except HTTPError as e:
            log.error("Error encountered: %s with details: %s for %s with "
                      "params %s", e, e.read(), path, str(kwargs))
            return Response(False, None)
        except Exception as e:
            log.error("Request raised exception: %s", e)
            return Response(False, None)

    ###########################################################################
    # MAAS server config API - http://maas.ubuntu.com/docs/api.html#maas-server
    ###########################################################################
    def get_config(self, name):
        """
        Returns the MAAS Server config value for the specific name parameter.

        See http://maas.ubuntu.com/docs/api.html#maas-server for the set of
        available configuration parameters for the MAAS server.

        :param name: the name of the config item to be retrieved
        :returns: the value of the config item
        """
        return self._get(u'/maas/', op='get_config', name=name)

    def set_config(self, name, value):
        """
        Sets the MAAS Server config specified to the value specified.

        See http://maas.ubuntu.com/docs/api.html#maas-server for the set of
        available configuration parameters for the MAAS server.

        :param name: the name of the config ite mto set.
        :returns: True if the config parameter was updated successfully,
                  False otherwise.
        """
        return self._post(u'/maas/', op='set_config', name=name, value=value)

    ###########################################################################
    # Boot Images API - http://maas.ubuntu.com/docs/api.html#boot-images
    ###########################################################################
    def get_boot_images(self, nodegroup):
        """
        Returns the boot images information for the specified nodegroup uuid.

        :param nodegroup: The nodegroup or uuid of the cluster for which the
                          images should be listed.
        """
        uuid = self._get_uuid(nodegroup)
        _url = u'/nodegroups/{uuid}/boot-images/'.format(uuid=uuid)
        return self._get(_url, op='list')

    def import_boot_images(self):
        """
        Initiates the importing of boot images.

        :rtype: bool indicating whether the start of the import was successful
        """
        return self.client.post(u'/nodegroups/', op='import_boot_images')

    ###########################################################################
    # Nodegroup API - http://maas.ubuntu.com/docs/api.html#nodegroups
    ###########################################################################
    def get_nodegroups(self):
        """
        Returns the nodegroups.
        http://maas.ubuntu.com/docs/api.html#nodegroups
        """
        return self._get(u'/nodegroups/', op='list')

    def accept_nodegroup(self, nodegroup):
        """
        Accept nodegroup enlistment(s).

        :param: nodegroup the uuid of the nodegroup or a Nodegroup object
        """
        uuid = self._get_uuid(nodegroup)
        return self._post(u'/nodegroups/', op='accept', uuid=uuid)

    ###########################################################################
    #  Nodegroup Interfaces API
    #  - http://maas.ubuntu.com/docs/api.html#nodegroup-interfaces
    ###########################################################################
    def get_nodegroup_interfaces(self, nodegroup):
        """
        List of NodeGroupInterfaces of a NodeGroup

        :param: uuid the uuid of the nodegroup
        :returns: a list of NodegroupInterface objects representing the
                 interfaces assigned to the nodegroup
        """
        uuid = self._get_uuid(nodegroup)
        _url = u'/nodegroups/{uuid}/interfaces/'.format(uuid=uuid)
        return self._get(_url, op='list')

    def get_nodegroup_interface(self, nodegroup, iface):
        """
        Returns the specified NodeGroupInterface for the nodegroup
        or None if not found.

        :param nodegroup: the nodegroup
        :param iface: the name of the interface.
        :returns: a NodeInterface for the specified iface
        """
        uuid = self._get_uuid(nodegroup)
        _url = u'/nodegroups/{uuid}/interfaces/{name}/'.format(uuid=uuid,
                                                               name=iface)
        return self._get(_url)

    def create_nodegroup_interface(self, nodegroup, iface):
        """
        Creates the NodegroupInterface in the nodegroup.

        :param nodegroup: uuid the uuid of the nodegroup
        :param iface: the interface for the node group
        """
        uuid = self._get_uuid(nodegroup)
        _url = u'/nodegroups/{uuid}/interfaces/'.format(uuid=uuid)
        return self._post(_url, op='new', **iface)

    def update_nodegroup_interface(self, nodegroup, iface):
        """
        Updates a nodegroup interface.
        """
        name = iface['name']
        uuid = self._get_uuid(nodegroup)
        _url = u'/nodegroups/{uuid}/interfaces/{name}/'.format(uuid=uuid,
                                                               name=name)
        return self._put(_url, **iface)

    ###########################################################################
    #  Node API - http://maas.ubuntu.com/docs/api.html#node
    ###########################################################################
    def get_node(self, system_id, **kwargs):
        """
        Read a specific node.

        :param system_id: the system id of the specified node
        """
        system_id = self._get_system_id(system_id)
        path = u'/nodes/{system_id}'.format(system_id=system_id)
        try:
            response = self.client.get(path, **kwargs)
            if response.getcode() == OK:
                return Response(True, bson.decode_all(response.read()))
            else:
                return Response(False, None)
        except Exception as e:
            log.error(str(e))
            return Response(False, None)

    def get_nodes(self, **kwargs):
        """
        Retrieves the list of nodes from the MAAS Controller, optionally
        specifyinng a set of criteria for filtering the response data.
        The filtering is defined online @
          - http://maas.ubuntu.com/docs/api.html#nodes

        :returns a list of Nodes in the MAAS cluster
        """
        return self._get(u'/nodes/', op='list')

    def accept_node(self, node):
        """
        Accepts the node into the nodegroup.
        Note: this implementation is somewhat naive and doesn't consider all
              possible return codes (400, 403, etc)

        :returns: True if the command was successful (200),
                  False otherwise.
        """
        system_id = self._get_system_id(node)
        return self._post(u'/nodes/', op='accept', system_id=[system_id])

    def accept_all_nodes(self):
        """
        Accepts all nodes into the node group.

        :returns: True if the command was successful (200),
                  False otherwise.
        """
        return self._post(u'/nodes/', op='accept_all')

    def create_node(self, node):
        """
        Creates the new Node. This create will autodetect the nodegroup.

        :params node: the node parameters
        :returns: a Node complete with the data requested/required.
        """
        return self._post(u'/nodes/', op='new', autodetect_nodegroup='yes',
                          **node)

    def claim_sticky_ip_address(self, node, requested_address, mac_address):
        """
        Assign a 'sticky' IP Address to a Node's MAC.

        :param node: the node (or system-id) to assign the sticky ip address to
        :param requested_address: the ip address of the node
        :param mac_address: the mac address to assign the ip_addr to
        """
        system_id = self._get_system_id(node)
        _url = u'/nodes/{system_id}/'.format(system_id=system_id)
        return self._post(_url, op='claim_sticky_ip_address',
                          mac_address=mac_address,
                          requested_address=requested_address)

    ###########################################################################
    #  Tags API - http://maas.ubuntu.com/docs/api.html#tags
    ###########################################################################
    def get_tags(self):
        """
        Get a listing of the Tags which are currently defined.

        :returns: a list of Tag objects
        """
        return self._get(u'/tags/', op='list')

    def create_tag(self, tag):
        """
        Creates a new Tag in the MAAS server.

        :returns: True if the Tag object was created, False otherwise.
        """
        return self._post(u'/tags/', op='new', **tag)

    def add_tag(self, tag, node):
        """
        Adds the specified tag to the specified node or system_id

        :returns: True if the Tag object was successfully assigned,
                  False otherwise.
        """
        system_id = self._get_system_id(node)
        _url = u'/tags/{name}/'.format(name=tag)
        return self._post(_url, op='update_nodes', add=system_id)
