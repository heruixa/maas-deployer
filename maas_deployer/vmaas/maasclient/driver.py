#
# Copyright 2015, Canonical Ltd
#
import logging

log = logging.getLogger('vmaas.main')


class Response(object):
    """
    Response for the API calls to use internally
    """
    def __init__(self, ok=False, data=None):
        self.ok = ok
        self.data = data

    def __nonzero__(self):
        """Allow boolean comparison"""
        return bool(self.ok)


class MAASDriver(object):
    """
    Defines the commands and interfaces for generically working with
    the MAAS controllers.
    """

    def __init__(self, api_url, api_key):
        self.api_url = api_url
        self.api_key = api_key

    def _get_system_id(self, obj):
        """
        Returns the system_id from an object or the object itself
        if the system_id is not found.
        """
        if 'system_id' in obj:
            return obj.system_id
        return obj

    def _get_uuid(self, obj):
        """
        Returns the UUID for the MAAS object. If the object has the attribute
        'uuid', then this method will return obj.uuid, otherwise this method
        will return the object itself.
        """
        if hasattr(obj, 'uuid'):
            return obj.uuid
        else:
            log.warning("Attr 'uuid' not found in %s" % obj)

        return obj

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
        raise NotImplementedError

    def set_config(self, name, value):
        """
        Sets the MAAS Server config specified to the value specified.

        See http://maas.ubuntu.com/docs/api.html#maas-server for the set of
        available configuration parameters for the MAAS server.

        :param name: the name of the config ite mto set.
        :returns: True if the config parameter was updated successfully,
                  False otherwise.
        """
        raise NotImplementedError()

    ###########################################################################
    # Boot Images API - http://maas.ubuntu.com/docs/api.html#boot-images
    ###########################################################################
    def get_boot_images(self, nodegroup):
        """
        Returns the boot images information for the specified nodegroup uuid.

        :param nodegroup: The nodegroup or uuid of the cluster for which the
                          images should be listed.
        """
        raise NotImplementedError()

    def import_boot_images(self):
        """
        Initiates the importing of boot images.

        :rtype: bool indicating whether the start of the import was successful
        """
        raise NotImplementedError()

    ###########################################################################
    # Nodegroup API - http://maas.ubuntu.com/docs/api.html#nodegroups
    ###########################################################################
    def get_nodegroups(self):
        """
        Returns the nodegroups.
        http://maas.ubuntu.com/docs/api.html#nodegroups
        """
        raise NotImplementedError()

    def accept_nodegroup(self, nodegroup):
        """
        Accept nodegroup enlistment(s).

        :param: nodegroup the uuid of the nodegroup or a Nodegroup object
        """
        raise NotImplementedError()

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
        raise NotImplementedError()

    def get_nodegroup_interface(self, nodegroup, iface):
        """
        Returns the specified NodeGroupInterface for the nodegroup
        or None if not found.

        :param nodegroup: the nodegroup
        :param iface: the name of the interface.
        :returns: a NodeInterface for the specified iface
        """
        raise NotImplementedError()

    def create_nodegroup_interface(self, nodegroup, iface):
        """
        Creates the NodegroupInterface in the nodegroup.

        :param nodegroup: uuid the uuid of the nodegroup
        :param iface: the interface for the node group
        """
        raise NotImplementedError()

    def update_nodegroup_interface(self, nodegroup, iface):
        """
        Updates a nodegroup interface.

        :param nodegroup: the uuid of the nodegroup
        :param iface: the maasclient.NodegroupInterface to update
        """
        raise NotImplementedError()

    ###########################################################################
    #  Node API - http://maas.ubuntu.com/docs/api.html#node
    ###########################################################################
    def get_node(self, system_id, **kwargs):
        """
        Read a specific node.

        :param system_id: the system id of the specified node
        """
        raise NotImplementedError()

    def get_nodes(self, **kwargs):
        """
        Retrieves the list of nodes from the MAAS Controller, optionally
        specifyinng a set of criteria for filtering the response data.
        The filtering is defined online @
          - http://maas.ubuntu.com/docs/api.html#nodes

        :returns a list of Nodes in the MAAS cluster
        """
        raise NotImplementedError()

    def accept_node(self, node):
        """
        Accepts the node into the nodegroup.
        Note: this implementation is somewhat naive and doesn't consider all
              possible return codes (400, 403, etc)

        :returns: True if the command was successful (200),
                  False otherwise.
        """
        raise NotImplementedError()

    def accept_all_nodes(self):
        """
        Accepts all nodes into the node group.

        :returns: True if the command was successful (200),
                  False otherwise.
        """
        raise NotImplementedError()

    def create_node(self, node):
        """
        Creates the new Node. This create will autodetect the nodegroup.

        :params node: the node parameters
        :returns: a Node complete with the data requested/required.
        """
        raise NotImplementedError()

    def claim_sticky_ip_address(self, node, requested_address, mac_address):
        """
        Assign a 'sticky' IP Address to a Node's MAC.

        :param node: the node (or system-id) to assign the sticky ip address to
        :param requested_address: the ip address of the node
        :param mac_address: the mac address to assign the ip_addr to
        """
        raise NotImplementedError()

    ###########################################################################
    #  Tags API - http://maas.ubuntu.com/docs/api.html#tags
    ###########################################################################
    def get_tags(self):
        """
        Get a listing of the Tags which are currently defined.

        :returns: a list of Tag objects
        """
        raise NotImplementedError()

    def create_tag(self, tag):
        """
        Creates a new Tag in the MAAS server.

        :returns: True if the Tag object was created, False otherwise.
        """
        raise NotImplementedError()

    def add_tag(self, tag, node):
        """
        Adds the specified tag to the specified node or system_id

        :returns: True if the Tag object was successfully assigned,
                  False otherwise.
        """
        raise NotImplementedError()
