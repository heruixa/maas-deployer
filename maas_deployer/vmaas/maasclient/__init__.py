'''
Created on May 14, 2015

@author: wolsen
'''
import logging

from maas_deployer.vmaas.maasclient.apidriver import APIDriver
from maas_deployer.vmaas.maasclient.clidriver import SSHDriver

log = logging.getLogger('vmaas.main')


class MAASException(Exception):
    pass


class MAASDriverException(Exception):
    pass


class MAASClient(object):
    """
    A wrapper for the python maas client which makes using the API a bit
    more user friendly.
    """

    def __init__(self, api_url, api_key, **kwargs):
        self.driver = self._get_driver(api_url, api_key, **kwargs)

    def _get_driver(self, api_url, api_key, **kwargs):
        if 'ssh_user' in kwargs:
            return SSHDriver(api_url, api_key, ssh_user=kwargs['ssh_user'])
        else:
            return APIDriver(api_url, api_key)

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
        resp = self.driver.get_config(name)
        if resp.ok:
            return resp.data
        return None

    def set_config(self, name, value):
        """
        Sets the MAAS Server config specified to the value specified.

        See http://maas.ubuntu.com/docs/api.html#maas-server for the set of
        available configuration parameters for the MAAS server.

        :param name: the name of the config ite mto set.
        :returns: True if the config parameter was updated successfully,
                  False otherwise.
        """
        resp = self.driver.set_config(name, value)
        if resp.ok:
            return True
        return False

    ###########################################################################
    # Boot Source API - http://maas.ubuntu.com/docs/api.html#boot-source
    ###########################################################################
    def delete_boot_source(self, id):
        """Delete boot source.

        :param id: numeric id of boot source to delete
        """
        resp = self.driver.delete_boot_source(id)
        if resp.ok:
            return True
        return False

    ###########################################################################
    # Boot Sources API - http://maas.ubuntu.com/docs/api.html#boot-sources
    ###########################################################################
    def get_boot_sources(self):
        """Get list of available boot sources."""
        resp = self.driver.get_boot_sources()
        if resp.ok:
            return resp.data
        return False

    def create_boot_source(self, url, keyring_data=None,
                           keyring_filename=None):
        """Add new boot source.

        :param url: the url of the bootsource
        :param keyring_data: The path to the keyring file for this BootSource.
        :param keyring_filename: The GPG keyring for this BootSource,
                                 base64-encoded.
        """
        resp = self.driver.create_boot_source(
                                            url,
                                            keyring_data=keyring_data,
                                            keyring_filename=keyring_filename)
        if resp.ok:
            return resp.data
        return False

    ###########################################################################
    # Boot Source Selections API - m.u.c/docs/api.html#boot-source-selections
    ###########################################################################
    def create_boot_source_selection(self, source_id, release, os, arches,
                                     subarches, labels):
        """
        Create a new boot source selection.

        :param source_id: numeric id
        :param release: e.g. trusty
        :param arches: e.g. amd64
        :param subarches: e.g. *
        :param os: e.g. ubuntu
        :param labels: e.g. release
        """
        resp = self.driver.create_boot_source_selection(source_id,
                                                        release=release, os=os,
                                                        arches=arches,
                                                        subarches=subarches,
                                                        labels=labels)
        if resp.ok:
            return resp.data
        return False

    def get_boot_source_selections(self, source_id):
        """
        Get boot source selections.

        :param source_id: numeric id
        """
        resp = self.driver.get_boot_source_selections(source_id)
        if resp.ok:
            return resp.data
        return False

    ###########################################################################
    # Boot Images API - http://maas.ubuntu.com/docs/api.html#boot-images
    ###########################################################################
    def get_boot_images(self, nodegroup):
        """
        Returns the boot images information for the specified nodegroup uuid.

        :param nodegroup: The nodegroup or uuid of the cluster for which the
                          images should be listed.
        """
        resp = self.driver.get_boot_images(nodegroup)
        if resp.ok:
            return resp.data
        return []

    def import_boot_images(self):
        """
        Initiates the importing of boot images.

        :rtype: bool indicating whether the start of the import was successful
        """
        return self.driver.import_boot_images()

    ###########################################################################
    # Nodegroup API - http://maas.ubuntu.com/docs/api.html#nodegroups
    ###########################################################################
    def update_nodegroup(self, nodegroup, **settings):
        """
        Update nodegroup.
        http://maas.ubuntu.com/docs/api.html#nodegroups
        """
        resp = self.driver.update_nodegroup(nodegroup, **settings)
        if resp.ok:
            return True
        return False

    def get_nodegroups(self):
        """
        Returns the nodegroups.
        http://maas.ubuntu.com/docs/api.html#nodegroups
        """
        resp = self.driver.get_nodegroups()
        if resp.ok:
            return [Nodegroup(n) for n in resp.data]
        return []

    def accept_nodegroup(self, nodegroup):
        """
        Accept nodegroup enlistment(s).

        :param: nodegroup the uuid of the nodegroup or a Nodegroup object
        """
        resp = self.driver.accept_nodegroup(nodegroup)
        if resp.ok:
            return True
        return False

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
        resp = self.driver.get_nodegroup_interfaces(nodegroup)
        if resp.ok:
            return [NodegroupInterface(n) for n in resp.data]
        return []

    def get_nodegroup_interface(self, nodegroup, iface):
        """
        Returns the specified NodeGroupInterface for the nodegroup
        or None if not found.

        :param nodegroup: the nodegroup
        :param iface: the name of the interface.
        :returns: a NodeInterface for the specified iface
        """
        resp = self.driver.get_nodegroup_interface(nodegroup, iface)
        if resp.ok:
            return NodegroupInterface(resp.data)
        return None

    def create_nodegroup_interface(self, nodegroup, iface):
        """
        Creates the NodegroupInterface in the nodegroup.

        :param nodegroup: uuid the uuid of the nodegroup
        :param iface: the interface for the node group
        """
        resp = self.driver.create_nodegroup_interface(nodegroup, iface)
        if resp.ok:
            return True
        return False

    def update_nodegroup_interface(self, nodegroup, iface):
        """
        Updates a nodegroup interface.
        """
        resp = self.driver.update_nodegroup_interface(nodegroup, iface)
        if resp.ok:
            return True
        return False

    ###########################################################################
    #  Node API - http://maas.ubuntu.com/docs/api.html#node
    ###########################################################################
    def get_node(self, system_id, **kwargs):
        """
        Read a specific node.

        :param system_id: the system id of the specified node
        """
        resp = self.driver.get_node(system_id, **kwargs)
        if resp.ok:
            return Node(resp.data)
        return None

    def get_nodes(self, **kwargs):
        """
        Retrieves the list of nodes from the MAAS Controller, optionally
        specifyinng a set of criteria for filtering the response data.
        The filtering is defined online @
          - http://maas.ubuntu.com/docs/api.html#nodes

        :returns a list of Nodes in the MAAS cluster
        """
        resp = self.driver.get_nodes(**kwargs)
        if resp.ok:
            return [Node(n) for n in resp.data]
        else:
            return []

    def accept_node(self, node):
        """
        Accepts the node into the nodegroup.
        Note: this implementation is somewhat naive and doesn't consider all
              possible return codes (400, 403, etc)

        :returns: True if the command was setuccessful (200),
                  False otherwise.
        """
        resp = self.driver.accept_node(node)
        if resp.ok:
            return True
        return False

    def accept_all_nodes(self):
        """
        Accepts all nodes into the node group.

        :returns: True if the command was successful (200),
                  False otherwise.
        """
        resp = self.driver.accept_all_nodes()
        if resp.ok:
            return True
        return False

    def create_node(self, node):
        """
        Creates the new Node. This create will autodetect the nodegroup.

        :params node: the node parameters
        :returns: a Node complete with the data requested/required.
        """
        resp = self.driver.create_node(node)
        if resp.ok:
            return Node(resp.data)
        return None

    def claim_sticky_ip_address(self, node, requested_address, mac_address):
        """
        Assign a 'sticky' IP Address to a Node's MAC.

        :param node: the node (or system-id) to assign the sticky ip address to
        :param requested_address: the ip address of the node
        :param mac_address: the mac address to assign the ip_addr to
        """
        resp = self.driver.claim_sticky_ip_address(node, requested_address,
                                                   mac_address)
        if resp.ok:
            return True
        return False

    ###########################################################################
    #  Tags API - http://maas.ubuntu.com/docs/api.html#tags
    ###########################################################################
    def get_tags(self):
        """
        Get a listing of the Tags which are currently defined.

        :returns: a list of Tag objects
        """
        resp = self.driver.get_tags()
        if resp.ok:
            return [Tag(t) for t in resp.data]
        return []

    def create_tag(self, tag):
        """
        Creates a new Tag in the MAAS server.

        :returns: True if the Tag object was created, False otherwise.
        """
        resp = self.driver.create_tag(tag)
        if resp.ok:
            return True
        return False

    def add_tag(self, tag, node):
        """
        Adds the specified tag to the specified node or system_id

        :returns: True if the Tag object was successfully assigned,
                  False otherwise.
        """
        resp = self.driver.add_tag(tag, node)
        if resp.ok:
            return True
        return False


class Node(dict):
    """
    Represents a Node
    """
    @property
    def status(self):
        return self['status']

    @property
    def mac_address_set(self):
        return self['mac_address_set']

    @property
    def cpu_count(self):
        return self['cpu_count']

    @property
    def zone(self):
        return self['zone']

    @property
    def routers(self):
        return self['routers']

    @property
    def netboot(self):
        return self['netboot']

    @property
    def osystem(self):
        return self['osystem']

    @property
    def storage(self):
        return self['storage']

    @property
    def substatus(self):
        return self['substatus']

    @property
    def hostname(self):
        return self['hostname']

    @property
    def owner(self):
        return self['owner']

    @property
    def ip_addresses(self):
        return self['ip_addresses']

    @property
    def system_id(self):
        return self['system_id']

    @property
    def architecture(self):
        return self['architecture']

    @property
    def power_state(self):
        return self['power_state']

    @property
    def memory(self):
        return self['memory']

    @property
    def power_type(self):
        return self['power_type']

    @property
    def tag_names(self):
        return self['tag_names']

    @property
    def disable_ipv4(self):
        return self['disable_ipv4']

    @property
    def distro_series(self):
        return self['distro_series']

    @property
    def resource_uri(self):
        return self['resource_uri']


class Nodegroup(dict):
    """
    Represents a nodegroup.
    """

    @property
    def name(self):
        return self['name']

    @property
    def cluster_name(self):
        return self['cluster_name']

    @property
    def status(self):
        return self['status']

    @property
    def uuid(self):
        return self['uuid']


class NodegroupInterface(dict):
    """
    Represents a nodegroup interface.
    """

    @property
    def name(self):
        return self['name']

    @property
    def ip_range_high(self):
        return self['ip_range_high']

    @property
    def ip_range_low(self):
        return self['ip_range_low']

    @property
    def static_ip_range_high(self):
        return self['static_ip_range_high']

    @property
    def static_ip_range_low(self):
        return self['static_ip_range_low']

    @property
    def ip(self):
        return self['ip']

    @property
    def subnet_mask(self):
        return self['subnet_mask']

    @property
    def management(self):
        return self['management']

    @property
    def interface(self):
        return self['interface']

    @property
    def router_ip(self):
        return self['router_ip']


class Tag(dict):
    """
    Represents a MAAS tag.
    """

    @property
    def name(self):
        return self['name']

    @property
    def comment(self):
        return self['comment']

    @property
    def definition(self):
        return self['definition']

    @property
    def kernel_opts(self):
        return self['kernel_opts']
