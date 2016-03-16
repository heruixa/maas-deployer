#
# Copyright 2015, Canonical Ltd
#

import copy
import json
import logging
import os
import urlparse

from subprocess import (
    CalledProcessError,
)

from maas_deployer.vmaas.util import (
    execc,
    flatten,
)
from maas_deployer.vmaas.maasclient.driver import MAASDriver
from maas_deployer.vmaas.maasclient.driver import Response

log = logging.getLogger('vmaas.main')


class CLIDriver(MAASDriver):
    """
    A MAAS driver implementation which uses the MAAS CLI.
    """

    def __init__(self, api_url, api_key, *args, **kwargs):
        if api_url.find('/api/') < 0:
            api_url = api_url + '/api/1.0'
        super(CLIDriver, self).__init__(api_url, api_key, *args, **kwargs)

    def _get_base_command(self):
        return ['maas', 'maas']

    @property
    def cmd_stdin(self):
        """String to be provided as stdin when executing commands.

        If nothing required, always return None.
        """
        return None

    def _maas_execute(self, cmd, *args, **kwargs):
        """
        Executes the specified subcommand. The keyword maas and the profile
        name will be prepended to the name
        """
        try:
            cmdarr = self._get_base_command()
            cmdarr.append(str(cmd))
            if args:
                for a in args:
                    cmdarr.append(str(a))
            if kwargs:
                for key in kwargs.keys():
                    value = kwargs[key]
                    if isinstance(value, list):
                        for v in value:
                            cmdarr.append("%s='%s'" % (key, str(v)))
                    else:
                        cmdarr.append("%s='%s'" % (key, str(value)))

            stdout = execc(cmdarr, stdin=self.cmd_stdin)[0]

            display_stdout = stdout
            if display_stdout and len(display_stdout) > 100:
                display_stdout = "%s..." % display_stdout[:100]

            log.debug("Command executed successfully: stdout='%s'",
                      display_stdout)

            try:
                output = json.loads(stdout)
            except ValueError:
                output = stdout

            return Response(True, output)
        except CalledProcessError as cpe:
            log.error("Command '%s' failed: rc='%s' output='%s'",
                      ' '.join(cmdarr), cpe.returncode, cpe.output)
            return Response(False, cpe.output)
        except OSError as ose:
            log.error("Command '%s' failed: error='%s'", ' '.join(cmdarr),
                      str(ose))
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
        return self._maas_execute('maas', 'get-config', name=name)

    def set_config(self, name, value):
        """
        Sets the MAAS Server config specified to the value specified.

        See http://maas.ubuntu.com/docs/api.html#maas-server for the set of
        available configuration parameters for the MAAS server.

        :param name: the name of the config ite mto set.
        :returns: True if the config parameter was updated successfully,
                  False otherwise.
        """
        return self._maas_execute('maas', 'set-config', name=name, value=value)

    ###########################################################################
    # Boot Source API - http://maas.ubuntu.com/docs/api.html#boot-source
    ###########################################################################
    def delete_boot_source(self, id):
        """Delete boot source.

        :param id: numeric id of boot source to delete
        """
        return self._maas_execute('boot-source', 'delete', id)

    ###########################################################################
    # Boot Sources API - http://maas.ubuntu.com/docs/api.html#boot-sources
    ###########################################################################
    def get_boot_sources(self):
        """Get list of available boot sources."""
        return self._maas_execute('boot-sources', 'read')

    def create_boot_source(self, url, keyring_data=None,
                           keyring_filename=None):
        """Add new boot source.

        :param url: the url of the bootsource
        :param keyring_data: The path to the keyring file for this BootSource.
        :param keyring_filename: The GPG keyring for this BootSource,
                                 base64-encoded.
        """
        kwargs = {'url': url}
        if keyring_data:
            kwargs['keyring_data@'] = keyring_data
        elif keyring_filename:
            kwargs['keyring_filename'] = keyring_filename

        return self._maas_execute('boot-sources', 'create', **kwargs)

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
        return self._maas_execute('boot-images', 'read', uuid)

    def import_boot_images(self):
        """
        Initiates the importing of boot images.

        :rtype: bool indicating whether the start of the import was successful
        """
        return self._maas_execute('boot-resources', 'import')

    ###########################################################################
    # Boot Source Selections API - m.u.c/docs/api.html#boot-source-selections
    ###########################################################################
    def create_boot_source_selection(self, source_id, release, os, arches,
                                     subarches, labels):
        """
        Create a new boot source selection.

        :param source_id: numeric id
        :param release: e.g. trusty
        :param os: e.g. ubuntu
        :param arches: e.g. amd64
        :param subarches: e.g. amd64
        :param labels: e.g. release
        """
        return self._maas_execute('boot-source-selections', 'create',
                                  source_id, release=release, os=os,
                                  arches=arches, subarches=subarches,
                                  labels=labels)

    def get_boot_source_selections(self, source_id):
        """
        Get boot source selections.

        :param source_id: numeric id
        """
        return self._maas_execute('boot-source-selections', 'read', source_id)

    ###########################################################################
    # Nodegroup API - http://maas.ubuntu.com/docs/api.html#nodegroups
    ###########################################################################
    def update_nodegroup(self, nodegroup, **settings):
        """
        Returns the nodegroups.
        http://maas.ubuntu.com/docs/api.html#nodegroups
        """
        return self._maas_execute('node-group', 'update', nodegroup.uuid,
                                  **settings)

    def get_nodegroups(self):
        """
        Returns the nodegroups.
        http://maas.ubuntu.com/docs/api.html#nodegroups
        """
        return self._maas_execute('node-groups', 'list')

    def accept_nodegroup(self, nodegroup):
        """
        Accept nodegroup enlistment(s).

        :param: nodegroup the uuid of the nodegroup or a Nodegroup object
        """
        uuid = self._get_uuid(nodegroup)
        return self._maas_execute('node-groups', 'accept', uuid=uuid)

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
        return self._maas_execute('node-group-interfaces', 'list', uuid)

    def get_nodegroup_interface(self, nodegroup, iface):
        """
        Returns the specified NodeGroupInterface for the nodegroup
        or None if not found.

        :param nodegroup: the nodegroup
        :param iface: the name of the interface.
        :returns: a NodeInterface for the specified iface
        """
        uuid = self._get_uuid(nodegroup)
        return self._maas_execute('node-group-interface', 'read', uuid,
                                  iface)

    def create_nodegroup_interface(self, nodegroup, iface):
        """
        Creates the NodegroupInterface in the nodegroup.

        :param nodegroup: uuid the uuid of the nodegroup
        :param iface: the interface for the node group
        """
        uuid = self._get_uuid(nodegroup)
        return self._maas_execute('node-group-interfaces', 'new', uuid,
                                  **iface)

    def update_nodegroup_interface(self, nodegroup, iface):
        """
        Updates a nodegroup interface.
        """
        name = iface['name']
        uuid = self._get_uuid(nodegroup)
        return self._maas_execute('node-group-interface', 'update', uuid, name,
                                  **iface)

    ###########################################################################
    #  Node API - http://maas.ubuntu.com/docs/api.html#node
    ###########################################################################
    def get_node(self, system_id, **kwargs):
        """
        Read a specific node.

        :param system_id: the system id of the specified node
        """
        system_id = self._get_system_id(system_id)
        return self._maas_execute('node', 'read', system_id)

    def get_nodes(self, **kwargs):
        """
        Retrieves the list of nodes from the MAAS Controller, optionally
        specifyinng a set of criteria for filtering the response data.
        The filtering is defined online @
          - http://maas.ubuntu.com/docs/api.html#nodes

        :returns a list of Nodes in the MAAS cluster
        """
        return self._maas_execute('nodes', 'list')

    def accept_node(self, node):
        """
        Accepts the node into the nodegroup.
        Note: this implementation is somewhat naive and doesn't consider all
              possible return codes (400, 403, etc)

        :returns: True if the command was successful (200),
                  False otherwise.
        """
        system_id = self._get_system_id(node)
        return self._maas_execute('nodes', 'accept', system_id=system_id)

    def accept_all_nodes(self):
        """
        Accepts all nodes into the node group.

        :returns: True if the command was successful (200),
                  False otherwise.
        """
        return self._maas_execute('nodes', 'accept-all')

    def create_node(self, node):
        """
        Creates the new Node. This create will autodetect the nodegroup.

        :params node: the node parameters
        :returns: a Node complete with the data requested/required.
        """
        node_copy = copy.deepcopy(node)
        # Need to convert the power_parameters and delete sticky_ip_addresses
        if 'sticky_ip_address' in node_copy:
            del node_copy['sticky_ip_address']
        if 'power_parameters' in node_copy:
            pparams = node_copy['power_parameters']
            if not isinstance(pparams, dict):
                pparams = json.loads(pparams)
            if 'power_type' in pparams:
                if 'power_type' not in node_copy:
                    node_copy['power_type'] = pparams['power_type']
                del pparams['power_type']
            morphed_params = flatten(pparams, parent_key='power_parameters')
            del node_copy['power_parameters']
            node_copy.update(morphed_params)

        return self._maas_execute('nodes', 'new', autodetect_nodegroup='yes',
                                  **node_copy)

    def claim_sticky_ip_address(self, node, requested_address, mac_address):
        """
        Assign a 'sticky' IP Address to a Node's MAC.

        :param node: the node (or system-id) to assign the sticky ip address to
        :param requested_address: the ip address of the node
        :param mac_address: the mac address to assign the ip_addr to
        """
        system_id = self._get_system_id(node)
        return self._maas_execute('node', 'claim-sticky-ip-address',
                                  system_id,
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
        return self._maas_execute('tags', 'list')

    def create_tag(self, tag):
        """
        Creates a new Tag in the MAAS server.

        :returns: True if the Tag object was created, False otherwise.
        """
        return self._maas_execute('tags', 'new', **tag)

    def add_tag(self, tag, node):
        """
        Adds the specified tag to the specified node or system_id

        :returns: True if the Tag object was successfully assigned,
                  False otherwise.
        """
        system_id = self._get_system_id(node)
        return self._maas_execute('tag', 'update-nodes', tag, add=system_id)


class SSHDriver(CLIDriver):
    """
    Wraps the CLI Driver in an ssh command for remote execution
    """
    def __init__(self, api_url, api_key, ssh_user='ubuntu'):
        self.ssh_user = ssh_user
        self.maas_ip = urlparse.urlparse(api_url)[1]
        if api_url.find('/api/') < 0:
            api_url = api_url + '/api/1.0'
        super(SSHDriver, self).__init__(api_url, api_key)
        self._login(api_url, api_key)

    @property
    def cmd_stdin(self):
        """Space-separated list of environment variables.

        If no env vars required, always return None.
        """
        return 'LC_ALL=C'

    def _login(self, api_url, api_key):
        cmd = ['ssh', '-i', os.path.expanduser('~/.ssh/id_maas'),
               '-o', 'UserKnownHostsFile=/dev/null',
               '-o', 'StrictHostKeyChecking=no',
               '-o', 'LogLevel=quiet',
               '{}@{}'.format(self.ssh_user, self.maas_ip),
               'maas', 'login', 'maas', api_url, api_key]
        execc(cmd, stdin=self.cmd_stdin)

    def _get_base_command(self):
        cmd = ['ssh', '-i', os.path.expanduser('~/.ssh/id_maas'),
               '-o', 'UserKnownHostsFile=/dev/null',
               '-o', 'StrictHostKeyChecking=no',
               '-o', 'LogLevel=quiet',
               '{}@{}'.format(self.ssh_user, self.maas_ip),
               'maas', 'maas']
        return cmd
