#
# Created on May 11, 2015
#
# @author: Billy Olsen
#

import copy
import itertools
import json
import logging
import os
import sys
import time

from subprocess import CalledProcessError


from maas_deployer.vmaas import (
    vm,
    util,
    template,
)

from maas_deployer.vmaas.maasclient import (
    bootimages,
    MAASClient,
    Tag,
)


log = logging.getLogger('vmaas.main')
JUJU_ENV_YAML = 'environments.yaml'


class DeploymentEngine(object):

    def __init__(self, config, env_name):
        self.config = config
        self.env_name = env_name
        self.ip_addr = None
        self.api_key = None

    def deploy(self, target):
        """
        Deploys the configuration defined in the config map
        """
        config = self.config.get(target)
        juju_config = config.get('juju-bootstrap')
        juju_domain = self.deploy_juju_bootstrap(juju_config)
        maas_config = config.get('maas')

        # Insert juju node information into the maas nodes list.
        # This allows us to define it in maas.
        juju_node = self._get_juju_node_params(juju_domain, maas_config)

        nodes = maas_config.get('nodes', [])
        if not nodes:
            log.warning("No MAAS cluster nodes provided")
            maas_config['nodes'] = nodes

        nodes.append(juju_node)

        self.deploy_maas_node(maas_config)

        self.wait_for_maas_installation(maas_config)
        self.configure_maas_virsh_control(maas_config)
        self.api_key = self._get_api_key(maas_config)
        self.wait_for_import_boot_images(maas_config)

        self.configure_maas(maas_config)

    def _get_juju_node_params(self, juju_domain, maas_config):
        """
        Determines the mac address of the juju machine specified.

        :param juju_domain: the juju bootstrap image domain
        :param include_power: a boolean value of whether to include
                              power parameters or not for virsh power
                              control.
        """
        node = {
            'name': juju_domain.name,
            'architecture': 'amd64/generic',
            'mac_addresses': [x for x in juju_domain.mac_addresses],
            'tags': 'bootstrap'
        }

        virsh_info = maas_config.get('virsh')
        if virsh_info:
            uri = virsh_info.get('uri', util.CONF.remote)
            node.update({
                'power_type': 'virsh',
                'power_parameters_power_address': uri,
                'power_parameters_power_id': juju_domain.name,
            })

        return node

    def deploy_juju_bootstrap(self, params):
        """
        Deploys the juju bootstrap node.
        """
        log.debug("Creating Juju bootstrap node...")
        juju_node = vm.Instance(**params)
        juju_node.netboot = True
        juju_node.define()
        return juju_node

    def deploy_maas_node(self, params):
        """
        Deploys the virtual maas node.
        """
        log.debug("Creating MAAS Virtual Machine...")
        maas = vm.CloudInstance(**params)
        maas.create()
        return maas

    def get_ssh_cmd(self, user, host, ssh_opts=None, remote_cmd=None):
        cmd = ['ssh', '-i', os.path.expanduser('~/.ssh/id_maas'),
               '-o', 'UserKnownHostsFile=/dev/null',
               '-o', 'StrictHostKeyChecking=no']

        if ssh_opts:
            cmd += ssh_opts

        cmd += [('%s@%s' % (user, host))]

        if remote_cmd:
            cmd += remote_cmd

        return cmd

    def get_scp_cmd(self, user, host, src, dst=None, scp_opts=None):
        if not dst:
            dst = ''

        cmd = ['scp', '-i', os.path.expanduser('~/.ssh/id_maas'),
               '-o', 'UserKnownHostsFile=/dev/null',
               '-o', 'StrictHostKeyChecking=no']

        if scp_opts:
            cmd += scp_opts

        cmd += [src, ('%s@%s:%s' % (user, host, dst))]
        return cmd

    def wait_for_vm_ready(self, user, host):
        cmd = self.get_ssh_cmd(user, host, remote_cmd=['true'])
        while True:
            try:
                util.execc(cmd, suppress_stderr=True)
                log.debug("MAAS vm started.")
                break
            except CalledProcessError:
                log.debug("Waiting for MAAS vm to start.")
                time.sleep(1)
                continue

    def _get_api_key_from_cloudinit(self, user, addr):
        # Now get the api key
        rcmd = [r'grep "+ apikey=" %s| tail -n 1| sed -r "s/.+=(.+)/\1/"' %
                ('/var/log/cloud-init-output.log')]
        cmd = self.get_ssh_cmd(user, addr, remote_cmd=rcmd)
        stdout, _ = util.execc(cmd=cmd)
        self.api_key = stdout

    @util.retry_on_exception(exc_tuple=[CalledProcessError])
    def wait_for_cloudinit_finished(self, maas_config, maas_ip):
        log.debug("Logging into maas host '%s'", (maas_ip))
        # Now get the api key
        msg = "MAAS controller is now configured"
        cloudinitlog = '/var/log/cloud-init-output.log'
        rcmd = ['grep "%s" %s' %
                (msg, cloudinitlog)]
        cmd = self.get_ssh_cmd(maas_config['user'], maas_ip,
                               remote_cmd=rcmd)
        out, err = util.execc(cmd=cmd, fatal=False)
        if out and not err:
            self._get_api_key_from_cloudinit(maas_config['user'], maas_ip)
            return

        log.info("Waiting for cloud-init to complete - this usually takes "
                 "several minutes")
        rcmd = ['grep -m 1 "%s" <(sudo tail -n 1 -F %s)' %
                (msg, cloudinitlog)]
        cmd = self.get_ssh_cmd(maas_config['user'], maas_ip,
                               remote_cmd=rcmd)
        util.execc(cmd=cmd)
        self._get_api_key_from_cloudinit(maas_config['user'], maas_ip)

    def wait_for_maas_installation(self, maas_config):
        """
        Polls the ssh console to wait for the MAAS installation to
        complete.
        """
        log.debug("Waiting for MAAS vm to come up for ssh..")
        maas_ip = self._get_maas_ip_address(maas_config)

        self.ip_addr = maas_ip
        self.wait_for_vm_ready(maas_config['user'], maas_ip)
        self.wait_for_cloudinit_finished(maas_config, maas_ip)

    def _get_maas_ip_address(self, maas_config):
        """Attempts to get the IP address from the maas_config dict.

        If an IP address for contacting the node isn't specified, this will
        try and look in the network_config to get the address. If that cannot
        be found, then the user will be prompted for the IP address.

        :param maas_config: the config dict for maas parameters.
        """
        ip_address = maas_config.get('ip_address', None)
        if ip_address:
            log.debug("Using ip address specified: %s", ip_address)
            return ip_address

        log.info("ip_address was not specified in maas section of deployment"
                 " yaml file.")
        while not ip_address:
            ip_address = raw_input("Enter the IP address for "
                                   "the MAAS controller: ")
        log.debug("User entered IP address: %s", ip_address)
        maas_config['ip_address'] = ip_address
        return ip_address

    @util.retry_on_exception(exc_tuple=[CalledProcessError])
    def _get_api_key(self, maas_config):
        """Retrieves the API key"""
        if not self.api_key:
            log.debug("Fetching MAAS api key")
            user = maas_config['user']
            remote_cmd = ['sudo', 'maas-region-admin', 'apikey', '--username',
                          user]
            cmd = self.get_ssh_cmd(maas_config['user'], self.ip_addr,
                                   remote_cmd=remote_cmd)
            self.api_key, _ = util.execc(cmd)

        return self.api_key

    def configure_maas_virsh_control(self, maas_config):
        """Configure the virsh control SSH keys"""
        virsh_info = maas_config.get('virsh')
        if not virsh_info:
            log.debug('No virsh specified in maas_config.')
            return

        KEY_TO_FILE_MAP = {
            'rsa_priv_key': 'id_rsa',
            'rsa_pub_key': 'id_rsa.pub',
            'dsa_priv_key': 'id_dsa',
            'dsa_pub_key': 'id_dsa.pub',
        }

        # First, make the remote directory.
        remote_cmd = ['mkdir', 'virsh-keys']
        cmd = self.get_ssh_cmd(maas_config['user'], self.ip_addr,
                               remote_cmd=remote_cmd)
        util.execc(cmd)

        for key, value in virsh_info.iteritems():
            # not a key of interest
            if not key.endswith('_key'):
                continue

            try:
                dest_file = 'virsh-keys/%s' % KEY_TO_FILE_MAP[key]
                cmd = self.get_scp_cmd(maas_config['user'], self.ip_addr,
                                       os.path.expanduser(value), dest_file)
                util.execc(cmd)
            except:
                log.error("Error reading from %s file" % value)

        # Now move them over to the maas user.
        script = """
        maas_home=$(echo ~maas)
        sudo mkdir -p $maas_home/.ssh
        sudo mv ~/virsh-keys/* $maas_home/.ssh
        sudo chown -R maas:maas $maas_home/.ssh
        sudo chmod 700 $maas_home/.ssh
        sudo find $maas_home/.ssh -name id* | xargs sudo chmod 600
        rmdir ~/virsh-keys
        """
        util.exec_script_remote(maas_config['user'], self.ip_addr, script)

    def wait_for_import_boot_images(self, maas_config):
        """Polls the import boot image status."""
        log.debug("Importing boot images...")
        ip_addr = self.ip_addr or self._get_maas_ip_address(maas_config)
        user = maas_config['user']
        password = maas_config['password']
        checker = bootimages.ImageImportChecker(host=ip_addr,
                                                username=user,
                                                password=password)
        log.debug("Logging into %s", (ip_addr))
        checker.do_login()

        while not checker.did_downloads_start():
            log.debug("Waiting for downloads of boot images to start...")
            time.sleep(2)

        complete, status = checker.are_images_complete()
        while not complete:
            # Make sure to verify there are resources in the status query.
            # Its possible that the check comes in before MAAS determines
            # which resources it needs, etc
            if status.resources:
                status_str = status.resources[0].status
                sys.stdout.write(' Importing images ... %s ' % status_str)
                sys.stdout.flush()
                sys.stdout.write('\r')
            time.sleep(5)
            complete, status = checker.are_images_complete()

        log.debug("\r\nBoot image importing has completed.")

    @staticmethod
    def _get_node_tags(node):
        """Tags value is expected to be a comma-separated list of tag names"""
        tags = node.get('tags', '').split()
        # Sanitise
        return map(str.strip, tags)

    def _get_juju_nodename(self, nodes):
        """Get name of Juju bootstrap node"""
        for node in nodes:
            if 'bootstrap' in self._get_node_tags(node):
                return node['name']

        log.debug("No Juju bootstrap node description found with tag "
                  "'bootstrap'")
        return None

    def _create_maas_tags(self, client, nodes):
        log.debug("Creating tags...")
        tags = []
        for n in nodes:
            tags += self._get_node_tags(n)

        existing_tags = client.get_tags()
        to_create = set(tags) - set([t.name for t in existing_tags])
        for tag in to_create:
            client.create_tag(Tag({'name': tag}))

    def _add_tags_to_node(self, client, node, maas_node):
        for tag in self._get_node_tags(node):
            log.debug("Adding tag '%s' to node '%s'", tag, node['name'])
            # log.debug("Tagging node with tag %s", tag)
            if not client.add_tag(tag, maas_node):
                log.warning(">> Failed to tag node %s with %s",
                            node['name'], tag)

    def _create_maas_nodes(self, client, nodes):
        """Add nodes to MAAS cluster"""
        if not nodes:
            log.info("No cluster nodes provided")
            return

        self._create_maas_tags(client, nodes)

        log.debug("Adding nodes to deployment...")
        existing_nodes = client.get_nodes()

        for node in nodes:
            if 'power' in node:
                power_params = node['power']
                node['power_type'] = power_params['type']
                del node['power']

                node['power_parameters'] = \
                    self.get_power_parameters(power_params)

            # Note, the hostname returned by MAAS for the existing nodes
            # uses the hostname.domainname for the nodegroup (cluster).
            existing_maas_node = None
            for n in existing_nodes:
                if n.hostname.startswith("%s." % node['name']):
                    existing_maas_node = n
                    break

            if existing_maas_node:
                log.debug("Node %s is already in MAAS.", node['name'])
                maas_node = existing_maas_node
            else:
                log.debug("Adding node %s ...", node['name'])
                node['hostname'] = node['name']
                maas_node = client.create_node(node)

            if maas_node is None:
                log.warning(">> Failed to add node %s ", node['name'])
                continue

            self._add_tags_to_node(client, node, maas_node)

    def configure_maas(self, maas_config):
        """
        Configures the MAAS instance.
        """
        api_url = 'http://{}/MAAS/api/1.0'.format(self.ip_addr)

        client = MAASClient(api_url, self.api_key,
                            ssh_user=maas_config['user'])

        nodegroup = client.get_nodegroups()[0]

        log.debug("Configuring MAAS settings...")
        maas_settings = maas_config.get('settings', {})
        for key in maas_settings:
            value = maas_settings[key]
            succ = client.set_config(key, value)
            if not succ:
                log.error("Unable to set %s to %s", key, value)

        log.debug("Creating the nodegroup interfaces...")
        node_group_interfaces = copy.deepcopy(maas_config['node_group_ifaces'])
        for iface in node_group_interfaces:
            if not self.create_nodegroup_interface(client, nodegroup, iface):
                log.warning("Unable to create nodegroup interface: %s",
                            iface)

        nodes = maas_config.get('nodes', [])
        self._create_maas_nodes(client, nodes)

        self._render_environments_yaml()
        log.debug("Uploading Juju environments.yaml to MAAS vm")

        target = '.juju/'
        script = """
        sudo -u juju mkdir -p /home/juju/%s
        """ % (target)
        util.exec_script_remote(maas_config['user'], self.ip_addr, script)

        cmd = self.get_scp_cmd(maas_config['user'], self.ip_addr,
                               JUJU_ENV_YAML)
        util.execc(cmd)

        script = """
        chown juju: %s; sudo mv %s /home/juju/%s
        """ % (JUJU_ENV_YAML, JUJU_ENV_YAML,  target)
        util.exec_script_remote(maas_config['user'], self.ip_addr, script)

        if os.path.exists(util.USER_PRESEED_DIR) and \
           os.path.isdir(util.USER_PRESEED_DIR):
            log.debug('Copying over custom preseed files.')
            cmd = self.get_scp_cmd(maas_config['user'], self.ip_addr,
                                   util.USER_PRESEED_DIR, scp_opts=['-r'])
            util.execc(cmd)

            # Move them to the maas dir
            script = """
            chown maas:maas preseeds/*
            sudo mv preseeds/* /etc/maas/preseeds/
            rmdir preseeds
            """
            util.exec_script_remote(maas_config['user'], self.ip_addr, script)

        # Start juju domain
        virsh_info = maas_config.get('virsh')
        juju_node = self._get_juju_nodename(nodes)
        if juju_node is not None and not virsh_info:
            util.virsh(['start', juju_node])

        self._wait_for_nodes_to_commission(client)
        self._claim_sticky_ip_address(client, maas_config)
        log.debug("Done")

    def _render_environments_yaml(self):
        """
        Renders the Juju environments.yaml for use within the MAAS environment
        which was just setup.
        """
        log.debug("Rendering Juju %s", (JUJU_ENV_YAML))
        params = {
            'ip_addr': self.ip_addr,
            'api_key': self.api_key,
            'env_name': self.env_name,
        }
        content = template.load(JUJU_ENV_YAML, params)
        with open(JUJU_ENV_YAML, 'w+') as f:
            f.write(content)

    def _wait_for_nodes_to_commission(self, client):
        """
        Polls and waits for the nodes to be commissioned.
        """
        nodes = client.get_nodes()
        COMMISSIONING = 1
        READY = 4

        ready = []
        status = ' Waiting for node commissioning to complete '
        spinner = itertools.cycle(['|', '/', '-', '\\'])
        while True:
            sys.stdout.write(' %s %s ... %d/%d ' % (spinner.next(), status,
                                                    len(ready), len(nodes)))
            sys.stdout.flush()
            sys.stdout.write('\r')
            commissioning = [n for n in nodes if n.status == COMMISSIONING]
            ready = [n for n in nodes if n.status == READY]

            if len(commissioning) == 0:
                if len(ready) != len(nodes):
                    log.warning("Nodes are no longer commissioning but not "
                                "all nodes are ready.")
                    return
                sys.stdout.write('   %s ... Done\r\n' % status)
                sys.stdout.flush()
                return
            else:
                time.sleep(5)
                nodes = client.get_nodes()

    def _claim_sticky_ip_address(self, client, maas_config):
        """
        Claim sticky IP address
        """
        maas_nodes = client.get_nodes()
        nodes = maas_config.get('nodes', [])
        for maas_node in maas_nodes:
            hostname = maas_node['hostname']
            for node in nodes:
                if hostname.startswith("%s." % node['name']) and \
                   'sticky_ip_address' in node:

                    sticky_ip_addr = node['sticky_ip_address']
                    mac_address = sticky_ip_addr.get('mac_address', None)
                    requested_address = sticky_ip_addr.get('requested_address',
                                                           None)

                    # log.debug("Claiming sticky IP address %s",
                    #           requested_address)
                    fn = client.claim_sticky_ip_address
                    if not fn(maas_node, requested_address, mac_address):
                        log.warning(">> Failed to claim sticky ip address")

    def get_power_parameters(self, config_parms):
        """
        Converts the power parameters entry
        """
        power_parameters = {}
        for key in config_parms:
            if key.startswith('power_'):
                power_parameters[key] = config_parms[key]
            else:
                new_key = 'power_' + key
                power_parameters[new_key] = config_parms[key]

        return json.dumps(power_parameters)

    def create_nodegroup_interface(self, client, nodegroup, properties):
        """
        Creates a NodegroupInterface object from the dictionary of attributes
        passed in.
        """
        # Note: for compatibility with current revisions of the deployment.yaml
        # file we'll need to flatten the resulting dict from the yaml and then
        # remap some of the resulting keys to meet what the MAAS API is looking
        # for.
        properties = util.flatten(properties)
        name_map = {
            'static_range_high': 'static_ip_range_high',
            'static_range_low': 'static_ip_range_low',
            'dynamic_range_high': 'ip_range_high',
            'dynamic_range_low': 'ip_range_low',
            'device': 'interface'
        }

        for key in name_map:
            if key in properties:
                properties[name_map[key]] = properties[key]
                del properties[key]

        if not properties.get('name', None):
            properties['name'] = properties['interface']

        if not properties.get('management', None):
            properties['management'] = '2'  # Default to dhcp and dns

        existing_iface = client.get_nodegroup_interface(nodegroup,
                                                        properties['name'])

        if existing_iface:
            success = client.update_nodegroup_interface(nodegroup, properties)
        else:
            success = client.create_nodegroup_interface(nodegroup, properties)

        return success
