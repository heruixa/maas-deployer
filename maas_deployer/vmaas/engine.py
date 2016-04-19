#
# Created on May 11, 2015
#
# @author: Billy Olsen
#

import base64
import copy
import itertools
import json
import logging
import os
import sys
import tempfile
import time
import uuid

from subprocess import CalledProcessError

from maas_deployer.vmaas import (
    vm,
    util,
    template,
)
from maas_deployer.vmaas.exception import (
    MAASDeployerClientError,
    MAASDeployerConfigError,
    MAASDeployerValueError,
)
from maas_deployer.vmaas.maasclient import (
    bootimages,
    MAASClient,
    Tag,
)
from maas_deployer.vmaas.maasclient.driver import Response


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
        maas_config = config.get('maas')
        nodes = maas_config.get('nodes', [])
        if not nodes:
            log.warning("No MAAS cluster nodes configured")
            maas_config['nodes'] = nodes

        juju_node = self.deploy_juju_bootstrap(config.get('juju-bootstrap'),
                                               maas_config)
        nodes.append(juju_node)

        # create extra VMs
        for node in config.get('virtual-nodes', {}):
            n = self.deploy_virtual_node(node, maas_config)
            nodes.append(n)

        self.deploy_maas_node(maas_config)

        self.wait_for_maas_installation(maas_config)
        self.configure_maas_virsh_control(maas_config)
        self.api_key = self._get_api_key(maas_config)

        api_url = 'http://{}/MAAS/api/1.0'.format(self.ip_addr)
        client = MAASClient(api_url, self.api_key,
                            ssh_user=maas_config['user'])

        self.apply_maas_settings(client, maas_config)
        self.configure_boot_source(client, maas_config)
        self.wait_for_import_boot_images(client, maas_config)
        self.configure_maas(client, maas_config)

    def _get_node_params(self, node_domain, node_config, maas_config,
                         tags=None):
        """
        Determines the mac address of the node machine specified.

        :param node_domain: the juju bootstrap image domain
        :param include_power: a boolean value of whether to include
                              power parameters or not for virsh power
                              control.
        """
        node = {
            'name': node_domain.name,
            'architecture': 'amd64/generic',
            'mac_addresses': [x for x in node_domain.mac_addresses],
            'tags': tags if tags else node_config['tags'],
        }

        virsh_info = maas_config.get('virsh')
        if virsh_info:
            uri = virsh_info.get('uri', util.CONF.remote)
            node.update({
                'power_type': 'virsh',
                'power_parameters_power_address': uri,
                'power_parameters_power_id': node_domain.name,
            })

        sticky_cfg = node_config.get('sticky_ip_address')
        if sticky_cfg:
            node['sticky_ip_address'] = sticky_cfg
            node['sticky_ip_address']['mac_address'] = node['mac_addresses'][0]

        return node

    def deploy_juju_bootstrap(self, params, maas_config):
        """Deploy the juju bootstrap node.

        Returns Juju node params from YAML config.
        """
        log.debug("Creating Juju bootstrap vm.")
        with vm.Instance(params) as juju_node:
            juju_node.netboot = True
            juju_node.define()
            # Insert juju node information into the maas nodes list.
            # This allows us to define it in maas.
            return self._get_node_params(juju_node, params, maas_config,
                                         tags='bootstrap')

    def deploy_virtual_node(self, params, maas_config):
        log.debug('Creating VM: %s' % params['name'])
        with vm.Instance(params) as node:
            node.netboot = True
            node.define()

            return self._get_node_params(node, params, maas_config)

    def deploy_maas_node(self, params):
        """
        Deploys the virtual maas node.
        """
        log.debug("Creating MAAS virtual machine.")
        with vm.CloudInstance(params, autostart=True) as maas_node:
            maas_node.create()

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
        if stdout:
            stdout = stdout.strip()

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
        log.info("done.")
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

        if self.api_key:
            self.api_key = self.api_key.strip()

        return self.api_key

    def configure_maas_virsh_control(self, maas_config):
        """Configure the virsh control SSH keys"""
        virsh_info = maas_config.get('virsh')
        if not virsh_info:
            log.debug('No virsh settings specified in maas_config.')
            return

        KEY_TO_FILE_MAP = {
            'rsa_priv_key': 'id_rsa',
            'rsa_pub_key': 'id_rsa.pub',
            'dsa_priv_key': 'id_dsa',
            'dsa_pub_key': 'id_dsa.pub',
        }

        # First, make the remote directory.
        remote_cmd = ['mkdir', '-p', 'virsh-keys']
        cmd = self.get_ssh_cmd(maas_config['user'], self.ip_addr,
                               remote_cmd=remote_cmd)
        util.execc(cmd)

        for key, value in virsh_info.iteritems():
            # not a key of interest
            if not key.endswith('_key'):
                continue

            src = os.path.expanduser(value)
            if not os.path.isfile(src):
                raise MAASDeployerValueError("Virsh SSH key '%s' not found"
                                             % (src))

            dst = 'virsh-keys/%s' % KEY_TO_FILE_MAP[key]
            cmd = self.get_scp_cmd(maas_config['user'], self.ip_addr, src, dst)
            util.execc(cmd)

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

    def _delete_existing_bootsources(self, client, sources, exclude=None):
        log.debug("Deleting exisiting boot sources")
        for source in sources:
            if exclude and source['id'] == exclude:
                log.debug("Skipping delete source id %s", (exclude))
                continue

            client.delete_boot_source(source['id'])

    def _create_new_boot_source(self, client, maas_config, url, keyring_data,
                                keyring_filename):
        log.debug("Creating new boot source url='%s'",  (url))
        # If we want to supply new keyring data we have to write it to
        # a file, upload it and reference that from the cli.
        if keyring_data:
            ssh_user = maas_config['user']
            remote_host = self.ip_addr
            with tempfile.NamedTemporaryFile() as ftmp:
                with open(ftmp.name, 'w') as fd:
                    fd.write(base64.b64decode(keyring_data))

                filepath = "/tmp/maas-deployer-archive-keyring.gpg"
                util.execc(self.get_scp_cmd(ssh_user, remote_host, ftmp.name,
                                            filepath))

                target = (keyring_filename or "/usr/share/keyrings/%s" %
                          (os.path.basename(filepath)))
                log.debug("Writing boot source key '%s'",  (target))
                cmd = ['sudo', 'mv', filepath, target]
                util.execc(self.get_ssh_cmd(ssh_user, remote_host,
                                            remote_cmd=cmd))
                cmd = ['sudo', 'chmod', '0644', target]
                util.execc(self.get_ssh_cmd(ssh_user, remote_host,
                                            remote_cmd=cmd))
                cmd = ['sudo', 'chown', 'root:', target]
                util.execc(self.get_ssh_cmd(ssh_user, remote_host,
                                            remote_cmd=cmd))

                keyring_filename = target

        ret = client.create_boot_source(url, keyring_filename=keyring_filename)
        if not ret:
            msg = "Failed to create boot resource url='%s'" % (url)
            log.error(msg)
            raise MAASDeployerClientError(msg)

    def configure_boot_source(self, client, maas_config):
        """Create a new boot source if one has been provided and setup boot
        source selections as provided.

        NOTE: see bug 1556085 and bug 1391254 for known caveats when
              configuring boot sources.
        """
        newsource = maas_config.get('boot_source')
        if newsource:
            log.debug("Configuring boot source '%s'",  (newsource['url']))
            sources = client.get_boot_sources()
            url = newsource['url']

            create = True
            sources_deleted = False
            existing_id = None
            existing_ids = [s['id'] for s in sources if s['url'] == url]
            if existing_ids:
                if not newsource.get('force'):
                    existing_id = existing_ids[0]
                    log.debug("Source with url='%s' already exists (id=%s) - "
                              "skipping create" % (url, existing_id))
                    create = False
                else:
                    if newsource.get('exclusive'):
                        self._delete_existing_bootsources(client, sources)
                        sources_deleted = True

            if create:
                self._create_new_boot_source(client, maas_config,
                                             newsource['url'],
                                             newsource.get('keyring_data'),
                                             newsource.get('keyring_filename'))

            if not sources_deleted:
                if newsource.get('exclusive'):
                    self._delete_existing_bootsources(client, sources)

            selections = newsource.get('selections')
            sources = client.get_boot_sources()
            if not selections:
                log.info("No boot source selections requested")
                return

            log.debug("Creating source selection(s)")
            for i, s in enumerate(selections):
                selection = selections[s]
                source = \
                    [src for src in sources if src['url'] == url]
                if len(source) > 1:
                    log.warning("Found more than one boot source with "
                                "url='%s'",  (url))

                # NOTE: __ALL__ of these are required to create a selection
                source_id = source[0]['id']
                release = selection['release']
                os = selection['os']
                labels = selection['labels']
                arches = selection['arches']
                subarches = selection['subarches']

                existing = client.get_boot_source_selections(source_id)
                existing = [e for e in existing
                            if e['release'] == release and e['os'] == os]
                if existing:
                    log.debug("Selection with release='%s' os='%s' "
                              "already exists on boot source='%s' - "
                              "skipping" %
                              (release, os, source_id))
                    continue

                ret = client.create_boot_source_selection(source_id,
                                                          release, os,
                                                          arches,
                                                          subarches,
                                                          labels)
                if not ret:
                    msg = "Failed to create boot source selection %d" % (i)
                    log.error(msg)
                    raise MAASDeployerClientError(msg)

    def wait_for_import_boot_images(self, client, maas_config):
        """Polls the import boot image status."""
        log.debug("Starting the import of boot resources")
        client.import_boot_images()

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
                power_settings = node.pop('power')

                # NOTE: See LP 1492163 for info on why we do this
                if power_settings.get('type') == 'virsh':
                    if power_settings.get('id') is None:
                        power_settings['id'] = node['name']

                node['power_parameters'] = \
                    self.get_power_parameters_encoded(power_settings)

                node['power_type'] = power_settings['type']

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

    def apply_maas_settings(self, client, maas_config):
        log.debug("Configuring MAAS settings...")
        maas_settings = maas_config.get('settings', {})
        for key in maas_settings:
            value = maas_settings[key]
            succ = client.set_config(key, value)
            if not succ:
                log.error("Unable to set %s to %s", key, value)

    def update_nodegroup(self, client, nodegroup, maas_config):
        """Update node group settings."""
        node_group_config = maas_config.get('node_group')
        if not node_group_config:
            log.debug("Did not find any node group settings in config")
            return

        supported_keys = ['name', 'cluster_name']
        if not set(node_group_config.keys()).issubset(supported_keys):
            msg = ("node_group config contains unsupported settings: %s" %
                   node_group_config.keys())
            raise MAASDeployerConfigError(msg)

        client.update_nodegroup(nodegroup, **node_group_config)

    def get_nodegroup(self, client, maas_config):
        """Get node group.

        We will get node group corresponding to uuid from config. If uuid not
        provided we will pick the first from the list returned by MAAS.
        """
        cfg_uuid = None
        node_group_config = maas_config.get('node_group')
        if not node_group_config:
            log.info("Node group config not provided")
        else:
            cfg_uuid = node_group_config.get('uuid')

        if cfg_uuid:
            log.debug("Using node group uuid '%s'", (cfg_uuid))
        else:
            log.debug("Node group uuid not provided in config")

        max_retries = 5
        while True:
            nodegroups = client.get_nodegroups()
            for nodegroup in nodegroups:
                # NOTE: see MAAS bug 1519810 for an explanation of why we do
                #       this.
                try:
                    uuid.UUID(nodegroup['uuid'])
                except ValueError:
                    # This would indicate that the cluster controller has
                    # failed to autodetect interfaces and thus cannot connect
                    # to the region controller. We will proceed since it is not
                    # likely to get solved until we manually add an interface.
                    if not max_retries:
                        log.debug("Using cluster controller '%s' despite not "
                                  "being fully initialised",
                                  (nodegroup['uuid']))
                        return nodegroup

                    max_retries -= 1
                    log.warning("Re-querying nodegroup list since one or more "
                                "nodegroups does not have a valid uuid")
                    time.sleep(2)
                    break

                if not cfg_uuid:
                    return nodegroup

                if nodegroup['uuid'] == cfg_uuid:
                    return nodegroup
            else:
                break

        raise MAASDeployerValueError("Could not find nodegroup with uuid "
                                     "'%s'" % (cfg_uuid))

    def configure_maas(self, client, maas_config):
        """Configures the MAAS instance."""
        nodegroup = self.get_nodegroup(client, maas_config)
        self.update_nodegroup(client, nodegroup, maas_config)
        self.create_nodegroup_interfaces(client, nodegroup, maas_config)

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
        for n in nodes:
            name = n['name']
            try:
                log.info('Starting: %s' % name)
                util.virsh(['start', name])
            except CalledProcessError as exc:
                # Ignore already started error
                msg = 'Domain is already active'
                if msg not in exc.output:
                    raise

                log.debug(msg)

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
        config_nodes = maas_config.get('nodes', [])
        sticky_nodes = {}
        for m_node in maas_nodes:
            hostname = m_node['hostname']
            for c_node in config_nodes:
                sticky_addr_cfg = c_node.get('sticky_ip_address')
                if (hostname.startswith("%s." % c_node['name']) and
                        sticky_addr_cfg):
                    ip_addr = sticky_addr_cfg.get('requested_address')
                    mac_addr = sticky_addr_cfg.get('mac_address')
                    if ip_addr and mac_addr:
                        sticky_nodes[ip_addr] = {'mac_addr': mac_addr,
                                                 'maas_node': m_node}

        for ip_addr, cfg in sticky_nodes.iteritems():
            node = cfg['maas_node']
            log.debug("Claiming sticky IP address '%s' for node '%s'",
                      ip_addr, node['hostname'])
            rc = client.claim_sticky_ip_address(node, ip_addr,
                                                cfg['mac_addr'])
            if not rc:
                log.warning("Failed to claim sticky ip address '%s'", ip_addr)

    def get_power_parameters_encoded(self, config_parms):
        """
        Converts the power parameters entry
        """
        power_parameters = {}
        # See https://maas.ubuntu.com/docs/api.html#power-types
        unprefixed_keys = ['mac_address', 'system_id', 'outlet_id', 'uuid',
                           'node_id', 'blade_id', 'node_outlet', 'server_name',
                           'lpar']
        for key in config_parms:
            if key in unprefixed_keys:
                power_parameters[key] = config_parms[key]
            else:
                # NOTE(dosaboy): this only works if we make sure we support all
                # keys that don't start with 'power_' above.
                log.debug("Prepending 'power_' to power key '%s'", (key))
                new_key = 'power_' + key
                power_parameters[new_key] = config_parms[key]

        return json.dumps(power_parameters)

    def create_nodegroup_interface(self, client, nodegroup, properties):
        """Add/update node group interface."""
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

        if not properties.get('name'):
            properties['name'] = properties['interface']

        log.debug("Creating interface '%s' in node group '%s'",
                  properties['name'], nodegroup.name)

        if not properties.get('management'):
            properties['management'] = '2'  # Default to dhcp and dns

        existing_iface = client.get_nodegroup_interface(nodegroup,
                                                        properties['name'])

        if existing_iface:
            success = client.update_nodegroup_interface(nodegroup, properties)
        else:
            success = client.create_nodegroup_interface(nodegroup, properties)

        # See LP #1519810 for explanation.
        if nodegroup.uuid == 'master':
            # Wait for controller to be connected
            time.sleep(5)
            return Response(True, "")

        return success

    def create_nodegroup_interfaces(self, client, nodegroup, maas_config):
        """
        Creates a NodegroupInterface object from the dictionary of attributes
        passed in.
        """
        log.debug("Creating node group '%s' interfaces", (nodegroup.name))
        node_group_interfaces = copy.deepcopy(maas_config['node_group_ifaces'])
        for iface in node_group_interfaces:
            if not self.create_nodegroup_interface(client, nodegroup, iface):
                msg = "Unable to create nodegroup interface: %s" % iface
                raise MAASDeployerClientError(msg)
