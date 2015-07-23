#!/usr/bin/env python
#
# Copyright Canonical 2015
#
# This module contains information regarding the virtual machines
# created for an automated MAAS deployment.
#

import libvirt
import logging
import os
import os.path
import shutil
import tempfile
import time

from lxml import etree
from subprocess import CalledProcessError

import vmaas.template as template

from vmaas.exception import (
    MAASDeployerResourceAlreadyExists,
)
from vmaas.util import (
    execc,
    virsh,
    CONF as cfg,
    USER_DATA_DIR,
)


log = logging.getLogger('vmaas.main')
working_dir = tempfile.mkdtemp()


class Instance(object):

    def __init__(self, name, interfaces, arch='amd64', disk_size='20G',
                 vcpus=1, memory=1024, pool='default', netboot=False):
        self.name = name
        self.interfaces = interfaces
        self.arch = arch
        self.disk_size = disk_size
        self.vcpus = vcpus
        self.memory = memory
        self.pool = pool
        self.netboot = netboot
        self.conn = libvirt.open(cfg.remote)

    def _get_disk_param(self, image=None, pool=None, fmt='qcow2'):
        if pool is None:
            pool = self.pool

        if image is None:
            image = '{}.img'.format(self.name)

        tmplt = 'vol={pool}/{image},format={format},bus=virtio,io=native'
        return tmplt.format(pool=pool, image=image, format=fmt)

    def _get_network_params(self):
        return self.interfaces

    @property
    def _existing_vols(self):
        pool = self.conn.storagePoolLookupByName(self.pool)
        return [v.name() for v in pool.listAllVolumes()]

    def _get_disks(self):
        """
        Returns the disks which should be created/added to the instance
        upon creation.

        :return: an array of disk definitions to attach to the domain
                 which will be created via virt-install
        """
        size = self.disk_size
        if str(size).endswith('G'):
            size = size[:-1]

        # Domain name is used as name of vol here
        img_name = "%s.img" % (self.name)
        if img_name in self._existing_vols:
            log.debug("Base volume '%s' already exists", (img_name))
            if cfg.use_existing:
                log.debug("use_existing=True so skipping create and using "
                          "existing volume")
                return []
            elif cfg.force:
                log.info("Deleting volume '%s' before create since force=True",
                         img_name)
                virsh(['vol-delete', '--pool', self.pool, img_name])
            else:
                raise MAASDeployerResourceAlreadyExists(resource=img_name,
                                                        resource_type='volume')

        return [("size=%s,format=qcow2,bus=virtio,io=native,pool=%s" %
                 (size, self.pool))]

    def _generate_command(self):
        """
        Generates the virt-install command to use for creating the domain.

        :return: an array of command parameters which can be executed to
                 create the domain.
        """
        cmd = ['virt-install',
               '--connect', cfg.remote,
               '--name', self.name,
               '--ram', str(self.memory),
               '--vcpus', str(self.vcpus)]

        for disk in self._get_disks():
            cmd.extend(['--disk', disk])

        for network in self._get_network_params():
            cmd.extend(['--network', network])

        if self.netboot:
            cmd.extend(['--boot', 'network,hd,menu=off'])

        cmd.extend(['--noautoconsole', '--vnc'])
        return cmd

    def _domain_exists(self, name):
        log.debug("Checking if domain '%s' exists", (name))
        return name in virsh(['list', '--all'])[0]

    def _undefine_domain(self, name):
        log.debug("Undefining domain '%s'", (name))
        virsh(['destroy', name], fatal=False)
        max_retries = 5
        delay = 2
        retries = 0
        while True:
            try:
                virsh(['undefine', name])
                break
            except CalledProcessError:
                if retries > max_retries:
                    raise

                retries += 1
                time.sleep(delay)
                delay *= 2

    def create(self):
        """
        Creates the domain. A created domain will exist and be started
        automatically.
        """
        if self._domain_exists(self.name):
            log.debug("Domain '%s' already exists", (self.name))
            if cfg.use_existing:
                log.debug("use_existing=True so skipping create and using "
                          "existing domain")
                return
            elif cfg.force:
                log.info("Deleting domain '%s' before create since force=True",
                         self.name)
                self._undefine_domain(self.name)
            else:
                raise MAASDeployerResourceAlreadyExists(resource=self.name,
                                                        resource_type='domain')

        cmd = self._generate_command()
        cmd = ['sudo'] + cmd
        try:
            log.debug("Creating domain '%s'", (self.name))
            execc(cmd)
        except CalledProcessError:
            log.error("Failed to create vm - cleaning up")
            # Cleanup (non-fatal since instance may not have been created)
            virsh(['destroy', self.name], fatal=False)
            virsh(['undefine', self.name], fatal=False)
            raise

    def define(self):
        """
        Defines the domain within libvirt. A defined domain exists but is
        not started. This will define the domain by using virt-install to
        dump the contents of a domain which would be created into an XML file
        and then importing that into libvirt.
        """
        if self._domain_exists(self.name):
            log.debug("Domain '%s' already exists", (self.name))
            if cfg.use_existing:
                log.debug("use_existing=True so skipping define and using "
                          "existing domain")
                return
            elif cfg.force:
                log.info("Deleting domain '%s' before define since force=True",
                         self.name)
                self._undefine_domain(self.name)
            else:
                raise MAASDeployerResourceAlreadyExists(resource=self.name,
                                                        resource_type='domain')

        cmd = self._generate_command()
        # By default, virt-install will create the domain and start it for
        # installation. To only define the domain, the xml of the domain will
        # be dumped. Any disks which would be created by the virt-install cmd
        # will still be created during the command execution, but the domain
        # will not be created.
        cmd.extend(['--print-xml'])
        cmd = ['sudo'] + cmd
        xml_file = ('/tmp/%s.xml' % self.name)

        try:
            log.debug("Creating domain '%s'", (self.name))
            execc(cmd, pipedcmds=[['sudo', 'tee', xml_file]])

            # Now that the XML has been dumped, need to import it into libvirt
            # using the virsh define command.
            virsh(['define', '--file', xml_file])
        except CalledProcessError as e:
            log.error("Failed to define domain: %s", e.output)
            raise

    @property
    def mac_addresses(self):
        """
        Returns the set of mac_addresses that belong to the virtual domain.
        """
        domain_xml = ""
        try:
            domain_xml, _ = virsh(['dumpxml', self.name])
        except CalledProcessError as e:
            log.error(str(e))
            domain_xml = ""

        xml = etree.fromstring(domain_xml.strip())
        return [mac.get('address') for mac in
                xml.xpath("/domain/devices/interface/mac[@address]")]

    @property
    def ip_addresses(self):
        """
        Discovers the IP address of this particular KVM instance. It is
        heavily dependent upon an ARP request already being fulfilled by
        the instance itself (which is likely the case anyways).
        """
        try:
            subcmd = ['awk', '/%s/ {{ print $1 }}' % (self.mac_addresses[0])]
            out, _ = execc(['arp'], pipedcmds=[subcmd])
        except CalledProcessError:
            return []

        addresses = [a.strip() for a in out.split('\n') if a]
        log.debug("Instance has address(es): %s", (','.join(addresses)))

        return addresses


class CloudInstance(Instance):

    def __init__(self, name, interfaces, disk_size='40G', vcpus=2,
                 memory=4096, pool='default', user='ubuntu', password='ubuntu',
                 release='trusty', arch='amd64', **kwargs):
        super(CloudInstance, self).__init__(self, name, interfaces)
        self.name = name
        self.interfaces = interfaces
        self.disk_size = disk_size
        self.vcpus = vcpus
        self.memory = memory
        self.pool = pool
        self.release = release
        self.user = user
        self.password = password
        self.arch = arch

        if 'network_config' in kwargs:
            self.network_interfaces_content = kwargs['network_config']

        if 'node_group_ifaces' in kwargs:
            self.node_group_ifaces = kwargs['node_group_ifaces']

        self.apt_http_proxy = kwargs.get('apt_http_proxy')

    def _get_cloud_image_info(self):
        """
        Returns a tuple with the cloud-image url and the file it
        should be saved as.
        """
        url = ('https://cloud-images.ubuntu.com/{release}/current/'
               '{release}-server-cloudimg-{arch}-disk1.img')
        url = url.format(release=self.release, arch=self.arch)
        f = url.split('/')[-1]
        return (url, f)

    def _create_base_volume(self, name, existing_vols):
        if name in existing_vols:
            log.debug("Base volume '%s' already exists", (name))
            if cfg.use_existing:
                log.debug("use_existing=True so skipping create and using "
                          "existing volume")
                return
            elif cfg.force:
                log.info("Deleting volume '%s' before create since force=True",
                         name)
                virsh(['vol-delete', '--pool', self.pool, name])
            else:
                raise MAASDeployerResourceAlreadyExists(resource=name,
                                                        resource_type='volume')

        url, fname = self._get_cloud_image_info()
        if not os.path.isfile(fname):
            log.info("Downloading {url}".format(url=url))
            try:
                execc(['wget', '-O', fname, url])
            except:
                if os.path.exists(fname):
                    os.remove(fname)

                raise Exception("Failed to download '%s'" % (url))

        log.debug("Creating base volume '%s'", (name))
        virsh(['vol-create-as', '--pool', self.pool, name, '3G'])

        try:
            log.debug("Uploading image '%s' to volume", (fname))
            virsh(['vol-upload', '--pool', self.pool, '--file', fname,
                   '--vol', name])
        except Exception as e:
            log.error("Upload failed - cleaning up")
            virsh(['vol-delete', '--pool', self.pool, '--vol', name])
            raise Exception("Upload to vol '%s' failed - %s" % (name, e))

    def _create_root_volume(self, name, basevol, existing_vols, storage_pool):
        if name in existing_vols:
            log.debug("Root volume '%s' already exists", (name))
            if cfg.use_existing:
                log.debug("use_existing=True so skipping create and using "
                          "existing volume")
                return
            elif cfg.force:
                log.info("Deleting volume '%s' before create since force=True",
                         name)
                virsh(['vol-delete', '--pool', self.pool, name])
            else:
                raise MAASDeployerResourceAlreadyExists(resource=name,
                                                        resource_type='volume')

        log.debug("Cloning '%s' from base image '%s'", name, basevol)
        virsh(['vol-clone', '--pool', self.pool, basevol, name])

        storage_pool.refresh()
        log.debug("Resizing volume '%s' to %s", name, self.disk_size)
        virsh(['vol-resize', '--pool', self.pool, name, self.disk_size])

    def ensure_cloud_image(self):
        """
        Downloads the cloud image and installs it into the configured pool for
        use.
        """
        storage_pool = self.conn.storagePoolLookupByName(self.pool)
        existing_vols = [v.name() for v in storage_pool.listAllVolumes()]
        basevol = "%s-%s-base" % (self.release, self.arch)
        self._create_base_volume(basevol, existing_vols)
        root_img_name = '{}-root.img'.format(self.name)
        self._create_root_volume(root_img_name, basevol, existing_vols,
                                 storage_pool)
        storage_pool.refresh()
        # Display volume info
        info = virsh(['vol-info', '--pool', self.pool, root_img_name])[0]
        info = "\n%s" % info
        log.debug(info)
        return self._get_disk_param(image=root_img_name)

    def _generate_meta_data_file(self):
        """
        Generates the cloud-init meta-data file containing
        the networking parameters.
        """
        # Note, need this weird hack to preserve the spacing in the
        # template file otherwise the spacing is off and the data gets
        # dropped due to yaml formatting.
        if self.network_interfaces_content is None:
            raise Exception("Expected the content of the "
                            "/etc/network/interfaces file to be provided.")

        content = '\n  '.join(self.network_interfaces_content.split('\n'))
        params = {'network_config': content}
        path = os.path.join(working_dir, 'meta-data')
        with open(path, 'w+') as out:
            content = template.load('meta-data', params)
            out.write(content)
            out.flush()

        return path

    def _get_ssh_key(self):
        """
        Returns the ssh key to load into the maas env.
        """
        ssh_dir = os.path.join('~', '.ssh')
        ssh_dir = os.path.expanduser(ssh_dir)
        if not os.path.exists(ssh_dir):
            os.makedirs(ssh_dir, 0700)

        ssh_file = os.path.join(ssh_dir, 'id_maas')
        if not os.path.exists(ssh_file):
            execc(['ssh-keygen', '-t', 'rsa', '-N', '', '-f', ssh_file])

        public_key_file = "{}.pub".format(ssh_file)
        with open(public_key_file, 'r') as f:
            public_key = f.read()

        return public_key

    def _generate_user_data_file(self):
        """
        Generates the necessary user data files which are fed into
        the cloud-init configuration.
        """
        base_file = os.path.join(working_dir, 'cloud-init.cfg')
        parms = {
            'user': self.user,
            'password': self.password,
            'ssh_key': self._get_ssh_key(),
            'apt_http_proxy': self.apt_http_proxy
        }
        content = template.load('cloud-init.cfg', parms)
        with open(base_file, 'w+') as f:
            f.write(content)
            f.flush()

        # Generate the script file...
        config_maas_script = os.path.join(working_dir, 'config-maas.sh')
        parms = {
            'user': self.user,
            'password': self.password,
            'node_group_ifaces': self.node_group_ifaces,
        }
        content = template.load('config-maas.sh', parms)
        with open(config_maas_script, 'w+') as f:
            f.write(content)
            f.flush()

        user_data_file = os.path.join(working_dir, 'user-data.txt')
        cmd = ['write-mime-multipart', '--output={}'.format(user_data_file),
               base_file, '{}:text/x-shellscript'.format(config_maas_script)]

        cmd = cmd + self._get_user_supplied_files()
        log.debug('Generating mime-multipart user data file using: %s',
                  str(cmd))
        execc(cmd)

        return user_data_file

    def _get_user_supplied_files(self):
        """
        Returns a list of the user supplied files to include in the cloud-init
        user-data file.
        """
        user_files = []

        if os.path.exists(USER_DATA_DIR) and \
           os.path.isdir(USER_DATA_DIR):
            try:
                for f in os.listdir(USER_DATA_DIR):
                    src = os.path.join(USER_DATA_DIR, f)
                    # Do not include directories
                    if os.path.isdir(src):
                        continue
                    dest = os.path.join(working_dir, 'user_data_%s' % f)
                    shutil.copy(src, dest)
                    user_files.append(dest)
            except OSError as e:
                log.error('Error copying user file: %s', str(e))
                raise e

        return user_files

    def create_seed_image(self):
        """
        Creates the seed image fed into the cloud-init bootstrap.
        """
        log.debug("Creating cloud-init seed image for MAAS...")
        storage_pool = self.conn.storagePoolLookupByName(self.pool)
        disk_parm = self._get_disk_param(image='{}-seed.img'.format(self.name),
                                         pool='default', fmt='raw')

        seed_name = '%s-seed.img' % self.name
        existing_vols = [v.name() for v in storage_pool.listAllVolumes()]
        if seed_name in existing_vols:
            log.info("Seed volume '%s' already exists", (seed_name))
            if not cfg.force:
                log.warning("Skipping create since force=False")
                return disk_parm
            else:
                log.info("Deleting volume '%s' before create since force=True",
                         seed_name)
                virsh(['vol-delete', '--pool', self.pool, seed_name])

        # Generate meta-data
        meta_data_file = self._generate_meta_data_file()

        # Generate user-data files.
        user_data_file = self._generate_user_data_file()

        log.debug('Creating local seed file')
        img_path = os.path.join(working_dir, seed_name)
        execc(['cloud-localds', img_path, user_data_file,
               meta_data_file])

        stat = os.stat(img_path)

        log.debug('Creating volume')
        # Now create the volume locally and then upload the volume
        virsh(['vol-create-as',
               '--pool', self.pool,
               '--name', seed_name,
               '--capacity', str(stat.st_size),
               '--format', 'raw'])

        storage_pool.refresh()

        log.debug('Uploading seed %s to volume...', img_path)
        virsh(['vol-upload', '--pool', self.pool, '--file', img_path,
               '--vol', seed_name])

        storage_pool.refresh()
        return disk_parm

    def _get_disks(self):
        """
        Returns the disks used for cloud image booting.
        """
        root_img = self.ensure_cloud_image()
        seed_img = self.create_seed_image()
        return [root_img, seed_img]

    def create(self):
        if self._domain_exists(self.name):
            log.debug("Domain '%s' already exists", (self.name))
            if cfg.use_existing:
                log.debug("use_existing=True so skipping create and using "
                          "existing domain")
                return
            elif cfg.force:
                log.info("Deleting domain '%s' before create since force=True",
                         self.name)
                self._undefine_domain(self.name)
            else:
                raise MAASDeployerResourceAlreadyExists(resource=self.name,
                                                        resource_type='domain')

        cmd = self._generate_command()
        cmd = ['sudo'] + cmd
        cmd.extend(['--import'])
        try:
            log.debug("Creating domain '%s'", (self.name))
            execc(cmd)
        except CalledProcessError:
            log.error("Failed to create vm - cleaning up")
            # Cleanup (non-fatal since instance may not have been created)
            virsh(['destroy', self.name], fatal=False)
            virsh(['undefine', self.name], fatal=False)
            raise
