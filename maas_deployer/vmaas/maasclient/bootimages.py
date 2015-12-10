#!/usr/bin/env python
#
# Provides a polling infrastructure for querying the MAAS
# Web-API to provide boot image import status information.
#

import urllib
import httplib2
import json


def sequence_no(num):
    while True:
        yield num
        num = num + 1


class ImageImportChecker(object):
    """
    An object which can check the status of importing boot-images.
    """
    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        self.headers = {}
        self.http = httplib2.Http()
        self.sequence = sequence_no(1)

    @property
    def is_logged_in(self):
        return 'Cookie' in self.headers

    def do_login(self):
        # First, we have to get the login page in order to get
        # the csrf tokens.
        url = 'http://%(host)s/MAAS' % {'host': self.host}
        response, _ = self.http.request(url, 'GET')
        self.headers['Content-type'] = 'application/x-www-form-urlencoded'
        self.headers['Cookie'] = response['set-cookie']

        csrf_token = self.headers['Cookie'].split(';')[0].split('=')[1]
        body = {
            'username': self.username,
            'password': self.password,
            'next': '/MAAS/images',
            'csrfmiddlewaretoken': csrf_token
        }

        url = 'http://%(host)s/MAAS/accounts/login/' % {'host': self.host}
        response, _ = self.http.request(url, 'POST', headers=self.headers,
                                        body=urllib.urlencode(body))

        # Expect a 302 redirect
        if '302' == response['status']:
            self.headers['Cookie'] = response['set-cookie']
            del self.headers['Content-type']
        else:
            raise Exception("Unexpected response: %s" % response)

    def get_status(self):
        if not self.is_logged_in:
            self.do_login()

        url = ('http://%(host)s/MAAS/images/?sequence=%(sequence)d' %
               {'host': self.host, 'sequence': self.sequence.next()})
        self.headers['X-Requested-With'] = 'XMLHttpRequest'
        response, content = self.http.request(url, 'GET', headers=self.headers)

        if 'set-cookie' in response:
            self.headers['Cookie'] = response['set-cookie']

        if not response['status'] == '200':
            raise Exception("Unexpected response received: %s" % response)

        data = json.loads(content)
        return ImportStatus(data)

    def did_downloads_start(self):
        status = self.get_status()
        if status.cluster_import_running or status.region_import_running:
            return True

        completed = 0
        for resource in status.resources:
            if resource.downloading:
                return True
            if resource.complete:
                completed = completed + 1

        # If everything is complete...
        if completed == len(status.resources):
            return True

        # What other ways can we tell?
        return False

    def are_images_complete(self):
        status = self.get_status()
        cluster_import_running = status.cluster_import_running
        region_import_running = status.region_import_running

        if cluster_import_running is False and region_import_running is False:
            if len(status.resources) == 0:
                return (False, status)
            return (True, status)
        else:
            return (False, status)


class ImportStatus(dict):

    @property
    def cluster_import_running(self):
        return self['cluster_import_running']

    @property
    def region_import_running(self):
        return self['region_import_running']

    @property
    def resources(self):
        resource_data = self['resources']
        return [BootResourceStatus(data) for data in resource_data]


class BootResourceStatus(dict):

    @property
    def status(self):
        return self['status']

    @property
    def last_update(self):
        return self['lastUpdate']

    @property
    def downloading(self):
        return self.get('downloading', False)

    @property
    def complete(self):
        return self.get('complete', False)

    @property
    def title(self):
        return self['title']
