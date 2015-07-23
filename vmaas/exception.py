#
# Copyright Canonical 2015
#
# This module contains information regarding the virtual machines
# created for an automated MAAS deployment.
#


class MAASDeployerBaseException(Exception):
    pass


class MAASDeployerResourceAlreadyExists(MAASDeployerBaseException):
    def __init__(self, resource, resource_type=None):
        if not resource_type:
            msg = ("Resource '%s' already exists and use_existing=False" %
                   (resource))
        else:
            msg = ("Resource '%s' (type=%s) already exists. To "
                   "re-use resources set use_existing=False. To "
                   "autodelete resources set force=True" %
                   (resource, resource_type))

        super(MAASDeployerResourceAlreadyExists, self).__init__(msg)
