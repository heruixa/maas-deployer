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
                   "re-use resources set use_existing=True. To "
                   "autodelete resources set force=True" %
                   (resource, resource_type))

        super(MAASDeployerResourceAlreadyExists, self).__init__(msg)


class MAASDeployerPoolNotFound(MAASDeployerBaseException):
    def __init__(self, pool):
        msg = ("Pool '%s' not found. Please ensure this pool exists prior to "
               "running the deployer" % (pool))

        super(MAASDeployerPoolNotFound, self).__init__(msg)


class MAASDeployerClientError(MAASDeployerBaseException):
    def __init__(self, msg):
        super(MAASDeployerClientError, self).__init__(msg)


class MAASDeployerConfigError(MAASDeployerBaseException):
    def __init__(self, msg):
        super(MAASDeployerConfigError, self).__init__(msg)


class MAASDeployerValueError(MAASDeployerBaseException):
    def __init__(self, msg):
        super(MAASDeployerValueError, self).__init__(msg)
