#
# Copyright 2015, Canonical
#

from jinja2 import Environment, PackageLoader

env = Environment()
env.loader = PackageLoader('maas_deployer.vmaas', 'templates')


def load(name, params):
    """
    Load a template from the vmaas.templates package
    :param name: template name
    :type name: string
    """
    return env.get_template(name).render(**params)
