#!/usr/bin/env python
"""
MAAS Deployment Tool
"""
import logging
import os
import sys
import yaml


# Setup logging before imports
logging.basicConfig(
    filename='maas_deployer.log',
    level=logging.DEBUG,
    format=('%(asctime)s %(levelname)s '
            '(%(funcName)s) %(message)s'))

log = logging.getLogger('vmaas.main')
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
handler.setFormatter(formatter)
log.addHandler(handler)


from maas_deployer.vmaas.engine import DeploymentEngine
from maas_deployer.vmaas.util import CONF as cfg


def main():
    cfg.parser.add_argument('-c', '--config', type=str,
                            default='deployment.yaml', required=False)
    cfg.parser.add_argument('-d', '--debug', action='store_true',
                            default=False)
    cfg.parser.add_argument('--force', action='store_true', default=False,
                            help='Force cleanup of resources prior to '
                                 'creation e.g. if we want to create a new '
                                 'domain or volume and one already exists '
                                 'with the same name, it will be '
                                 'automatically deleted and re-created.')
    cfg.parser.add_argument('--use-existing', action='store_true',
                            default=False,
                            help='Re-using existing resources can be risky '
                                 'since they may contain unexpected/unwanted '
                                 'state. Setting this option to True will '
                                 'allow existing resources to be used '
                                 'otherwise an exception will be raised if '
                                 'any are found.')
    cfg.parser.add_argument('--remote', required=False,
                            default='qemu:///system',
                            help='Specify a remote virsh connection URL for '
                                 'communicating with the hypervisor. This '
                                 'parameter takes the same values as the '
                                 'virsh command does. For example, a remote '
                                 'qemu connection over ssh might be '
                                 'qemu+ssh://user@somehypervisor/system. The '
                                 'default value is the local system at '
                                 'qemu:///system')
    cfg.parser.add_argument('target', metavar='target', type=str, nargs='?',
                            help='Target environment to run')
    cfg.parse_args()

    # File logger is always DEBUG but stdout is default INFO.
    if cfg.debug:
        handler.setLevel(logging.DEBUG)
    else:
        handler.setLevel(logging.INFO)

    log.debug("Starting MAAS deployer")

    if not os.path.isfile(cfg.config):
        log.error("Unable to find config file %s", cfg.config)
        sys.exit(1)

    with open(cfg.config, 'r') as fd:
        config = yaml.safe_load(fd)

    target = cfg.target

    if target is None and len(config.keys()) == 1:
        target = config.keys()[0]

    if target not in config:
        log.error("Unable to find target: %s", target)
        sys.exit(2)

    try:
        engine = DeploymentEngine(config, target)
        engine.deploy(target)
    except:
        # Remove console handler to avoid displaying the exception twice
        log.removeHandler(handler)
        log.exception("MAAS deployment failed.")
        raise
    else:
        log.info("MAAS deployment completed.")


if __name__ == '__main__':
    main()
