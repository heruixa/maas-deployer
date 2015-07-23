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


from vmaas.engine import DeploymentEngine
from vmaas.util import CONF as cfg


if __name__ == '__main__':
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

    config = yaml.safe_load(file(cfg.config))
    target = cfg.target

    if target is None and len(config.keys()) == 1:
        target = config.keys()[0]

    if target not in config:
        log.error("Unable to find target: %s", target)
        sys.exit(2)

    engine = DeploymentEngine(config, target)
    engine.deploy(target)

    log.info("MAAS deployment completed.")
