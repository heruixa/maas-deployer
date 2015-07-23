#!/bin/bash
DEPS=(
    cloud-image-utils
    kvm
    python-bson
    python-httplib2
    python-jinja2
    python-libvirt
    python-lxml
    python-maas-client
    python-yaml
    virtinst
)

sudo apt-get install -y ${DEPS[@]}

