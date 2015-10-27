#!/bin/bash -eux
#
# TODO: this is legacy and should be migrated to python code.
#

# Create the MAAS region admin
sudo maas-region-admin createadmin \
    --username={{user}} \
    --password={{password}} \
    --email={{user}}@localhost

sudo sed -i 's/dns-nameserver.*/dns-nameserver 127.0.0.1/g' /etc/network/interfaces
# NOTE: we should cleanup /etc/resolv.conf once MAAS DNS has been configured.

# Configuring MAAS to be a gateway node.
echo "Configuring MAAS as a gateway"
ext_dev=$(ip route get 8.8.8.8 | awk '{print $5}')
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.d/80-canonical.conf
sysctl -p /etc/sysctl.d/80-canonical.conf
iptables -t nat -A POSTROUTING -o $ext_dev -j MASQUERADE
sed -i -s "s/^exit 0/iptables -t nat -A POSTROUTING -o $ext_dev -j MASQUERADE\nexit 0/" /etc/rc.local

