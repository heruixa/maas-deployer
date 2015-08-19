#!/bin/bash -eux
#
# This is a shell script which is used to configure MAAS and kick
# off the downloading of system images.
#

# Create the MAAS region admin
sudo maas-region-admin createadmin \
    --username={{user}} \
    --password={{password}} \
    --email={{user}}@localhost


# Configure the dns nameservers
echo "Configuring the DNS nameserver"
for dev in `ip link show | grep eth.*mtu | cut -d':' -f2`; do
  sudo resolvconf -d ${dev}.inet
done

sudo sed -i 's/dns-nameserver.*/dns-nameserver 127.0.0.1/g' /etc/network/interfaces


# Generate a MAAS API key for the admin user and start the importing of boot resources.
echo "Generating MAAS API login credentials for admin"
# Generate a MAAS API Key, then start the download of images.
apikey=$(sudo maas-region-admin apikey --username {{user}})
ipaddr=$(ip route get 8.8.8.8 | awk 'NR==1 {print $NF}')
maas login maas http://${ipaddr}/MAAS/api/1.0 ${apikey}


# Configure MAAS networks...
echo "Configuring MAAS node group interfaces (dns and dhcp configuration)..."
maas_ip=$(ip addr show eth0 | awk '/inet / {print $2}' | cut -d/ -f1)
maas_net=$(ip addr show eth0 | awk '/inet / {print $2}' | cut -d/ -f1 | cut -d. -f-3)


node_group_uuid=$(maas maas node-groups list | grep uuid | cut -d\" -f4)
attempts=0
while [[ "$node_group_uuid" == "master" ]] && [ $attempts -le 10 ]
do
    echo "Node group uuid is 'master', waiting to get a uuid"
    sleep 2
    node_group_uuid=$(maas maas node-groups list | grep uuid | cut -d\" -f4)
    attempts=$((attempts+1))
done

if [[ "$node_group_uuid" == "master" ]]
then
    echo "Unable to determine the node group uuid!"
    exit 1
fi

# Configuring MAAS to be a gateway node.
echo "Configuring MAAS as a gateway"
ext_dev=$(ip route get 8.8.8.8 | awk '{print $5}')
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.d/80-canonical.conf
sysctl -p /etc/sysctl.d/80-canonical.conf
iptables -t nat -A POSTROUTING -o $ext_dev -j MASQUERADE
sed -i -s "s/^exit 0/iptables -t nat -A POSTROUTING -o $ext_dev -j MASQUERADE\nexit 0/" /etc/rc.local


# Create a juju user
sudo adduser --disabled-password --gecos "Juju,,," juju


# Kick off the boot-resources import
echo "Starting the import of boot resources"
maas maas boot-resources import


