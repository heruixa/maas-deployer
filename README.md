# MAAS Deployer

MAAS deployer provides the ability to automate the deployment of MAAS clusters
for use as a Juju provider. Using a set of configuration files and simple
commands this tool will build a MAAS cluster using virtual machines for the
region controller and bootstrap hosts and automatically commission nodes as
required so that the only next step required is to deploy services with Juju.

# Installation and Usage

A basic workflow starts by writing a YAML file describing the MAAS cluster you
want to create. The examples directory contains a sample YAML that can be used
as starting point. There are many supported options such as network
configuration, node tagging, proxies etc.

To install maas-deployer please do the following:

  sudo add-apt-repository ppa:maas-deployers/stable
  sudo apt-get update
  sudo apt-get install maas-deployer

Once you have create a yaml description of your deployment do:

  maas-deployer -c deployment.yaml --debug

Once this has completed, you should end up with two virtual machines, one for
the Juju bootstrap host and one for the MAAS controller whose web interface
should be available at http://<maas-host>/MAAS.

By default maas-deployer will check if any resources it wants to create already
exist and fail if they do. You can optionally reuse existing resources to make
runs idempotent by using the --use-existing flag or force delete resource
before creating them using the --force flag e.g.

  maas-deployer -c deployment.yaml --force

A successful run of MAAS deployer should give you the following:

  - MAAS node provisioned and configured

  - MAAS boot-images in progress of being downloaded

  - Configuration parameters configured in MAAS

  - Nodes commissioning in http://<maas-host>/MAAS/#/nodes

  - Nodes tagged appropriately (api, bootstrap, etc)

  - Juju environments.yaml file generated and uploaded to
    /home/juju on maas controller

  - Nodes commissioned and ready

# Deploying charms

The controller vm will have a pre-configured Juju environments file uploaded to
/home/juju/.juju/environments.yaml which can used by logging in and switching
to the juju user:

  sudo su - juju
  juju bootstrap --constraints="tags=bootstrap"

Or alternatively you could just copy it over to your $HOME e.g.

  sudo cp -R /home/juju/.juju ~
  sudo chown -R <user>: .juju
  juju bootstrap --constraints="tags=bootstrap"

Once the environment is bootstrapped you deploy charms as you like.

# Support

Please raise bugs for issues found with this tool by visiting:

  https://bugs.launchpad.net/maas-deployer
