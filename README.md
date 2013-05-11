vpcctl
======

AWS VPC deployment utility

## Install from source into virtualenv ##

<pre>
$ virtualenv -p python2.7 demo0
$ source demo0/bin/activate
$ git clone git://github.com/adelinedigital/vpcctl.git
$ cd vpcctl
$ python setup.py install
</pre>

## Authentication ##

Your access and secret keys need to be setup.  You may specify them in the main
YAML configuration file or via boto's configuration file:
https://code.google.com/p/boto/wiki/BotoConfig

## Elastic IP ##

Review config/minimal-us-east-1.yaml and replace the public-ip entry with an
available EIP.  The EIP needs to be available to your VPC: scoped for VPC and
not previously associated with an instance/ENI.

## Create A VPC ##

<pre>
$ vpcctl.py -f config/minimal-us-east-1.yaml initvpc -n demo0 -k mykeypairname -t tag0:value0
</pre>

## Usage ##

<pre>
vpcctl.py -f config.yaml initvpc [-n NAME] [-d DELAY] [-k KEY] [-t TAG]

optional arguments:
  -n NAME, --name NAME  Implementation name (tagged)
  -d DELAY, --delay DELAY
                        delay in seconds between NAT gateway hosts and
                        dependent hosts
  -k KEY, --key KEY     SSH key
  -t TAG, --tag TAG     arbitrary tag: use key:value format
</pre>

<pre>
vpcctl.py -f config.yaml runinstance [-h] [-k KEY] [-t TAG] [-c COUNT] vpcid name

positional arguments:
  vpcid                 VPC ID (e.g. vpc-4235bc4)
  name                  instance configuration name

optional arguments:
  -h, --help            show this help message and exit
  -k KEY, --key KEY     SSH key
  -t TAG, --tag TAG     arbitrary tag: uuse key:value format
  -c COUNT, --count COUNT
                        number of instances to launch
</pre>

## Configuration Reference ##

### ami-options ###

Nested associative arrays:

```python
ami-options = {'region': {'os-release': {'os-version': {'instance-arch': {'instance-store': 'ami-id'} } } } }
```

Example:
```yaml
ami-options:
  us-east-1:
    ubuntu-20130313:
      '12.10':
        64-bit: {ebs: ami-ae9806c7, instance: ami-00e17f69}
        32-bit: {ebs: ami-d09806b9, instance: ami-88e27ce1}
    amazon:
      '2013.03.1':
        64-bit: {ebs: ami-3275ee5b, instance: ami-fc75ee95}
        32-bit: {ebs: ami-5675ee3f, instance: ami-3875ee51}
  us-west-2:
    ubuntu-20130228:
      '12.04':
        64-bit: {ebs: ami-70970240, instance: ami-d6ea7fe6}
        32-bit: {ebs: ami-869401b6, instance: ami-accb56c5}
    ubuntu-20130303:
      '12.10':
        64-bit: {ebs: ami-b48f1a84, instance: ami-c68c19f6}
        32-bit: {ebs: ami-6e8f1a5e, instance: ami-dcddff99}
```

### vpc-options ###

#### region ####

Geographical region to deploy/manage the VPC.

#### cidr ####

VPC's cider block

#### DNS Configuration ####
<pre>
  enable_dns_support: true
  enable_dns_hostnames: true
</pre>

VPC's DNS services.

#### vpc-name ####

Name of the VPC.  Is tagged to all taggable objects as 'vpc-name'.

#### Access Configuration ####
<pre>
  aws-access-key-id: AKI3LS8SAMPLE
  aws-secret-access-key: d3b07384dsample495y8ku4958yfhm495ydhxy65
</pre>

Authentication credentials.  If not specified in the configuration
file, vpcctl will fall back to standard Boto configuration files.

Example
```yaml
vpc-options:
  region: us-east-1
  cidr: 10.16.0.0/16
  enable_dns_support: true
  enable_dns_hostnames: true
  vpc-name: example-vpc
```

### instance-defaults ####
#### availability-zone ####

The default availability zone.  May be overridden via individual object
configuration.

#### key-name ####

SSH key pair.  Override key-name with -k or --key CLI arguments.

#### AMI Selection ####
<pre>
  os-version
  os-release
  instance-arch
  instance-store
</pre>

AMI selection directives.  See ami-options above.

#### instance-type ####

Default instance type.  May be overridden via individual instance configuration.

#### iam-role ####

Default IAM role for instances.

####  count ####

Default number of instances to launch for each instance configuration.  Implies
DHCP.

Example:
```yaml
instance-defaults:
  availability-zone: us-east-1c
  key-name: sshkeyname
  os-release: amazon
  os-version: 2013.03.1
  instance-store: ebs
  instance-arch: 64-bit
  instance-type: m1.small
  iam-role: S3InstanceReadAccess
  count: 1
```

### DHCP Options ###

#### domain_name ####

DHCP domain_name

#### domain_name_servers ####

Use 'AmazonProvidedDNS' to have Amazon deploy DNS service to VPC.

Example:

```yaml
dhcp_options:
  domain_name: ec2.internal
  domain_name_servers: AmazonProvidedDNS
```

### availability-zones ###

List of associative arrays configuring subnets in availability zones.  Networks
named 'external' will automatically be configured to route to an Internet
Gateway device.  All other names result in internal subnets.  Internal subnets
will be configured to route to a local NAT service instance, if available.

The following example deploys 18 subnets in 3 availability zones:

```yaml
- name: us-east-1c
  networks: { cache: 10.16.69.0/24, external: 10.16.64.0/24,
              infrastructure: 10.16.65.0/24, rds: 10.16.67.0/24,
              web: 10.16.66.0/24, mail: 10.16.68.0/24 }

- name: us-east-1d
  networks: { cache: 10.16.101.0/24, external: 10.16.96.0/24,
              infrastructure: 10.16.97.0/24, rds: 10.16.99.0/24,
              web: 10.16.98.0/24, mail: 10.16.100.0/24 }

- name: us-east-1e
  networks: { cache: 10.16.133.0/24, external: 10.16.128.0/24,
              infrastructure: 10.16.129.0/24, rds: 10.16.131.0/24,
              web: 10.16.130.0/24, mail: 10.16.132.0/24 }
```

### security-groups ###

List of associative arrays confiuring security groups.

```yaml
- name: default
  description: "default security group"
  rules:
  - { protocol: tcp,  from_port: 22, to_port: 22, source: self }
  - { protocol: icmp, from_port: -1, to_port: -1, source: 0.0.0.0/0 }

- name: web
  description: "web services group"
  rules:
  - { protocol: tcp, from_port:  80, to_port:  80, source: 0.0.0.0/0 }
  - { protocol: tcp, from_port: 443, to_port: 443, source: 0.0.0.0/0 }
```

### load-balancers ###

List of associative arrays specifying load balancers.

Keys instances, security-groups, availability-zones and subnets reference
configuration object object names.

#### scheme ####

May be 'internal' or 'internet-facing'.

#### listeners ####

A list of [ source, dest, proto ] configurations.

Example:
```yaml
load-balancers:
- name: ext-lb0
  instances: [ web-1c ]
  security-groups: [ default, web ]
  availability-zones: [ us-east-1c ]
  subnets: [ external ]
  scheme: internet-facing
  listeners:
  - [ 80, 80, 'http']

- name: int-lb0
  instances: [ web-1c ]
  security-groups: [ default, web ]
  availability-zones: [ us-east-1c ]
  subnets: [ web ]
  aliases: [ int-lb0 ]
  scheme: internal
  listeners:
  - [ 80, 80, HTTP ]
```

### instances ###

List of associative arrays specifying instance configurations.

#### role ####

Specifies the subnet name.  This is overridden by more specific configuration
directives like 'nics' or 'private-ip'.

#### user-data-file ####

Path to a local file to feed the instances' user-data field.

#### nat-gateway ####

Configures networking requirements to service as a NAT gateway.

#### Network Configuration ####

Order of configuration priority from high to low: nics, private-ip, DHCP.

##### nics #####

Used to specify multiple network interfaces.  Each entry may specify the
following configuration directives:

* public-ip: an available Elastic IP
* private-ip: internal IP address
* security-groups: list of names of security group configurations

##### private-ip #####

Specifies a single network interface.

##### DHCP ######

If private-ip or nics is not specified, the instance will acquire an IP address
via DHCP.

##### public-ip #####

An available elastic IP to associate with the instance.

Examples:

Instance with multiple network interfaces:
```yaml
- name: ep0
  nics:
  - { private-ip: 10.16.64.10, public-ip: 123.234.123.234, security-groups: [ default, ep, imap, smtp ] }
  - { private-ip: 10.16.64.11, public-ip: 234.123.234.123, security-groups: [ default, ep, imap, smtp ] }
  user-data-file: cloudinit/ep0.yaml
  nat-gateway: true
```

DHCP instances:
```yaml
- name: web-1c
  role: web
  security-groups: [ web, default ]
  user-data-file: cloudinit/web.yaml
  instance-type: t1.micro
  instance-store: ebs
  availability-zone: us-east-1c
  count: 2
```

## Demonstrative Configuration File ##

```yaml
ami-options:
  us-east-1:
    amazon:
      '2013.03.1':
        64-bit: {ebs: ami-3275ee5b, instance: ami-fc75ee95}

vpc-options:
  region: us-east-1
  cidr: 10.16.0.0/16
  enable_dns_support: true
  enable_dns_hostnames: true
  ## override vpc-name with -n or --name CLI arguments
  vpc-name: minimal0
  ## define access/secret keys here or fall back to boto configuration
  ## https://code.google.com/p/boto/wiki/BotoConfig
  #aws-access-key-id: AKI3LS8SAMPLE
  #aws-secret-access-key: d3b07384dsample495y8ku4958yfhm495ydhxy65

instance-defaults:
  availability-zone: us-east-1c
  ## override key-name with -k or --key CLI arguments
  key-name: sshkeyname
  os-release: amazon
  os-version: 2013.03.1
  instance-store: ebs
  instance-arch: 64-bit
  instance-type: m1.small
  iam-role: S3InstanceReadAccess
  count: 1

dhcp_options:
  domain_name: ec2.internal
  domain_name_servers: AmazonProvidedDNS

availability-zones:
- name: us-east-1c
  networks: { external: 10.16.64.0/24, internal: 10.16.65.0/24 }

security-groups:
- name: default
  description: "default security group"
  rules:
  - { protocol: tcp,  from_port: 22, to_port: 22, source: self }
  - { protocol: icmp, from_port: -1, to_port: -1, source: 0.0.0.0/0 }

- name: web
  description: "web services group"
  rules:
  - { protocol: tcp, from_port:  80, to_port:  80, source: 0.0.0.0/0 }
  - { protocol: tcp, from_port: 443, to_port: 443, source: 0.0.0.0/0 }

- name: ep
  description: "ep services group"
  rules:
  - { protocol:  tcp, from_port:   22, to_port:   22, source: 0.0.0.0/0 }
  - { protocol:  tcp, from_port: 1194, to_port: 1194, source: 0.0.0.0/0 }

load-balancers:
- name: ext-lb0
  instances: [ web-1c ]
  security-groups: [ default, web ]
  availability-zones: [ us-east-1c ]
  subnets: [ external ]
  scheme: internet-facing
  listeners:
  - [ 80, 80, 'http']

instances:
- name: ep0
  instance-type: m1.small
  private-ip: 10.16.64.10
  public-ip: a.b.c.d
  availability-zone: us-east-1c
  security-groups: [ default, ep ]
  user-data-file: cloudinit/ep0.yaml
  nat-gateway: true

- name: web-1c
  role: internal
  security-groups: [ web, default ]
  user-data-file: cloudinit/web.yaml
  instance-type: t1.micro
  instance-store: ebs
  availability-zone: us-east-1c
  count: 2
```
