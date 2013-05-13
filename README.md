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

Create VPC:
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

Ad-hoc instance launch:
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
* _scope: global_

Nested associative arrays:

```python
ami-options = {region: {os-release: {os-version: {instance-arch: {instance-store: 'ami-id'}}}}}
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
* _scope: global_
* _type: dictionary_

Example
```yaml
vpc-options:
  region: us-east-1
  cidr: 10.16.0.0/16
  enable_dns_support: true
  enable_dns_hostnames: true
  vpc-name: example-vpc
```

#### region:
* _scope: vpc-options_
* _type: string_

Geographical region to deploy/manage the VPC, e.g.:
* us-east-1
* us-west-2

#### cidr:
* _scope: vpc-options_
* _type: string_

VPC's CIDR block.

<pre>10.0.0.0/16</pre>

#### enable-dns-support:
#### enable-dns-hostnames:
* _scope: vpc-options_
* _type: boolean_

VPC's DNS services.  AWS will deploy DNS services in the VPC if
enable-dns-support is set to 'true'.  if enable-dns-hostnames and
enable-dns-support are both set to 'true', AWS will deploy DNS services with
resolution for hostnames and IP addresses within the VPC.

#### vpc-name:
* _scope: vpc-options_
* _type: string_

Name of the VPC.  Is tagged to all taggable objects as 'vpc-name'.

#### aws-access-key-id:
#### aws-secret-access-key:
* _scope: vpc-options_
* _type: string_

Authentication credentials.  If not specified in the configuration
file, vpcctl will fall back to standard Boto configuration files.

### instance-defaults
* _scope: global_
* _type: dictionary_

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

#### availability-zone:
* _scope: instance-defaults_
* _type: string_

The default availability zone, e.g. us-east-1c.

#### key-name:

SSH key pair.  Override key-name with -k or --key CLI arguments.

#### os-version:
#### os-release:
#### instance-arch:
#### instance-store:
* _scope: instance-defaults_
* _type: string_

AMI selection directives.  See ami-options above.

#### instance-type:
* _scope: instance-defaults_
* _type: string_

Default instance type, e.g. m1.small.

#### iam-role:
* _scope: instance-defaults_
* _type: string_

Default IAM role for instances.

#### count:
* _scope: instance-defaults_
* _type: int_

Default number of instances to launch for each instance configuration.  Values
greater than one preclude many things such as specifying IP addresses or EBS
attachements.  Default will usually be 1.

### dhcp-options: ###
* _scope: global_
* _type: dictionary_

#### domain-name:
* _scope: dhcp-options_ 
* _type: string_

DHCP domain-name:

#### domain-name-servers
* _scope: dhcp-options_ 
* _type: string_

Use 'AmazonProvidedDNS' to have Amazon deploy DNS service to VPC.

Example:
```yaml
dhcp-options:
  domain-name: ec2.internal
  domain-name-servers: AmazonProvidedDNS
```

### availability-zones:
* _scope: global_
* _type: list of dictionaries_

List of associative arrays configuring subnets in availability zones.  Networks
named 'external' will automatically be configured to route to an Internet
Gateway device.  All other names result in internal subnets.  Internal subnets
will be configured to route to a local NAT service instance, if available.  See
nat-gateway instance flag below.

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

### security-groups:
* _scope: global_
* _type: list of dictionaries_

List of associative arrays configuring security groups.

#### name:
* _scope: security-group_
* _type: string_

#### description:
* _scope: security-group_
* _type: string_

#### rules:
* _scope: security-group_
* _type: list of dictionaries_

##### protocol:
* _scope: rule_
* _type: string_
'tcp', 'udp' or 'icmp'

##### from-port and to-port:
* _scope: rule_
* _type: int_

##### source:
* _scope: rule_
* _type string_
'self', 'default' or valid CIDR block.

Example:
```yaml
- name: default
  description: "default security group"
  rules:
  - { protocol: tcp,  from_port: 22, to_port: 22, source: self }
  - { protocol: icmp, from_port: -1, to_port: -1, source: 0.0.0.0/0 }

- name: ldap
  description: "ldap services group"
  rules:
  - { protocol: tcp, from_port:  389, to_port:  389, source: default }

- name: web
  description: "web services group"
  rules:
  - { protocol: tcp, from_port:  80, to_port:  80, source: 0.0.0.0/0 }
  - { protocol: tcp, from_port: 443, to_port: 443, source: 0.0.0.0/0 }
```

### load-balancers:
* _scope: global_
* _type: list of dictionaries_

List of associative arrays specifying load balancers.

#### scheme:
* _scope: load-balancers_
* _type: string_

May be 'internal' or 'internet-facing'.

#### listeners:
* _scope: load-balancers_
* _type: list_

A list of [ source, dest, proto ] configurations.  In Python, this might look
like a tuple: (int, int, string).

#### instances:
* _scope: load-balancers_
* _type: list of strings_

List of strings that reference configuration object names.

#### security-groups:
* _scope: load-balancers_
* _type: list of strings_

List of strings that reference configuration object names.

#### availability-zones:
* _scope: load-balancers_
* _type: list of strings_

List of strings that reference configuration object names.

#### subnets:
* _scope: load-balancers_
* _type: list of strings_

List of strings that reference configuration object names.

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

### instances:
* _scope: global_
* _type: list of dictionaries_

List of associative arrays specifying instance configurations.

#### name:
* _scope: instance configuration_
* _type: string_

Name of the instance or instances.  Gets tagged as value for 'Name' key.

#### instance-type:
* _scope: instance configuration_
* _type: string_

E.g.: m1.small or t1.micro.  Falls back to instance-defaults: instance-type if
not specified.

#### availability-zone:
* _scope: instance configuration_
* _type: string_

Falls back to instance-defaults: availability-zone if not specified.

#### subnet:
* _scope: instance configuration_
* _type: string_

References the instance's subnet by configuration name.  This is overridden by
more specific configuration directives like 'nics' or 'private-ip'.

#### user-data-file:
* _scope: instance configuration_
* _type: string_

Path to a local file to feed the instances' user-data field.

#### nat-gateway:
* _scope: instance configuration_
* _type: boolean_

Configures networking requirements for an instance to serve as a NAT gateway.

Order of configuration priority from high to low: nics, private-ip, DHCP.

#### attach-volumes:
* _scope: instance configuration_
* _type: dictionary_

Attach an existing EBS volume.

Key: device
Value: volume ID

Example:
```yaml
attach-volumes:
    /dev/sdf: vol-d7c13b8f
    /dev/sdg: vol-cdc13b95
```

#### create-volumes:
* _scope: instance configuration_
* _type: dictionary_

Create one or more new EBS block volumes.

Key: device
Value: associative array of new device configuration:
* size: int (GB)
* snapshot: string (id or null)
* type: string (standard or io1)
* iops: int (iops or null)

Example:
```yaml
create-volumes:
   "/dev/sdj": { size: 2, snapshot: null, type: standard, iops: null }
   "/dev/sdk": { size: 2, snapshot: null, type: standard, iops: null }
'''

#### nics:
* _scope: instance configuration_
* _type: dictionary_

Used to specify multiple network interfaces.  Each entry may specify the
following configuration directives:

* public-ip: an available Elastic IP
* private-ip: internal IP address
* security-groups: list of names of security group configurations

#### public-ip:
* _scope: instance configuration_
* _type: string_

An available elastic IP to associate with the instance.

#### private-ip:
* _scope: instance configuration_
* _type: string_

Specifies a single IP address.

#### Example Network Configurations
Instance with multiple network interfaces:
```yaml
- name: ep0
  nics:
  - { private-ip: 10.16.64.10, public-ip: 123.234.123.234, security-groups: [ default, ep, imap, smtp ] }
  - { private-ip: 10.16.64.11, public-ip: 234.123.234.123, security-groups: [ default, ep, imap, smtp ] }
  nat-gateway: true
```

DHCP instances:
```yaml
- name: web-1c
  subnet: web
  security-groups: [ web, default ]
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
  enable-dns-support: true
  enable-dns-hostnames: true
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

dhcp-options:
  domain-name: ec2.internal
  domain-name-servers: AmazonProvidedDNS

availability-zones:
- name: us-east-1c
  networks: { external: 10.16.64.0/24, internal: 10.16.65.0/24 }

security-groups:
- name: default
  description: "default security group"
  rules:
  - { protocol: tcp,  from-port: 22, to-port: 22, source: self }
  - { protocol: icmp, from-port: -1, to-port: -1, source: 0.0.0.0/0 }

- name: web
  description: "web services group"
  rules:
  - { protocol: tcp, from-port:  80, to-port:  80, source: 0.0.0.0/0 }
  - { protocol: tcp, from-port: 443, to-port: 443, source: 0.0.0.0/0 }

- name: ep
  description: "ep services group"
  rules:
  - { protocol:  tcp, from-port:   22, to-port:   22, source: 0.0.0.0/0 }
  - { protocol:  tcp, from-port: 1194, to-port: 1194, source: 0.0.0.0/0 }

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
