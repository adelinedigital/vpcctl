#!/usr/bin/env python

"""
This utility creates Virtual Private Clouds in Amazon Web Services from a
simple configuration file.

Copyright 2013 Jon M. Skelton <jskelton@adelinedigital.com>
"""

__author__ = 'Jon M. Skelton'
__version__ = '0.1'

import sys
import time
import yaml
import ipcalc
import argparse
import boto.ec2
import boto.rds
import boto.iam
import boto.vpc
import collections
import boto.ec2.elb

from boto.exception import EC2ResponseError
from boto.ec2.ec2object import TaggedEC2Object
from boto.ec2.networkinterface import NetworkInterfaceSpecification
from boto.ec2.networkinterface import NetworkInterfaceCollection
from boto.ec2.blockdevicemapping import BlockDeviceMapping
from boto.ec2.blockdevicemapping import BlockDeviceType

REGION = None

VPC_CONN = None
EC2_CONN = None
IAM_CONN = None
ELB_CONN = None
RDS_CONN = None

ACCESS_KEY = None
SECRET_KEY = None

DEFAULT_DELAY = 30

class connected(object):
    """
    A method decorator that ensures various Boto connection objects are
    correctly instansiated before the AWS operations are performed.

    wrapped methods must have boto.vpc.vpc.VPC instance object as the
    first argument or available as 'vpc' in kwargs.
    """

    def __init__(self, service):
        """
        Constructor takes a single string argument identifying the
        required AWS service.

        :type service: str
        :param service: one of 'vpc', 'ec2', 'iam', 'elb', or 'rds'
        """
        self.service = service

    def __call__(self, func):
        def wrapped_func(*args, **kwargs):
            global EC2_CONN
            global IAM_CONN
            global ELB_CONN
            global RDS_CONN

            if self.service == 'ec2' and EC2_CONN == None:
                EC2_CONN = boto.ec2.connect_to_region(region_name=REGION,
                                                      aws_access_key_id=ACCESS_KEY,
                                                      aws_secret_access_key=SECRET_KEY)
            elif self.service == 'elb' and ELB_CONN == None:
                ELB_CONN = boto.ec2.elb.connect_to_region(region_name=REGION,
                                                          aws_access_key_id=ACCESS_KEY,
                                                          aws_secret_access_key=SECRET_KEY)
            elif self.service == 'iam' and IAM_CONN == None:
                IAM_CONN = boto.iam.connect_to_region(region_name=REGION,
                                                      aws_access_key_id=ACCESS_KEY,
                                                      aws_secret_access_key=SECRET_KEY)
            elif self.service == 'rds' and RDS_CONN == None:
                RDS_CONN = boto.rds.connect_to_region(region_name=REGION,
                                                      aws_access_key_id=ACCESS_KEY,
                                                      aws_secret_access_key=SECRET_KEY)

            return func(*args, **kwargs)
        return wrapped_func

def find_vpc(region, access_key, secret_key, vpc_id):
    """
    searches for and returns a VPC by ID

    :type region: str
    :param region: region e.g. us-east-1
    :type access_key: str
    :param access_key: AWS Access Key
    :type secret_key: str
    :param secret_key: AWS Secret Key
    :type vpc_id: str
    :param vpc_id: VPC's ID
    :rtype: class:`boto.vpc.vpc.VPC`
    :return: found VPC or None
    """

    sys.stdout.write('searching for VPC: {}'.format(vpc_id))
    sys.stdout.flush()

    global VPC_CONN
    if not VPC_CONN:
        VPC_CONN = boto.vpc.connect_to_region(region_name=region,
                                              aws_access_key_id=access_key,
                                              aws_secret_access_key=secret_key)
    while True:
        try:
            vpcs = VPC_CONN.get_all_vpcs([vpc_id])
            if len(vpcs) == 1:
                sys.stdout.write('\n')
                sys.stdout.flush()
                return vpcs[0]

            sys.stdout.write('.  Not found.\n')
            sys.stdout.flush()
            return None

        except EC2ResponseError:
            sys.stdout.write(".")
            sys.stdout.flush()
            time.sleep(1)

def tag_taggable(taggable, key=None, value=None, tags=None):
    """
    Wrapper function used to tag AWS objects.

    :type taggable: boto.ec2.ec2object.TaggedEC2Object
    :param taggable: object to be tagged.
    :type key: str
    :param key: key for tag
    :type value: str
    :param value: key for tag
    :type tags: dictionary
    :param tags: dictionary of key/value pairs
    """

    if not isinstance(taggable, TaggedEC2Object):
        return

    while(True):
        try:
            if tags and isinstance(tags, collections.Mapping):
                for tag in tags:
                    taggable.add_tag(tag, tags[tag])
            if key and value:
                taggable.add_tag(str(key), str(value))
            return
        except EC2ResponseError:
            sys.stdout.write('.')
            sys.stdout.flush()
            time.sleep(1)

@connected('ec2')
def tag_instance_volumes(vpc, instance_id, key=None, value=None, tags=None):
    """
    Tag all volumes associated with an instance

    :type vpc: :class:`boto.vpc.vpc.VPC`
    :param vpc: VPC instance object
    :type instance_id: str
    :param instance_id: instance ID
    :type key: str
    :param key: key for tag
    :type value: str
    :param value: key for tag
    :type tags: dictionary
    :param tags: dictionary of key/value pairs
    """

    if not instance_id:
        return

    while(True):
        try:
            vols = EC2_CONN.get_all_volumes(
                                 filters={'attachment.instance-id':instance_id})
            for vol in vols:
                tag_taggable(taggable=vol, key=key, value=value, tags=tags)
                sys.stdout.write(' {}'.format(vol))
                sys.stdout.flush()

            sys.stdout.write('\n')
            sys.stdout.flush()
            return
        except EC2ResponseError:
            pass

        sys.stdout.write('.')
        sys.stdout.flush()
        time.sleep(1)

def create_internet_gateway(vpc, tags=None):
    """
    Create an Internet gateway object for VPC.

    :type vpc: :class:`boto.vpc.vpc.VPC`
    :param vpc: instance of a VPC
    :type tags: dict
    :param tags: dictionary of tags {str:str}
    :rtype: str
    :return: igw id
    """

    sys.stdout.write('creating internet gateway: ')
    sys.stdout.flush()
    igw = None

    while(True):
        try:
            igw = vpc.connection.create_internet_gateway()
            sys.stdout.write(igw.id)
            sys.stdout.flush()
            break
        except EC2ResponseError:
            sys.stdout.write('.') 
            sys.stdout.flush()
            time.sleep(1)

    while(True):
        try:
            igws = vpc.connection.get_all_internet_gateways(
                                      filters=[('internet-gateway-id', igw.id)])
            if len(igws) == 1:
                igw = igws[0]
                tag_taggable(igw, tags)
                vpc.connection.attach_internet_gateway(internet_gateway_id=igw.id,
                                                       vpc_id=vpc.id)
                sys.stdout.write('\n')
                sys.stdout.flush()
                return igw
        except EC2ResponseError:
            pass

        sys.stdout.write('.')
        sys.stdout.flush()
        time.sleep(1)

    return igw.id

def create_internal_routes(vpc, av_zones, tags=None):
    """
    Create route tables for Availability Zones with internal subnets.

    :type vpc: :class:`boto.vpc.vpc.VPC`
    :param vpc: instance of a VPC
    :type av_zones: iter
    :param av_zones: iterable of Availability Zones with internal subnets
    :type tags: dict
    :param tags: dictionary of tags {str:str}
    :rtype: dict
    :return: dictionary of {azname:rtb-object}
    """

    route_tables = dict()

    for av_zone in av_zones:
        route = vpc.connection.create_route_table(vpc_id=vpc.id)
        tag_taggable(taggable=route, key='vpcctl-az', value=av_zone['name'])
        tag_taggable(taggable=route, key='vpcctl-rtb-type', value='internal')
        tag_taggable(taggable=route, tags=tags)

        route_tables[av_zone['name']] = route

    return route_tables

def create_subnets(vpc, av_zones, external_rt, internal_rts, tags=None):
    """
    Create subnets.

    :type vpc: :class:`boto.vpc.vpc.VPC`
    :param vpc: instance of a VPC
    :type av_zones: dict
    :param av_zones: dictionary of Availability Zones
    :type external_rt: :class:`boto.vpc.routetable.RouteTable`
    :param external_rt: route table with route to internet gateway object
    :type internal_rts: dict of av_zone(str): :class:`boto.vpc.routetable.RouteTable`
    :param internal_rts: availability zones and their respective route tables
    :type tags: dict
    :param tags: dictionary of tags {str:str}
    :rtype: list
    :return: list of :class:`boto.vpc.subnet.Subnet`
    """

    networks = []

    for av_zone in av_zones:
        for network in av_zone['networks']:
            subnet = vpc.connection.create_subnet(vpc_id=vpc.id,
                  cidr_block=av_zone['networks'][network],
                  availability_zone=av_zone['name'])
            tag_taggable(taggable=subnet, key='vpcctl-subnet-role', value=network)
            tag_taggable(taggable=subnet, tags=tags)
          
            if network == 'external':
                sys.stdout.write('  Associating {} ({}) with subnet {}.\n'.format(
                                                    external_rt, network, subnet))
                sys.stdout.flush()
                vpc.connection.associate_route_table(route_table_id=external_rt.id,
                                               subnet_id=subnet.id)
            else:
                sys.stdout.write('  Associating {} ({}) with subnet {}.\n'.format(
                                  internal_rts[av_zone['name']],
                                  network, subnet))
                sys.stdout.flush()
                vpc.connection.associate_route_table(
                                route_table_id=internal_rts[av_zone['name']].id,
                                subnet_id=subnet.id)

            networks.append(subnet)
            sys.stdout.write('created: {}\n'.format(subnet))
            sys.stdout.flush()

    return networks

@connected('ec2')
def create_security_groups(vpc, sg_configs, tags=None):
    """
    Create security groups.

    :type vpc: :class:`boto.vpc.vpc.VPC`
    :param vpc: instance of a VPC
    :type sg_configs: dict
    :param sg_configs: dictionary of security group configurations
    :type tags: dict
    :param tags: dictionary of tags {str:str}
    """

    default_sg = EC2_CONN.get_all_security_groups(filters={'vpc-id': vpc.id})[0]

    for sgconfig in sg_configs:
        if sgconfig['name'] == 'default':
            sec_group = default_sg
        else:
            sec_group = EC2_CONN.create_security_group(name=sgconfig['name'],
                                         description=sgconfig['description'],
                                         vpc_id=vpc.id)

        tag_taggable(taggable=sec_group, key='vpcctl-sg-name',
                                         value=sgconfig['name'])
        tag_taggable(taggable=sec_group, key='vpcctl-sg-description',
                                         value=sgconfig['description'])
        tag_taggable(taggable=sec_group, tags=tags)

        if 'rules' in sgconfig:
            for rule in sgconfig['rules']:
                source = rule['source']
                protocol = rule['protocol']
                from_port = int(rule['from-port'])
                to_port = int(rule['to-port'])
                if source == 'self':
                    sec_group.authorize(ip_protocol=protocol,
                                        from_port=from_port,
                                        to_port=to_port,
                                        src_group=sec_group)
                    sys.stdout.write('authorized traffic from {}:{} to {}:{} for {}.\n'.format(
                                  sec_group, from_port, sec_group, to_port, protocol))
                    sys.stdout.flush()
                elif source == 'default':
                    sec_group.authorize(ip_protocol=protocol,
                                        from_port=from_port,
                                        to_port=to_port,
                                        src_group=default_sg)
                    sys.stdout.write('authorized traffic from {}:{} to {}:{} for {}.\n'.format(
                                  default_sg, from_port, sec_group, to_port, protocol))
                    sys.stdout.flush()
                else:
                    sec_group.authorize(ip_protocol=protocol,
                                        from_port=from_port,
                                        to_port=to_port, cidr_ip=source)
                    sys.stdout.write('authorized traffic from {}:{} to {}:{} for {}.\n'.format(
                                  source, from_port, sec_group, to_port, protocol))
                    sys.stdout.flush()

@connected('ec2')
def create_volume(vpc, size, zone, snapshot=None, volume_type=None, iops=None):
    """
    Create EBS volume.

    :type vpc: :class:`boto.vpc.vpc.VPC`
    :param vpc: instance of a VPC
    :type size: int
    :param size: volume size in GB
    :type zone: str
    :param zone: availability zone
    :type snapshot: string
    :param snapshot: ID of snapshot
    :type volume_type: string
    :param volume_type: standard or io1
    :rtype: :class:`boto.ec2.volume.Volume`
    :return: created volume
    """

    sys.stdout.write('creating {}GB volume'.format(size))
    sys.stdout.flush()

    volume = None

    while(True):
        try:
            volume = EC2_CONN.create_volume(size=size, zone=zone,
                                            snapshot=snapshot,
                                            volume_type=volume_type,
                                            iops=iops)
            sys.stdout.write(" {}".format(volume.id))
            sys.stdout.flush()
            break
        except EC2ResponseError:
            sys.stdout.write('.')
            sys.stdout.flush()
            time.sleep(1)

    while(True):
        try:
            volumes = EC2_CONN.get_all_volumes(volume_ids=[volume.id])
            if len(volumes) == 1:
                sys.stdout.write('\n')
                sys.stdout.flush()
                return volumes[0]
        except EC2ResponseError:
            sys.stdout.write('.')
            sys.stdout.flush()
            time.sleep(1)

def find_subnet_by_role(vpc, role, av_zone):
    """
    return subnet located by role and availability zone or None

    :type vpc: :class:`boto.vpc.vpc.VPC`
    :param vpc: instance of a VPC
    :type role: str
    :param role: name of role
    :type av_zone: string
    :param av_zone: name of availability zone
    :rtype: :class:`boto.vpc.subnet.Subnet`
    :return: subnet
    """

    subnets = vpc.connection.get_all_subnets(subnet_ids=None,
                                       filters=[('vpcId', vpc.id)])

    for subnet in subnets:
        if subnet.tags['vpcctl-subnet-role'] == role and \
                    subnet.availability_zone == av_zone:
            return subnet

    return None

def find_subnet_by_ipaddr(vpc, ipaddr):
    """
    return subnet located by ip address or None

    :type vpc: :class:`boto.vpc.vpc.VPC`
    :param vpc: instance of a VPC
    :type ipaddr: str
    :param ipaddr: ip address
    :rtype: :class:`boto.vpc.subnet.Subnet`
    :return: subnet
    """

    subnets = vpc.connection.get_all_subnets(subnet_ids=None,
                                       filters=[('vpcId', vpc.id)])

    for subnet in subnets:
        if ipaddr in ipcalc.Network(ip=subnet.cidr_block):
            return subnet

    return None

@connected('ec2')
def find_nic_by_ipaddr(vpc, ipaddr):
    """
    return nic located by ip address or None

    :type vpc: :class:`boto.vpc.vpc.VPC`
    :param vpc: instance of a VPC
    :type ipaddr: str
    :param ipaddr: ip address
    :rtype: :class:`boto.ec2.networkinterface.NetworkInterface`
    :return: nic
    """

    pri_nics = EC2_CONN.get_all_network_interfaces(filters={'vpc-id':vpc.id,
                                                            'private-ip-address':ipaddr})
    if len(pri_nics) == 1:
        return pri_nics[0]

    pub_nics = EC2_CONN.get_all_network_interfaces(filters={'vpc-id':vpc.id,
                                                            'association.public-ip':ipaddr})
    if len(pub_nics) == 1:
        return pub_nics[0]

    return None

@connected('ec2')
def create_nic_spec(vpc, ipaddr, network, nic_index, security_groups, tags=None):
    """
    return subnet located by ip address or None

    :type vpc: :class:`boto.vpc.vpc.VPC`
    :param vpc: instance of a VPC
    :type ipaddr: str
    :param ipaddr: ip address
    :type network: :class:`boto.vpc.network.Network`
    :param network: network
    :type nic_index: int
    :param nic_index: starts at 1
    :type security_groups: list
    :param security_groups: list of boto.ec2.securitygroup.SecurityGroup 
    :rtype: :class:`boto.vpc.subnet.Subnet`
    :return: subnet
    """

    if not network:
        network = find_subnet_by_ipaddr(vpc=vpc, ipaddr=ipaddr)

    nic = find_nic_by_ipaddr(vpc, ipaddr)
    if nic:
        sys.stdout.write('found existing NIC: {}.  Querying EC2'.format(nic))
        sys.stdout.flush()
    else:
        nic = EC2_CONN.create_network_interface(subnet_id=network.id,
                                                private_ip_address=ipaddr,
                                                description=None,
                                                groups=security_groups)

        sys.stdout.write('{} created.  Querying EC2'.format(nic))
        sys.stdout.flush()

    while(True):
        try:
            nics = EC2_CONN.get_all_network_interfaces( \
                                       filters={'vpc-id': vpc.id,
                                                'network-interface-id': nic.id})
            if len(nics) == 1:
                nic = nics[0]
                tag_taggable(taggable=nic, tags=tags)
                sys.stdout.write('\n')
                sys.stdout.flush()
                return NetworkInterfaceSpecification(network_interface_id=nic.id,
                                                     device_index=nic_index)
        except EC2ResponseError:
            pass

        sys.stdout.write('.')
        sys.stdout.flush()
        time.sleep(1)

@connected('ec2')
def find_address_object_by_ipaddr(vpc, ipaddr):
    """
    return address object located by ip address or None

    :type vpc: :class:`boto.vpc.vpc.VPC`
    :param vpc: instance of a VPC
    :type ipaddr: str
    :param ipaddr: ip address
    :rtype: :class:`boto.ec2.address.Address`
    :return: address
    """

    addresses = EC2_CONN.get_all_addresses(addresses=[ipaddr])
    if addresses:
        return addresses[0]

    raise ValueError('address not found: ' + str(ipaddr))

@connected('ec2')
def create_nicspecs(vpc, instance_config, tags=None):
    """
    Create NIC specification

    :type vpc: :class:`boto.vpc.vpc.VPC`
    :param vpc: instance of a VPC
    :type instance_config: dict
    :param instance_configs: dictionary of instance configurations
    :type tags: dict
    :param tags: dictionary of tags {str:str}
    :rtype: :class:`boto.ec2.networkinterface.NetworkInterfaceCollection`
    :return: NIC specifications
    """

    nicspecs = NetworkInterfaceCollection()
    security_group_list = EC2_CONN.get_all_security_groups(
                                 filters={'vpc-id': vpc.id})

    if 'nics' in instance_config:
        index = 0
        for nic in instance_config['nics']:
            security_groups = [ sg for sg in security_group_list \
                                    if sg.name in nic['security-groups'] ]
            nicspec = create_nic_spec(vpc=vpc, ipaddr=nic['private-ip'],
                                          network=None, nic_index=index,
                                        security_groups=security_groups,
                                                              tags=tags)
            if 'public-ip' in nic:
                addr_obj = find_address_object_by_ipaddr(vpc=vpc,
                                                         ipaddr=nic['public-ip'])
                if addr_obj.association_id:
                    sys.stdout.write("not reassociating {}\n".format(addr_obj))
                    sys.stdout.flush()
                else:
                    EC2_CONN.associate_address(instance_id=None, public_ip=None,
                                               allocation_id=addr_obj.allocation_id,
                                               network_interface_id=nicspec.network_interface_id,
                                               private_ip_address=nic['private-ip'],
                                               allow_reassociation=False)

            nicspecs.append(nicspec)
            index += 1

    elif 'private-ip' in instance_config:
        security_groups = [sg for sg in security_group_list \
                               if sg.name in instance_config['security-groups']]
        nicspec = create_nic_spec(vpc=vpc,
                                  ipaddr=instance_config['private-ip'],
                                  network=None,
                                  nic_index=0,
                                  security_groups=security_groups, tags=tags)
        if 'public-ip' in instance_config:
            addr_obj = find_address_object_by_ipaddr(vpc=vpc,
                                            ipaddr=instance_config['public-ip'])
            if addr_obj.association_id:
                sys.stdout.write("not reassociating {}\n".format(addr_obj))
                sys.stdout.flush()
            else:
                EC2_CONN.associate_address(instance_id=None, public_ip=None,
                                           allocation_id=addr_obj.allocation_id,
                                           network_interface_id=nicspec.network_interface_id,
                                           private_ip_address=instance_config['private-ip'],
                                           allow_reassociation=True)

        nicspecs.append(nicspec)

    elif 'subnet' in instance_config:
        security_groups = [sg for sg in security_group_list \
                               if sg.name in instance_config['security-groups']]
        network = find_subnet_by_role(vpc, instance_config['subnet'],
                                      instance_config['availability-zone'])

        nicspec = create_nic_spec(vpc=vpc,
                                  ipaddr=None,
                                  network=network,
                                  nic_index=0,
                                  security_groups=security_groups,
                                  tags=tags)
        nicspecs.append(nicspec)
    else:
        sys.stdout.write('No network configuration found for instance: {}'.format(
                                                         instance_config['name']))
        sys.stdout.flush()

    return nicspecs

def create_block_device_map(instance_config):
    """
    Create block device map

    :type instance_config: dict
    :param instance_config: instance configuration
    :rtype: :class:`boto.ec2.blockdevicemapping.BlockDeviceMapping`
    :return: Block device mapping
    """

    if not 'create-volumes' in instance_config:
        return None

    bdm = BlockDeviceMapping()

    for devname in instance_config['create-volumes']:
        devinfo = dict()
        devinfo['size'] = instance_config['create-volumes'][devname]['size']

        if 'snapshot' in instance_config['create-volumes'][devname]:
            devinfo['snapshot_id'] = instance_config['create-volumes'][devname]['snapshot']
        if 'type' in instance_config['create-volumes'][devname]:
            devinfo['volume_type'] = instance_config['create-volumes'][devname]['type']
        if 'iops' in instance_config['create-volumes'][devname]:
            devinfo['iops'] = instance_config['create-volumes'][devname]['iops']
        
        dev = BlockDeviceType(**devinfo)
        bdm[devname] = dev

    return bdm

def resolve_default_ami(region, instance_config, instance_defaults, ami_options):
    """
    Find the appropriate AMI

    :type region: str
    :param region: AWS Region
    :type instance_config: dict
    :param instance_config: instance configuration
    :type instance_defaults: dict
    :param instance_defaults: default instance configuration details
    :type ami_options: dict
    :param ami_options: available amis
    :rtype: :class:`boto.ec2.blockdevicemapping.BlockDeviceMapping`
    :return: Block device mapping
    """

    if 'os-version' in instance_config:
        os_version = instance_config['os-version']
    else:
        os_version = instance_defaults['os-version']

    if 'os-release' in instance_config:
        os_release = instance_config['os-release']
    else:
        os_release = instance_defaults['os-release']

    if 'instance-arch' in instance_config:
        instance_arch = instance_config['instance-arch']
    else:
        instance_arch = instance_defaults['instance-arch']

    if 'instance-store' in instance_config:
        instance_store = instance_config['instance-store']
    else:
        instance_store = instance_defaults['instance-store']

    return ami_options[region][os_release][os_version][instance_arch][instance_store]

def db_launch_config(db_config):
    """
    Resolve keyword arguments (**kwargs) used to launch a database.

    :type db_config: dict
    :param db_config: database configuration
    :rtype: dict
    :return: kwargs dictionary
    """

    if 'raw-options' in db_config:
        options = db_config['raw-options']
    else:
        options = dict()

    for option in (('name', 'id'),
                   ('iops', 'iops'),
                   ('port', 'port'),
                   ('engine', 'engine'),
                   ('multi-az', 'multi_az'),
                   ('size', 'allocated_storage'),
                   ('db-instance-type', 'instance_class'),
                   ('master-username', 'master_username'),
                   ('master-password', 'master_password'),
                   ('db-security-groups', 'security_groups'),
                   ('availability-zone', 'availability_zone'),
                   ('db-subnet-group-name', 'db_subnet_group_name')):
        if option[0] in db_config:
            options[option[1]] = db_config[option[0]]

    return options

def instance_launch_config(instance_config, instance_defaults, ami_options, region):
    """
    Resolve keyword arguments (**kwargs) used to launch an instance.

    :type instance_config: dict
    :param instance_config: instance configuration
    :type instance_defaults: dict
    :param instance_defaults: default instance configuration options
    :type ami_options: dict
    :param ami_options: available ami description configuration
    :type region: str
    :param region: region name
    :rtype: dict
    :return: kwargs dictionary
    """

    if 'raw-options' in instance_config:
        options = instance_config['raw-options']
    else:
        options = dict()

    if 'count' in instance_config:
        options['min_count'] = instance_config['count']
        options['max_count'] = instance_config['count']
    elif 'count' in instance_defaults:
        options['min_count'] = instance_defaults['count']
        options['max_count'] = instance_defaults['count']
    else:
        options['min_count'] = 1
        options['max_count'] = 1

    if 'instance_profile_name' not in options and 'iam-role' in instance_config:
        options['instance_profile_name'] = instance_config['iam-role']
    elif 'instance_profile_name' not in options:
        options['instance_profile_name'] = instance_defaults['iam-role']

    if 'placement' not in options and 'availability-zone' in instance_config:
        options['placement'] = instance_config['availability-zone']
    elif 'placement' not in options:
        options['placement'] = instance_defaults['availability-zone']
        #consumed by create_nicspecs()
        #TODO: unrelated to instance launch kwargs
        instance_config['availability-zone'] = instance_defaults['availability-zone']
    if 'instance_type' not in options and 'instance-type' in instance_config:
        options['instance_type'] = instance_config['instance-type']
    elif 'instance_type' not in options:
        options['instance_type'] = instance_defaults['instance-type']

    if not 'key_name' in options:
        options['key_name'] = instance_defaults['key-name']

    if 'image_id' not in options and 'image-id' in instance_config:
        options['image_id'] = instance_config['image-id']
    elif 'image-id' not in options:
        options['image_id'] = resolve_default_ami(region, instance_config,
                                                  instance_defaults, ami_options)

    if 'user-data-file' in instance_config:
        with open(instance_config['user-data-file'], 'rb') as userdata_fd:
            options['user_data'] = userdata_fd.read()

    return options

@connected('ec2')
def attach_volume(vpc, volume_id, instance_id, device):
    sys.stdout.write('attaching {} to {} on {}'.format(volume_id,
                                                       instance_id,
                                                       device))
    sys.stdout.flush()

    while True:
        try:
            EC2_CONN.attach_volume(volume_id=volume_id,
                                   instance_id=instance_id,
                                   device=device)
            sys.stdout.write('\n')
            sys.stdout.flush()
            return
        except EC2ResponseError as err:
            sys.stdout.write('.')
            sys.stdout.flush()
            time.sleep(1)

@connected('ec2')
def create_instances(vpc, instance_configs, config_defaults,
                     ami_options, tags=None):
    """
    Launch intances

    :type vpc: :cla
    :param instance_config: instance configuration
    :type instance_config: dict
    :param instance_config: instance configuration
    :type config_defaults: dict
    :param config_defaults: default instance configuration options
    :type ami_options: dict
    :param ami_options: available ami description configuration
    :type tags: dict
    :param tags: key value pairs to be tagged to instances
    :rtype: list of :class:`boto.ec2.instance.Instance`
    :return: List of instance objects created
    """

    reservations = dict()
    vol_assignments = dict()

    for instance_config in instance_configs:
        options = instance_launch_config(instance_config, config_defaults,
                                         ami_options, vpc.region.name)

        #single VMs get a NIC built with security groups and subnets.
        #multiple VM launches reference security groups and subnets directly.
        if options['min_count'] == 1:
            options['network_interfaces'] = create_nicspecs(vpc=vpc,
                                               instance_config=instance_config,
                                               tags=tags)
        else:
            subnet = find_subnet_by_role(vpc=vpc,
                                         role=instance_config['subnet'],
                                         av_zone=options['placement'])
            if subnet:
                options['subnet_id'] = subnet.id
            else:
                sys.stdout.write('unable to find network for {}.\n'.format(
                                                  instance_config['name']))

            security_group_list = EC2_CONN.get_all_security_groups(
                                                     filters={'vpc-id': vpc.id})

            options['security_group_ids'] = [sg.id for sg in security_group_list \
                                 if sg.name in instance_config['security-groups']]

        #options['block_device_map'] = create_block_device_map(instance_config)
        options['block_device_map'] = None

        reservation = EC2_CONN.run_instances(**options)

        #don't proceed until the instances are 'visible'
        probed_instances = [ i for r in EC2_CONN.get_all_instances(
                                        filters={'reservation_id':reservation.id}) \
                                        for i in r.instances ]
        while len(reservation.instances) != len(probed_instances):
            sys.stdout.write('.')
            sys.stdout.flush()
            time.sleep(1)
            probed_instances = [i for r in EC2_CONN.get_all_instances(
                                      filters={'reservation_id':reservation.id})
                                      for i in r.instances]

        if options['min_count'] == 1 and 'attach-volumes' in instance_config:
            vol_assignments[reservation.instances[0].id] = \
                            instance_config['attach-volumes']

        if 'create-volumes' in instance_config:
            for device in instance_config['create-volumes']:
                size = instance_config['create-volumes'][device]['size']
                snapshot = instance_config['create-volumes'][device]['snapshot']
                volume_type = instance_config['create-volumes'][device]['type']
                iops = instance_config['create-volumes'][device]['iops']
                new_volume = create_volume(vpc=vpc,
                                           size=size,
                                           zone=options['placement'],
                                           snapshot=snapshot,
                                           volume_type=volume_type,
                                           iops=iops)
                vol_assignments[reservation.instances[0].id] = {device: new_volume.id}

        reservations[instance_config['name']] = reservation

    instances = [ i for r in reservations for i in reservations[r].instances ]
    instance_ids = [ instance.id for instance in instances ]

    #wait until instances not in state 'pending'
    old_count = 0
    while(True):
        try:
            new_reservations = EC2_CONN.get_all_instances(instance_ids=instance_ids)
            new_instances = [ i for r in new_reservations for i in r.instances ]
            instances_pending = [ i for i in new_instances if i.state == 'pending' ]
            if not instances_pending:
                sys.stdout.write('\n')
                sys.stdout.flush()
                break
            if len(instances_pending) != old_count:
                sys.stdout.write('\nwaiting on pending instances: {}'.format(
                                                           instances_pending))
                sys.stdout.flush()
            old_count = len(instances_pending)
        except EC2ResponseError:
            pass
        sys.stdout.write('.')
        sys.stdout.flush()
        time.sleep(1)

    #nat-gateway management
    nat_gateways = [(instance['name'], instance['availability-zone']) \
                                     for instance in instance_configs \
                                     if 'nat-gateway' in instance and \
                                         instance['nat-gateway']]

    nat_gateways = {key: value for (key, value) in nat_gateways}
    for name in reservations:
        for instance in reservations[name].instances:
            if name in nat_gateways:
                EC2_CONN.modify_instance_attribute(instance_id=instance.id,
                                                   attribute='sourceDestCheck',
                                                   value='false')
                tag_taggable(taggable=instance,
                             key='vpcctl-nat-gateway',
                             value=nat_gateways[name])

    if vol_assignments:
        for instance_id in vol_assignments:
            for device in vol_assignments[instance_id]:
                volume_id = vol_assignments[instance_id][device]
                attach_volume(vpc=vpc, volume_id=volume_id,
                              instance_id=instance_id, device=device)

    #tags for instances
    for name in reservations:
        for instance in reservations[name].instances:
            tag_taggable(taggable=instance, key='Name', value=name)
            tag_taggable(taggable=instance, key='vpcctl-i-name', value=name)
            tag_taggable(taggable=instance, tags=tags)
            tag_instance_volumes(vpc=vpc, instance_id=instance.id, tags=tags)

    return instances

@connected('ec2')
@connected('elb')
def create_loadbalancers(vpc, elb_configs, tags=None):
    """
    create ELB load balancers

    :type vpc: :class:`boto.vpc.vpc.VPC`
    :param vpc: instance of a VPC
    :type elb_configs: dict
    :param elb_configs: load balancer configuration
    :type tags: dict
    :param tags: key value pairs to be tagged to instances
    :rtype: list of :class:`boto.ec2.elb.loadbalancer.LoadBalancer`
    :return: List of loadbalancer objects created
    """

    elbs = list()
    if not elb_configs:
        return elbs

    for elb_config in elb_configs:
        listeners = [ tuple(listener) for listener in elb_config['listeners'] ]

        subnets = list()
        for subnet_name in elb_config['subnets']:
            for azone in elb_config['availability-zones']:
                subnet = find_subnet_by_role(vpc, subnet_name, azone)
                if subnet:
                    subnets.append(subnet.id)
        sys.stdout.write('loadbalancer {} getting subnets: {}\n'.format(
                                            elb_config['name'], subnets))
        sys.stdout.flush()
        all_sg_groups = EC2_CONN.get_all_security_groups(
                                     filters={'vpc-id': vpc.id})
        sg_groups = [ sg.id for sg in all_sg_groups \
                                   if sg.name in elb_config['security-groups'] ]
        if not subnets or not listeners or not sg_groups:
            sys.stdout.write('Skipping {} due to no subnets\n'.format(elb_config['name']))
            sys.stdout.flush()
            continue

        elb = ELB_CONN.create_load_balancer(name=elb_config['name'],
                                      listeners=listeners,
                                      zones=None,
                                      subnets=subnets,
                                      security_groups=sg_groups,
                                      scheme=elb_config['scheme'])
        tag_taggable(taggable=elb, tags=tags)
        sys.stdout.write('created {} elastic load balancer {}\n'.format(
                                  elb_config['scheme'], elb))
        sys.stdout.flush()
        reservations = EC2_CONN.get_all_instances(filters={'vpc-id': vpc.id})
        instances = [ i.id for r in reservations            \
                           for i in r.instances             \
                                 if i.tags['vpcctl-i-name'] \
                                 in elb_config['instances'] ]
        if not instances:
            sys.stdout.write('Skipping instances {} due to no instances\n'.format(elb_config['name']))
            sys.stdout.flush()
            continue
            
        ELB_CONN.register_instances(load_balancer_name=elb.name,
                                    instances=instances)
        elbs.append(elb)
    return elbs

#@connected('rds')
def create_database(vpc, db_options, tags=None):
    """
    create RDS database

    :type vpc: :class:`boto.vpc.vpc.VPC`
    :param vpc: instance of a VPC
    :type db_configs: dict
    :param db_configs: database configuration
    :type tags: dict
    :param tags: key value pairs to be tagged to instances
    :rtype: :class:`boto.rds.dbinstance.DBInstance`
    :return: RDS object
    """

    options = db_launch_config(db_options)
    sys.stdout.write('creating database {}: '.format(db_options['name']))
    sys.stdout.flush()
    rds = None
    while(True):
        try:
            rds = RDS_CONN.create_dbinstance(**options)
            break
        except EC2ResponseError:
            sys.stdout.write('.') 
            sys.stdout.flush()
            time.sleep(1)

    while(True):
        try:
            rouses = RDS_CONN.get_all_dbinstances(instance_id=rds.id)
            if len(rouses) == 1:
                rds = rouses[0]
                tag_taggable(taggable=rds, tags=tags)
                break
        except EC2ResponseError:
            sys.stdout.write('.') 
            sys.stdout.flush()
            time.sleep(1)

    sys.stdout.write('\n')
    return rds
          
def create_databases(vpc, db_configs, tags=None):
    """
    create RDS databases

    :type vpc: :class:`boto.vpc.vpc.VPC`
    :param vpc: instance of a VPC
    :type db_configs: list of dict
    :param db_configs: database configurations
    :type tags: dict
    :param tags: key value pairs to be tagged to instances
    :rtype: list of :class:`boto.rds.dbinstance.DBInstance`
    :return: list of RDS objects
    """

    dbs = list()

    for db_config in db_configs:
        dbs.append(create_database(vpc, db_config))

    return dbs

def dotted_delay(delay_sec, message=None):
    """
    delay a specific number of seconds while writing '.' to stdout.

    :type delay_sec: int()'able
    :param delay_sec: seconds to delay
    :type message: str()'able
    :param message: explaination of delay
    """
    try:
        delay = int(delay_sec)
    except ValueError:
        delay = 0

    if delay > 0:
        if message:
            sys.stdout.write(str(message))
        for index in range(0, delay):
            time.sleep(1)
            sys.stdout.write('.')
            sys.stdout.flush()
        sys.stdout.write('\n')
        sys.stdout.flush()

def init_vpc(config, tags):
    """
    create a new VPC

    :type config: dict
    :param config: global configuration
    :type tags: dict
    :param tags: key value pairs to be tagged to instances
    """

    global VPC_CONN
    if not VPC_CONN:
        VPC_CONN = boto.vpc.connect_to_region(region_name=REGION,
                                              aws_access_key_id=ACCESS_KEY,
                                              aws_secret_access_key=SECRET_KEY)
    vpc = VPC_CONN.create_vpc(config['vpc-options']['cidr'])
    tag_taggable(taggable=vpc, tags=tags)

    while vpc.state != 'available':
        try:
            sys.stdout.write("VPC {} is {}\n".format(vpc.id, vpc.state))
            sys.stdout.flush()
            time.sleep(1)
            vpc = vpc.connection.get_all_vpcs([vpc.id])[0]
        except EC2ResponseError:
            pass

    sys.stdout.write("VPC {} is {}\n".format(vpc.id, vpc.state))
    sys.stdout.flush()

    if 'enable-dns-support' in config['vpc-options']:
        enable_dns_support = config['vpc-options']['enable-dns-support']
        vpc.connection.modify_vpc_attribute(vpc_id=vpc.id,
                                      enable_dns_support=enable_dns_support)

    if 'enable-dns-hostnames' in config['vpc-options']:
        enable_dns_hostnames = config['vpc-options']['enable-dns-hostnames']
        vpc.connection.modify_vpc_attribute(vpc_id=vpc.id,
                                      enable_dns_hostnames=enable_dns_hostnames)

    if 'dhcp-options' in config:
        opts = dict()
        if 'domain-name' in config['dhcp-options']:
            opts['domain_name'] = config['dhcp-options']['domain-name']
        if 'domain-name-servers' in config['dhcp-options']:
            opts['domain_name_servers'] = config['dhcp-options']['domain-name-servers']
        dhcp_options = VPC_CONN.create_dhcp_options(**opts)
        tag_taggable(taggable=dhcp_options, tags=tags)
        VPC_CONN.associate_dhcp_options(dhcp_options.id, vpc.id)

    igw = create_internet_gateway(vpc=vpc, tags=tags)
    
    main_route_table = VPC_CONN.get_all_route_tables( \
                                                filters=[('vpc-id', vpc.id)])[0]
    tag_taggable(taggable=main_route_table, tags=tags)
    sys.stdout.write('main route table: {}\n'.format(main_route_table))
    sys.stdout.flush()

    internal_rts = create_internal_routes(vpc=vpc,
                                          av_zones=config['availability-zones'],
                                          tags=tags)
    sys.stdout.write('internal route tables:\n')
    for route in internal_rts:
        tag_taggable(taggable=internal_rts[route], tags=tags)
        sys.stdout.write('    {} {}\n'.format(internal_rts[route].id,
                                              internal_rts[route].vpc_id))
    sys.stdout.flush()

    external_rt = VPC_CONN.create_route_table(vpc.id)
    tag_taggable(taggable=external_rt, tags=tags)
    vpc.connection.create_route(route_table_id=external_rt.id,
                          destination_cidr_block='0.0.0.0/0', gateway_id=igw.id)

    sys.stdout.write('external route table: {} {}\n'.format(external_rt.id,
                                 ', '.join(map(str, external_rt.routes))))
    sys.stdout.flush()

    create_subnets(vpc, config['availability-zones'],
                   external_rt, internal_rts, tags)
    create_security_groups(vpc, config['security-groups'], tags)

    #create nat gateway instances first to facilitate
    #Internet connectivity at internal instance build time
    if 'instances' in config:
        nat_gateway_configs = [ instance_config for instance_config in config['instances'] \
                                                 if 'nat-gateway' in instance_config ]
        non_gateway_configs = [ instance_config for instance_config in config['instances'] \
                                                 if 'nat-gateway' not in instance_config ]

        nat_gateway_instances = create_instances(vpc=vpc,
                                                 instance_configs=nat_gateway_configs,
                                                 config_defaults=config['instance-defaults'],
                                                 ami_options=config['ami-options'],
                                                 tags=tags)

        if 'launch-delay' in config['vpc-options']:
            delay = config['vpc-options']['launch-delay']
        else:
            delay = DEFAULT_DELAY

        if nat_gateway_instances:
            dotted_delay(delay_sec=delay,
                         message='delaying {} seconds for NAT gateway launch'.format(delay))

        non_gateway_instances = \
                 create_instances(vpc=vpc,
                 instance_configs=non_gateway_configs,
                 config_defaults=config['instance-defaults'],
                 ami_options=config['ami-options'],
                 tags=tags)

        instances = nat_gateway_instances + non_gateway_instances

        nat_gateways = [ (i.placement, i) for i in instances \
                                           if 'vpcctl-nat-gateway' in i.tags ]
        nat_gateways = {key: value for (key, value) in nat_gateways}

        for azone in internal_rts:
            if azone in nat_gateways:
                sys.stdout.write('routing {} to {} for {}\n'.format(internal_rts[azone],
                                                                nat_gateways[azone], azone))
                vpc.connection.create_route(internal_rts[azone].id, '0.0.0.0/0',
                                            instance_id=nat_gateways[azone].id)
        sys.stdout.flush()

    if 'load-balancers' in config:
        create_loadbalancers(vpc=vpc, elb_configs=config['load-balancers'])

    if 'databases' in config:
        create_databases(vpc=vpc, db_configs=config['databases'])

def main():
    """
    CLI Driver function
    """

    global ACCESS_KEY
    global SECRET_KEY
    global REGION

    cliargparser = argparse.ArgumentParser(description="AWS VPS Management")
    cliargparser.add_argument('-f', '--file',
                              action="store",
                              help="Configuration file in YAML")
    #cliargparser.epilog = 'Mighty epilog'

    subparsers = cliargparser.add_subparsers(dest='command_subparser',
                                             help='commands')

    initvpc_parser = subparsers.add_parser('initvpc', help='Create a VPC')
    initvpc_parser.add_argument('-n', '--name', action='store',
                                help='Implementation name (tagged)')
    initvpc_parser.add_argument('-d', '--delay', action='store',
                                help='delay in seconds between NAT gateway hosts and dependent hosts')
    initvpc_parser.add_argument('-k', '--key', action='store', help='SSH key')
    initvpc_parser.add_argument('-t', '--tag', action='append',
                                help='arbitrary tag: use key:value format')
    runinstance_parser = subparsers.add_parser('runinstance', help='Run an instance')
    runinstance_parser.add_argument('vpcid', action='store',
                                    help='VPC ID (e.g. vpc-4235bc4)')
    runinstance_parser.add_argument('name', action='store',
                                    help='instance configuration name')
    runinstance_parser.add_argument('-k', '--key', action='store', help='SSH key')
    runinstance_parser.add_argument('-t', '--tag', action='append',
                                    help='arbitrary tag: uuse key:value format')
    runinstance_parser.add_argument('-c', '--count', action='store', type=int,
                                    help='number of instances to launch')

    args = cliargparser.parse_args()

    tags = dict()
    if args.tag:
        for tag in args.tag:
            (key, value) = tag.split(':')
            tags[key] = value

    with open(args.file) as config_fd:
        config = yaml.load(config_fd)

    if 'aws-access-key-id' in config['vpc-options']:
        ACCESS_KEY = config['vpc-options']['aws-access-key-id']
    if 'aws-secret-access-key' in config['vpc-options']:
        SECRET_KEY = config['vpc-options']['aws-secret-access-key']

    if 'region' in config['vpc-options']:
        REGION = config['vpc-options']['region']
        
    if args.name:
        tags['vpcctl-name'] = args.name
    elif 'name' in config:
        tags['vpcctl-name'] = config['name']

    if args.key:
        config['instance-defaults']['key-name'] = args.key

    iam_connection = boto.connect_iam(aws_access_key_id=ACCESS_KEY,
                                      aws_secret_access_key=SECRET_KEY)

    tags['vpcctl-user-arn'] = \
        iam_connection.get_user()['get_user_response']['get_user_result']['user']['arn']
    tags['vpcctl-datestamp'] = time.asctime()

    if args.command_subparser == 'initvpc':
        if args.delay:
            config['vpc-options']['launch-delay'] = args.delay
        if 'launch-delay' not in config['vpc-options']:
            config['vpc-options']['launch-delay'] = DEFAULT_DELAY

        init_vpc(config=config, tags=tags)

    elif args.command_subparser == 'runinstance':
        if args.key:
            config['instance-defaults']['key-name'] = args.key

        vpc = find_vpc(region=config['vpc-options']['region'],
                       access_key=ACCESS_KEY,
                       secret_key=SECRET_KEY,
                       vpc_id=args.vpcid)
        instance_configs = [ instance for instance in config['instances'] \
                                       if instance['name'] == args.name ]
        if args.count:
            for config in instance_configs:
                config['count'] = args.count
        create_instances(vpc=vpc,
                         instance_configs=instance_configs,
                         config_defaults=config['instance-defaults'],
                         ami_options=config['ami-options'],
                         tags=tags)
if __name__ == "__main__":
    main()
