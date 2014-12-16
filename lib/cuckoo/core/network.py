# Copyright (C) 2010-2014 ESET Inc.

import logging

from lib.cuckoo.common.abstracts import LibVirtMachinery
import libvirt

log = logging.getLogger(__name__)

#
# The network manager shall be used to manage ip address allocation in
# different networks.
#
class NetworkManager:
    def __init__(self):
        pass

    def add_network(self, network_name, ipmanager):
        pass

    def allocate_ip(self, network_name, mac_address):
        pass

    def release_ip(self, network_name, ip_address):
        pass

#
# The ip address manager is used to allocate / release ip address lease for
# a virtual machine on a specific network, managed by the leasedb backend.
#
class IPManager:
    def __init__(self, leasedb):
        self.leasedb = leasedb

    # Allocate a unique ip address for the specified mac address
    def allocate(self, mac_address):
        # FIXME - Prone to race condition
        ip_address = self.leasedb.get_free_ip()

        lease = StaticLease(ip_address, mac_address)
        self.leasedb.add(lease)

        return lease

    # Release this ip address
    def release(self, ip_address):
        lease = self.leasedb.get_by_ip(ip_address)
        self.leasedb.del(lease)
        return lease

#
# A static lease is simply an association of an ip address <-> mac address
#
class StaticLease:
    def __init__(self, ip, mac):
        self.ip = ip
        self.mac = mac

    def __str__(self):
        return self.mac + "\t" + self.ip

#
# A lease database is a place where we can reserve an ip address for a specifc
# mac address.
#
class LeaseDB:
    def __init__(self, network):
        pass

    def add(self, lease):
        pass

    def del(self, lease):
        pass

    def get_by_ip(self, ip):
        pass

    def get_by_mac(self, mac):
        pass

    def get_free_ip(self):
        pass

#
# Manage the lease database from Libvirt
#
def Libvirt_LeaseDB(LeaseDB):
    #
    # `network` is a Libvirt network object
    # e.g. result from `c.networkLookupByName("default")`
    #
    def __init__(self, network):
        self.network = network

        (self.ip_to_mac_leases, self.mac_to_ip_leases) = self._parse_xml_file()

    def add(self, lease):
        self.ip_to_mac_leases[lease.ip] = lease.mac
        self.mac_to_ip_leases[lease.mac] = lease.ip

        xml_line = self._build_xml_line(lease)

        self.network.update(libvirt.VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST, libvirt.VIR_NETWORK_SECTION_IP_DHCP_HOST, -1, xml_line, libvirt.VIR_NETWORK_UPDATE_AFFECT_LIVE|libvirt.VIR_NETWORK_UPDATE_AFFECT_CONFIG)

        return lease

    def del(self, lease):
        xml_line = self._build_xml_line(lease)
        self.network.update(libvirt.VIR_NETWORK_UPDATE_COMMAND_DELETE, libvirt.VIR_NETWORK_SECTION_IP_DHCP_HOST, -1, xml_line, libvirt.VIR_NETWORK_UPDATE_AFFECT_LIVE|libvirt.VIR_NETWORK_UPDATE_AFFECT_CONFIG)

        del self.ip_to_mac_leases[lease.ip]
        del self.mac_to_ip_leases[lease.mac]

        return lease

    def get_by_ip(self, ip):
        if ip in self.ip_to_mac_leases:
            return StaticLease(ip, self.ip_to_mac_leases[ip])
        return None

    def get_by_mac(self, mac):
        if mac in self.mac_to_ip_leases:
            return StaticLease(self.mac_to_ip_leases[mac], mac)
        return None

    def get_free_ip(self):
        network = "192.168.122."
        for i in range(100, 254):
            ip = network + str(i)
            if not self.get_by_ip(ip):
                return ip
        raise Exception("could not find a free ip, subnet is full")

    def _parse_xml_file(self):
        ip_to_mac_leases = {}
        mac_to_ip_leases = {}

        tree = ET.fromstring(network.XMLDesc(0))
        hosts = tree.findall("./ip/dhcp/host")
        for host in hosts:
            ip_to_mac_leases[host.attrib["ip"]] = host.attrib["mac"]
            mac_to_ip_leases[host.attrib["mac"]] = host.attrib["ip"]

        return (ip_to_mac_leases, mac_to_ip_leases)

    def _build_xml_line(self, lease):
        return "<host mac='" + lease.mac + "' ip='" + lease.ip + "' />"
