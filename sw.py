#!/usr/bin/env python3
# sw.py

from easysnmp import snmp_get, snmp_set, snmp_walk
from arpreq import arpreq
from icmplib import ping as icmp_ping
import netaddr
import re

NETS = netaddr.IPSet(netaddr.IPRange('192.168.57.1', '192.168.57.249')) |\
    netaddr.IPSet(netaddr.IPRange('192.168.58.2', '192.168.58.249')) |\
    netaddr.IPSet(netaddr.IPRange('192.168.59.2', '192.168.59.249')) |\
    netaddr.IPSet(netaddr.IPRange('192.168.60.2', '192.168.60.249')) |\
    netaddr.IPSet(netaddr.IPRange('192.168.47.2', '192.168.47.249')) |\
    netaddr.IPSet(netaddr.IPRange('192.168.49.2', '192.168.49.249'))


def ping(ip):
    result = icmp_ping(str(ip), count=1, timeout=1, privileged=False)
    return result


class Switch:
    def __init__(self, ip):
        self.ip = netaddr.IPAddress(ip)
        if not self.ip in NETS:
            # raise ValueError(
            #     f'address {self.ip} is out of inkotel switches range')
            print(f'WARN: address {self.ip} is out of inkotel switches range')
        try:  # first, check availability via arp, it is faster
            self.mac = netaddr.EUI(arpreq(self.ip))
        except TypeError:  # if arpreq returns None
            if self.is_alive():  # check availability via icmp
                self.mac = netaddr.EUI(0)
                print(f"WARN: can't get mac via arp, using: {self.mac}, "
                      f"probably you are not in the same vlan with {self.ip}")
            else:
                raise Exception(f"Host {self.ip} is not available")
        self.model = re.search('[A-Z]{1,3}-?[0-9]{1,4}[^ ]*|GEPON',
                               self.get_oid('1.3.6.1.2.1.1.1.0'))[0]
        self.location = self.get_oid('1.3.6.1.2.1.1.6.0')

    def is_alive(self):
        result = ping(self.ip).is_alive
        return result

    def get_oid(self, oid):
        return snmp_get(oid, hostname=str(self.ip), version=2).value
