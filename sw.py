#!/usr/bin/env python3
# sw.py

from easysnmp import snmp_get, snmp_set, snmp_walk
from arpreq import arpreq
from icmplib import ping as icmp_ping
from colorama import Fore, Back, Style
import netaddr
import re

NETS = netaddr.IPSet(netaddr.IPRange('192.168.57.1', '192.168.57.249')) |\
    netaddr.IPSet(netaddr.IPRange('192.168.58.2', '192.168.58.249')) |\
    netaddr.IPSet(netaddr.IPRange('192.168.59.2', '192.168.59.249')) |\
    netaddr.IPSet(netaddr.IPRange('192.168.60.2', '192.168.60.249')) |\
    netaddr.IPSet(netaddr.IPRange('192.168.47.2', '192.168.47.249')) |\
    netaddr.IPSet(netaddr.IPRange('192.168.49.2', '192.168.49.249'))

MODEL_COLORS = {'DXS-3600-32S': Fore.RED + Style.BRIGHT,
                'DGS-3627G': Fore.YELLOW + Style.BRIGHT,
                'DGS-3120-24SC': Fore.GREEN + Style.BRIGHT,
                'DXS-1210-12SC/A2': Fore.BLUE + Style.BRIGHT,
                'DXS-1210-28S': Fore.BLUE + Style.BRIGHT,
                'LTP-8X': Fore.CYAN + Style.BRIGHT,
                'DXS-1210-12SC/A1': Fore.BLUE + Style.DIM,
                'GEPON': Style.DIM,
                'S5328C-EI-24S': Style.DIM,
                'DEFAULT': Fore.GREEN,
                }


class Switch:
    """Simple switch class

    Atributes:
        ip:       IP address in netaddr.IPAddress format.
        mac:      MAC address in netaddr.EUI format.
        model:    Switch model.
        location: System location.

    Methods:
        is_alive: Boolean value, whether the switch is available by icmp.
        get_oid:  Get snmp oid value from the switch.
        print:    Print short information about the switch.

    Exceptions:
        UnavailableError: Raises on init if the switch is unavailable.
    """

    def __init__(self, ip, check_icmp=False):
        """Init of switch class

        Arguments:

        ip: Any format of IP address, supported by netaddr.

        check_icmp: Boolean value (default is false). If set to true,
                    additionally uses icmp to init check availability
                    of the switch if arp check failed. Takes more time.
                    For example, with batch processing of 1375 switches, 
                    the difference between arp and icmp is 21s vs 2m-17s

        """
        self.ip = netaddr.IPAddress(ip)
        if not self.ip in NETS:
            # raise ValueError(
            #     f'address {self.ip} is out of inkotel switches range')
            print(f'WARN: address {self.ip} is out of inkotel switches range')
        try:  # first, check availability via arp, it is faster
            self.mac = netaddr.EUI(arpreq(self.ip))
        except TypeError:  # if arpreq returns None
            if check_icmp:
                if self.is_alive():  # check availability via icmp
                    self.mac = netaddr.EUI(0)
                    print(f"WARN: can't get mac via arp, using: {self.mac}, "
                          f"maybe you aren't in the same vlan with {self.ip}")
                else:
                    self._raise_unavailable()
            else:
                self._raise_unavailable()
        self.model = re.search('[A-Z]{1,3}-?[0-9]{1,4}[^ ]*|GEPON',
                               self.get_oid('1.3.6.1.2.1.1.1.0'))[0]
        # Add HW revision for DXS-1210-12SC
        if self.model == 'DXS-1210-12SC':
            self.model += '/' + self.get_oid('1.3.6.1.2.1.47.1.1.1.1.8.1')
        self.location = self.get_oid('1.3.6.1.2.1.1.6.0')

    class UnavailableError(Exception):
        """Custom exception when switch is not available"""
        pass

    def _raise_unavailable(self):
        raise self.UnavailableError(f'Host {str(self.ip)} is not available!')

    def is_alive(self):
        """Check if switch is available via icmp"""
        result = ping(self.ip).is_alive
        return result

    def get_oid(self, oid):
        """Get snmp oid from switch"""
        return snmp_get(oid, hostname=str(self.ip), version=2).value

    def print(self):
        """Print short switch description"""
        if self.model in MODEL_COLORS:
            model_color = MODEL_COLORS[self.model]
        else:
            model_color = MODEL_COLORS['DEFAULT']
        print(Fore.YELLOW + self.model + Fore.RESET +
              ' [' + Fore.CYAN + short_ip(self.ip) + Fore.RESET + '] ' +
              model_color + self.location + Fore.RESET + Style.RESET_ALL)
        # print(Fore.RESET + Style.DIM + str(self.mac) + Style.RESET_ALL)


def ping(ip):
    """Ping with one packet"""
    result = icmp_ping(str(ip), count=1, timeout=1, privileged=False)
    return result


def full_ip(ip):
    """Convert x.x to 192.168.x.x"""
    rx = r'([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
    return re.sub(rf'^({rx}\.{rx})$', '192.168.\g<1>', str(ip))


def short_ip(ip):
    """Convert 192.168.x.x to x.x"""
    rx = r'([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
    return re.sub(rf'^192\.168\.({rx}\.{rx})$', '\g<1>', str(ip))


if __name__ == '__main__':
    import argparse

    argp = argparse.ArgumentParser(
        description='Show information about switch')
    argp.add_argument('ip', type=str)
    argp.add_argument('--icmp', action='store_true')

    # argcmd = argp.add_subparsers(dest='command')
    # argcmd.add_parser('show')

    args = argp.parse_args()
    sw = Switch(full_ip(args.ip), bool(args.icmp))
    sw.print()
