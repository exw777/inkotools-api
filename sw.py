#!/usr/bin/env python3
# sw.py

from easysnmp import snmp_get
from arpreq import arpreq
from icmplib import ping as icmp_ping
from colorama import Fore, Back, Style
from contextlib import contextmanager
import netaddr
import re
import pexpect
import yaml

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
SECRETS_FILE = 'config/secrets.yml'
# load secrets from file
try:
    with (open(SECRETS_FILE, 'r')) as f:
        SECRETS = yaml.safe_load(f)['secrets']
except FileNotFoundError as e:
    print(Fore.RED + str(e) + Fore.RESET)
    s = Fore.YELLOW + SECRETS_FILE.replace('.yml', '.sample.yml') + Fore.RESET
    print(f"You must provide yaml file with secrets. See '{s}' for example.")
    exit(e.errno)


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

    def __init__(self, ip):
        """Init of switch class

        Arguments:

        ip: Any format of IP address, supported by netaddr.
        """
        # set ip address
        self.ip = netaddr.IPAddress(ip)
        if not self.ip in NETS:
            # raise ValueError(
            #     f'address {self.ip} is out of inkotel switches range')
            print(f'WARN: address {self.ip} is out of inkotel switches range')

        # check availability
        # arpreq is faster than icmp, but only works when
        # there is a corresponding entry in the local arp table
        if not (arpreq(self.ip) or self.is_alive()):
            raise self.UnavailableError(
                f'Host {str(self.ip)} is not available!')

        # set model
        self.model = re.search('[A-Z]{1,3}-?[0-9]{1,4}[^ ]*|GEPON',
                               self.get_oid('1.3.6.1.2.1.1.1.0'))[0]
        # add HW revision for DXS-1210-12SC
        if self.model == 'DXS-1210-12SC':
            self.model += '/' + self.get_oid('1.3.6.1.2.1.47.1.1.1.1.8.1')

        # set system location
        self.location = self.get_oid('1.3.6.1.2.1.1.6.0')

        # set mac address
        # first, try via arp, second via snmp
        try:
            self.mac = netaddr.EUI(arpreq(self.ip))
        except TypeError:
            # most of dlink and qtech have special self-mac interface
            # for DXS-1210-12SC (both A1 and A2 revisions) we use mac
            # of the first port, which differs from the self-mac by 1
            # HUAWEY and both models of GPON are not supported yet
            if re.search('DXS-1210-12SC', self.model):
                o = '1'
            elif re.search('QSW', self.model):
                o = '3001'
            elif re.search('3600|3526', self.model):
                o = '5120'
            elif re.search('DES|DGS|DXS', self.model):
                o = '5121'
            else:
                o = None
            # easysnmp returns mac in OCTETSTR type, which is a string
            # of characters corresponding to the bytes of the mac
            # we need some magic to convert it to netaddr mac
            # byte(char) -> int -> hex -> byte(str)
            if o:
                snmp_mac = self.get_oid(f'1.3.6.1.2.1.2.2.1.6.{o}')
                if re.search('NOSUCH', snmp_mac):
                    snmp_mac = None
                else:
                    self.mac = netaddr.EUI(
                        ':'.join(map(lambda x: hex(ord(x))[2:], snmp_mac)))
                    if o == '1':
                        self.mac = netaddr.EUI((int(self.mac)-1))
            else:
                self.mac = netaddr.EUI(0)
                print(f"WARN: can't get mac for {self.ip}, using: {self.mac}")

    class UnavailableError(Exception):
        """Custom exception when switch is not available"""
        pass

    def is_alive(self):
        """Check if switch is available via icmp"""
        result = ping(self.ip).is_alive
        return result

    def get_oid(self, oid):
        """Get snmp oid from switch"""
        return snmp_get(oid, hostname=str(self.ip), version=2).value

    def show(self):
        """Print short switch description"""
        if self.model in MODEL_COLORS:
            model_color = MODEL_COLORS[self.model]
        else:
            model_color = MODEL_COLORS['DEFAULT']
        print(Fore.YELLOW + self.model + Fore.RESET +
              ' [' + Fore.CYAN + short_ip(self.ip) + Fore.RESET + '] ' +
              model_color + self.location + Fore.RESET + Style.RESET_ALL)
        # print(Fore.RESET + Style.DIM + str(self.mac) + Style.RESET_ALL)

    @contextmanager
    def _connection(self):
        """Wrapper of connection to switch via telnet"""

        # set credentials
        if re.search('DXS|3627G', self.model):
            creds = SECRETS['admin_profile']
        else:
            creds = SECRETS['user_profile']

        # set prompt
        if re.search('DXS-1210-12SC/A1', self.model):
            prompt = '>'
        else:
            prompt = '#'

        # set endline
        if re.search('3627G|3600|3000|3200|3028|3026|3120', self.model):
            self._endline = '\n\r'
        elif re.search('1210|QSW|LTP', self.model):
            self._endline = '\r\n'
        elif re.search('3526', self.model):
            self._endline = '\r\n\r'
        else:
            self._endline = '\r\n'

        # TODO: different timeout for each model
        tn = pexpect.spawn(f'telnet {self.ip}',
                           timeout=45, encoding="utf-8")

        tn.expect('ame:|in:')
        tn.send(creds['login']+'\r')
        tn.expect('ord:')
        tn.send(creds['password']+'\r')
        # asking login again - wrong password
        if tn.expect([prompt, 'ame:|in:']) == 1:
            print(f'{Fore.RED}Wrong password!{Fore.RESET}')
            s = Fore.YELLOW + SECRETS_FILE + Fore.RESET
            exit(f"Verify contents of '{s}' and try again.")
        else:
            # calculate full prompt-line for further usage
            self._prompt = tn.before.split()[-1] + prompt
            # TODO: for cisco cli conf t this is wrong!
        yield tn

        tn.close()

    def interact(self):
        """Interact with switch via telnet"""
        with self._connection() as tn:
            self.show()
            # set terminal title
            term_title = f'[{short_ip(self.ip)}] {self.location}'
            print(f'\33]0;{term_title}\a', end='', flush=True)
            tn.interact()
        print('\nConnection closed')

    def get_command(self, cmd="sh conf cur"):
        """Get result of command"""
        with self._connection() as tn:
            tn.sendline(cmd)

            # skip command confirmation
            # ONLY DLINK CLI
            if re.search('DGS|DES', self.model):
                tn.expect('Command:')
            tn.expect(self._endline)

            # print(f'command was:{tn.before.strip()}')

            output = ''
            while True:
                match = tn.expect([self._prompt, 'All', 'More', 'Refresh'])
                output += tn.before
                if match == 0:
                    break
                elif match == 1:
                    tn.send('a')
                elif match == 2:
                    tn.send(' ')
                elif match == 3:
                    tn.send('q')

            print(output.strip())


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
    import click

    @click.group()
    @click.argument('ip')
    @click.pass_context
    def cli(ctx, ip):
        try:
            ctx.obj = Switch(full_ip(ip))
        except Switch.UnavailableError as e:
            exit(e)

    @cli.command()
    @click.pass_context
    def show(ctx):
        """Print short switch description"""
        ctx.obj.show()

    @cli.command()
    @click.pass_context
    def connect(ctx):
        """Interact with switch via telnet"""
        ctx.obj.interact()

    @cli.command()
    @click.pass_context
    @click.argument('cmd')
    def send(ctx, cmd):
        """Send CMD to switch via telnet"""
        ctx.obj.get_command(cmd)

    cli()
