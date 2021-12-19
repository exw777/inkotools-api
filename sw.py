#!/usr/bin/env python3
# sw.py

from easysnmp import snmp_get
from arpreq import arpreq
from icmplib import ping as icmp_ping
from colorama import Fore, Back, Style
import netaddr
import re
import pexpect
import logging
import logging.config
from jinja2 import Environment as j2env
from jinja2 import FileSystemLoader as j2loader
from time import time
import asyncio
import concurrent.futures

from config import config

log = logging.getLogger()
logging.config.dictConfig(config['logger'])

j2 = j2env(loader=j2loader('templates/'))

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
        show:     Print short information about the switch.
        interact: Interact with switch via telnet.
        send:     Send commands to switch via telnet.

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

        # set managment ip for L3 switches
        # we need the first interface in snmp_walk 1.3.6.1.2.1.16.19.11.1.1,
        # but snmp_walk is slower, than hardcoded snmp_get for two models
        if self.model == 'DXS-3600-32S':
            o = '5120'
        elif self.model == 'DGS-3627G':
            o = '5121'
        else:
            o = None
        if o:
            self.mgmt_ip = netaddr.IPAddress(self.get_oid(
                f'1.3.6.1.2.1.16.19.11.1.1.{o}'))
        else:
            self.mgmt_ip = self.ip

        if not self.mgmt_ip in NETS:
            log.warning(f'Address {self.ip} is out of inkotel switches range')

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
                log.warning(f"Can't get mac for {self.ip}, using: {self.mac}")
        log.debug(f'[{self.ip}] switch object created')

    class UnavailableError(Exception):
        """Custom exception when switch is not available"""
        pass

    def is_alive(self):
        """Check if switch is available via icmp"""
        result = ping(self.ip).is_alive
        return result

    def get_oid(self, oid):
        """Get snmp oid from switch"""
        return snmp_get(oid, hostname=str(self.ip),
                        version=2, timeout=3).value

    def show(self, full=False):
        """Print short switch description

        Arguments:

        full: Boolean. If set, print additional line with mac address.
        """
        if self.model in MODEL_COLORS:
            model_color = MODEL_COLORS[self.model]
        else:
            model_color = MODEL_COLORS['DEFAULT']
        short_line = Fore.YELLOW + self.model + Fore.RESET + \
            ' [' + Fore.CYAN + short_ip(self.mgmt_ip) + Fore.RESET + '] ' + \
            model_color + self.location + Fore.RESET + Style.RESET_ALL

        full_line = short_line + '\n' + \
            Fore.RESET + Style.DIM + str(self.mac) + Style.RESET_ALL

        return short_line if not full else full_line

    def _telnet(self):
        """Connect via telnet and keep connection in returned object"""

        # HARDCODE: huawey is restricted for telnet connection
        if self.model == 'S5328C-EI-24S':
            log.error(f'huawey is restricted for telnet connection')
            return None

        # check that connection is not established
        if not hasattr(self, '_connection') or not self._connection.isalive():
            # set credentials
            if re.search('DXS|3627G', self.model):
                creds = config['secrets']['admin_profile']
            else:
                creds = config['secrets']['user_profile']

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
                               timeout=120, encoding="utf-8")

            tn.expect('ame:|in:')
            tn.send(creds['login']+'\r')
            tn.expect('ord:')
            tn.send(creds['password']+'\r')
            # asking login again - wrong password
            if tn.expect([prompt, 'ame:|in:']) == 1:
                log.critical('Wrong password!')
                exit(f"Verify contents of 'secrets.yml' and try again.")
            else:
                # calculate full prompt-line for further usage
                self._prompt = tn.before.split()[-1] + prompt

            self._connection = tn
            log.debug(f'[{self.ip}] new telnet connection')
        else:
            log.debug(f'[{self.ip}] telnet already connected')
        return self._connection

    def _close_telnet(self):
        """Close telnet connection"""
        if hasattr(self, '_connection'):
            self._connection.close()
            log.debug(f'[{self.ip}] telnet connection closed')

    def interact(self):
        """Interact with switch via telnet"""
        tn = self._telnet()
        if not tn:
            log.debug('telnet object is empty')
            return None
        print(self.show())
        # set terminal title
        term_title = f'[{short_ip(self.ip)}] {self.location}'
        print(f'\33]0;{term_title}\a', end='', flush=True)
        tn.interact()
        print('\nInteraction completed')

    def send(self, commands=[], template=None, **kwargs):
        """Send commands to switch

        Arguments:

        commands: It can be one command, list of commands, or plain text,
                  where commands are separated by newlines or symbols ';'.

        template: Load commands from j2 file of templates directory.
                  If specified, commands argument is ignored.

        Returns: Result of running commands as plain text.
        """

        if template:
            log.debug(f'template: {template}')
            log.debug(f'kwargs: {kwargs}')
            try:
                commands = j2.get_template(template).render(sw=self, **kwargs)
            except Exception as e:
                log.error(f'Template {template} loading error: {str(e)}')

        # exit on empty commands
        if not commands:
            log.warning(f'[{self.ip}] empty commands list')
            return None

        log.debug(f'raw commands: {commands}')

        # if commands are plain text, split it to list, and trim extra spaces
        if type(commands) is not list:
            commands = list(
                map(str.strip, commands.replace('\n', ';').split(';')))
            log.debug(f'converted commands: {commands}')

        tn = self._telnet()
        if not tn:
            log.debug('telnet object is empty')
            return None

        output = ''
        for cmd in commands:
            # skip empty commands
            if not cmd:
                continue
            log.debug(f'command: {cmd}')
            tn.sendline(cmd)
            # gpon doesn't work without next line
            if re.search('GEPON|LTP-8X', self.model):
                tn.send('\r')

            # on dlink cli skip writing to output command confirmation
            if re.search('DGS|DES', self.model):
                tn.expect('Command:')
            tn.expect(self._endline)

            # regex for cisco cli configure terminal mode
            conf_t = self._prompt[:-1]+'\([a-z0-9-/]+\)#'

            # dict of expectations and key responses for them
            # prompt - break expect loop
            # All/More - page processing
            # Refresh - quit from monitoring
            # [y/n] (ignore case) - saving in cisco cli
            # ]? DXS-3600 confirm tftp backup
            page_exp = {
                self._prompt: 'break',
                conf_t: 'break',
                '(?i)all': 'a',
                'More': ' ',
                'Refresh': 'q',
                '(?i)y/n]:': 'y\r',
                ']\?': '\r',
            }
            cmd_out = ''
            while True:
                match = tn.expect(list(page_exp.keys()))
                cmd_out += tn.before
                send_key = list(page_exp.values())[match]
                if send_key == 'break':
                    break
                else:
                    tn.send(send_key)
            log.debug(f'output: {cmd_out}')
            output += cmd_out

        # return result of commands
        return output.strip()

    def __del__(self):
        # close telnet connection on class destruction
        self._close_telnet()
        log.debug(f'[{self.ip}] switch object destroyed')

    def backup(self, **kwargs):
        """Backup via tftp

        Optional arguments:

            server: Default is 250 host of switch subnet.

            path:   Default is 'backup'.

        Returns: True if file transfer is successful,
                 raw result otherwise.
        """
        start = time()
        try:
            result = self.send(template='backup.j2', **kwargs)
        except Exception as e:
            log.error(f'[{self.ip}] backup error: {e}')
            return None
        end = time() - start
        r = ' successful|Success|finished|complete|Upload configuration.*Done'
        if result and re.search(r, result):
            log.info(f'[{self.ip}] backup sent in {end:.2f}s')
            return True
        else:
            log.error(f'[{self.ip}] backup result is: {result}')
            return result

    def save(self):
        """Save config"""
        start = time()
        try:
            result = self.send(template='save.j2')
        except Exception as e:
            log.error(f'[{self.ip}] saving error: {e}')
            return None
        end = time() - start
        r = 'Done|Success|OK| success'
        if result and re.search(r, result):
            log.info(f'[{self.ip}] saved in {end:.2f}s')
            return True
        else:
            log.error(f'[{self.ip}] wrong saving result: {result}')
            return result

    def get_acl(self, port=None):
        """Get acl from switch

        If port is not defined, returns all entries
        """
        try:
            result = self.send(template='acl.j2', port=port)
        except Exception as e:
            log.error(f'[{self.ip}] get acl error: {e}')
            return None
        if not result:
            return None
        if re.search('QSW', self.model):
            # q-tech
            regex = (r'Interface Ethernet1/(?P<port>\d{1,2})'
                     r'\s+am port\s+am ip-pool\s+'
                     r'(?P<ip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})')
        else:
            # d-link
            regex = (r'source_ip\s+'
                     r'(?P<ip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})'
                     r'.+port\s+(?P<port>\d{1,2})')
        result = [(m.group('port'), m.group('ip'))
                  for m in re.finditer(regex, result)]
        return result

    def add_acl(self, port, ip):
        """Add acl to switch port"""
        try:
            result = self.send(template='acl.j2', port=port, ip=ip)
        except Exception as e:
            log.error(f'[{self.ip}] add acl error: {e}')
            return False
        if re.search('ERROR|[Ff]ail', result):
            log.error(f'[{self.ip}] failed to add acl {ip} port {port}')
            return False
        else:
            return True

    def delete_acl(self, port):
        """Delete acl from switch port"""
        try:
            result = self.send(template='acl.j2', port=port, ip=None)
        except Exception as e:
            log.error(f'[{self.ip}] delete acl error: {e}')
            return False
        if re.search('ERROR|[Ff]ail', result):
            log.error(f'[{self.ip}] failed to delete acl {ip} port {port}')
            return False
        else:
            return True

    def set_acl(self, port, ip):
        """Set acl to switch port

        Overwrites value if entry exists
        """
        if self.get_acl(port=port):
            self.delete_acl(port=port)
        try:
            result = self.send(template='acl.j2', port=port, ip=ip)
        except Exception as e:
            log.error(f'[{self.ip}] set acl error: {e}')
            return False
        if re.search('ERROR|[Ff]ail', result):
            log.error(f'[{self.ip}] failed to set acl {ip} port {port}')
            return False
        else:
            return True


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


async def batch_async(sw_list, func, external=False, max_workers=1024):
    """Asyncio batch processing for list of switches

    Run: asyncio.run(batch_async(*args))

    Arguments:

        sw_list:    list of switches ip addresses

           func:    string with name of internal method of Switch class
                    or function object for external function (see below)

    Optional arguments:

        external:   boolean value, if set to True, external function 
                    expected in 'func' argument. Required arg is 'sw',
                    which is Switch class instance.
                    default: False

     max_workers:   max count of parallel threads used in asyncio 
                    default: 1024
    """

    with concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix='sw') as pool:
        loop = asyncio.get_running_loop()
        jobs = []

        for ip in sw_list:
            try:
                sw = Switch(ip)
            except Switch.UnavailableError as e:
                log.warning(e)
            except Exception as e:
                log.error(f'{ip}: {e}')
            else:
                if external:
                    args = [func, sw]
                else:
                    args = [eval(f'sw.{func}')]
                jobs.append(loop.run_in_executor(pool, *args))

        try:
            await asyncio.gather(*jobs, return_exceptions=False)
        except Exception as e:
            log.error(f'async error: {e}')

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
    @click.option('--full', is_flag=True, help='Show additional info.')
    def show(ctx, full):
        """Print short switch description"""
        print(ctx.obj.show(full=full))

    @cli.command()
    @click.pass_context
    def connect(ctx):
        """Interact with switch via telnet"""
        ctx.obj.interact()

    @cli.command(context_settings=dict(
        ignore_unknown_options=True,
        allow_extra_args=True,
    ))
    @click.pass_context
    @click.argument('arg')
    @click.option('--file', is_flag=True, help='Use template file.')
    def send(ctx, arg, file):
        """Send CMD to switch via telnet"""
        if file:
            # parse extra params for template
            params = dict()
            from ast import literal_eval
            for item in ctx.args:
                p = item.split('=')
                params[p[0]] = literal_eval(p[1])
            print(ctx.obj.send(template=arg, **params))
        else:
            print(ctx.obj.send(commands=arg))

    @cli.command()
    @click.pass_context
    @click.argument('oid')
    def snmp(ctx, oid):
        """SNMP get OID from switch"""
        print(ctx.obj.get_oid(oid))

    cli()
