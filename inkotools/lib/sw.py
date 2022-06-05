#!/usr/bin/env python3
# lib/sw.py

# internal imports
import asyncio
import concurrent.futures
import inspect
import logging
import re
import socket
from time import time

# external imports
import netaddr
import pexpect
from jinja2 import Environment as j2env
from jinja2 import FileSystemLoader as j2loader

# local imports
from .cfg import ROOT_DIR, COMMON, SECRETS, NETS, PIP_NETS

# module logger
log = logging.getLogger(__name__)

# dynamic imports for normal mode
if COMMON['tcp_only_mode']:
    log.debug('Working in tcp-only mode')
else:
    from arpreq import arpreq
    from easysnmp import snmp_get
    from icmplib import ping as icmp_ping

# simple ip regexp
RGX_IP = r'(?:\d{1,3}\.){3}\d{1,3}'


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

    def __init__(self, ip, model=None, location=None, mac=None):
        """Init of switch class

        Arguments:

        ip: Any format of IP address, supported by netaddr.
        """

        # logger with ip name
        self.log = logging.getLogger(str(ip))

        # set ip address
        self.ip = netaddr.IPAddress(str(ip))

        # check availability
        if not self.is_alive():
            raise self.UnavailableError(
                f'Host {str(self.ip)} is not available!')

        # tcp only mode for proxychains use
        if COMMON['tcp_only_mode']:
            # first try to get data provided via class constructor
            self.model = model
            self.location = location
            self.mac = mac

            # set model via telnet
            if self.model is None:
                self._setup_telnet_model()

            # get mac and location via telnet
            if self.location is None or self.mac is None:
                if re.search(r'DES|DGS|DXS-1210-12SC', self.model):
                    raw = self.send('sh sw')
                elif re.search(r'DXS', self.model):
                    raw = self.send(['sh mac-address-table static vlan 1',
                                     'sh snmp-server'])
                elif re.search(r'QSW', self.model):
                    raw = self.send(['sh mac-address-table static vlan 1',
                                     'sh snmp status'])
                elif re.search(r'LTP', self.model):
                    raw = self.send(['show system environment',
                                     'show ip snmp'])
                elif self.model == 'GEPON':
                    raw = self.send('show system infor')
                elif self.model == 'GP3600-04':
                    raw = self.send(['sh ver', 'sh conf | inc location'])

                rgx_mac = r'(?P<mac>(?:\w\w[-:]){5}\w\w)'
                rgx_loc = r'[Ll]ocation *:? *[\'"]?(?P<loc>.*\w)?'

                self.location = re.search(rgx_loc, raw).group('loc')
                self.mac = netaddr.EUI(re.search(rgx_mac, raw).group('mac'))

        # normal mode
        else:
            # set model
            self.model = re.search(r'[A-Z]{1,3}-?[0-9]{1,4}[^ ]*|GEPON',
                                   self.get_oid('1.3.6.1.2.1.1.1.0'))[0]
            # add HW revision for DXS-1210-12SC
            if self.model == 'DXS-1210-12SC':
                self.model += '/' + self.get_oid('1.3.6.1.2.1.47.1.1.1.1.8.1')

            # set system location
            self.location = self.get_oid('1.3.6.1.2.1.1.6.0')

            # set mac address
            # first, try via arp, second via snmp (for routed ips)
            try:
                if not arpreq(self.ip):
                    # ping to update arp table
                    ping(self.ip)
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
                elif re.search(r'DXS-3600|3526', self.model):
                    o = '5120'
                elif re.search(r'DES|DGS|DXS', self.model):
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
                    self.log.warning(
                        f"Can't get mac for {self.ip}, using: {self.mac}")

        # get max ports from switch model and set transit and access ports
        max_ports = re.findall(r'(?:.*)(\d{2})(?:.*$)', self.model)
        if max_ports:
            max_ports = int(max_ports[0])
        self.access_ports = []
        self.transit_ports = []
        if re.search(r'DES|QSW|3000|DGS-1210', self.model):
            self.access_ports = list(range(1, (max_ports//8)*8 + 1))
            self.transit_ports = list(
                range(self.access_ports[-1] + 1, max_ports + 1))
        elif re.search(r'DXS|DGS', self.model):
            if max_ports > 24:
                self.transit_ports = list(range(1, 25))
            else:
                self.transit_ports = list(range(1, max_ports + 1))

        # for l3 switches set self ip from managment vlan
        if self.ip not in NETS:
            if re.search('DXS', self.model):
                raw = self.send('sh ip interface vlan 1')
                rgx = r'(?P<ip>(?:\d+\.){3}\d+)'
            elif re.search('DGS', self.model):
                raw = self.send('sh sw')
                rgx = r'IP Address +: (?P<ip>(?:\d+\.){3}\d+)'
            self.ip = netaddr.IPAddress(re.search(rgx, raw).group('ip'))
            self.log = logging.getLogger(str(self.ip))

        self.log.debug(f'switch object created: [{self.ip}] '
                       f'[{self.mac}] [{self.model}] [{self.location}]')

    class UnavailableError(Exception):
        """Custom exception when switch is not available"""
        pass

    class CredentialsError(Exception):
        """Custom exception on wrong creds"""
        pass

    class ModelError(Exception):
        """Custom exception on unsupported model"""
        pass

    def _models(supported='', restricted=''):
        """Supported models decorator"""
        def decorator(func):
            def wrapper(self, *args, **kwargs):

                if isinstance(supported, list):
                    is_supported = True if self.model in supported else False
                elif supported != '':
                    is_supported = bool(re.search(supported, self.model))
                else:
                    is_supported = True

                if isinstance(restricted, list):
                    is_restricted = True if self.model in restricted else False
                elif restricted != '':
                    is_restricted = bool(re.search(restricted, self.model))
                else:
                    is_restricted = False

                if not is_supported or is_restricted:
                    raise self.ModelError(f'Model {self.model} not supported')

                return func(self, *args, **kwargs)

            return wrapper
        return decorator

    def help(self):
        """List all public methods with args"""
        methods = {}
        for m in inspect.getmembers(self, inspect.ismethod):
            if not m[0].startswith('_'):
                methods[m[0]] = str(inspect.signature(eval(f'self.{m[0]}')))
        return methods

    def is_alive(self):
        """Check if switch is available

        check availability: arp --> icmp --> telnet
        arpreq is faster than icmp, but only works when
        there is a corresponding entry in the local arp table
        first two check are skipping in no-snmp mode
        """
        if not COMMON['tcp_only_mode']:
            if arpreq(self.ip) or ping(self.ip).is_alive:
                return True
        # third check is via tcp port 80 (web) and 23 (telnet)
        for p in [80, 23]:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((str(self.ip), p)) == 0:
                s.close()
                return True
            s.close()
        return False

    def get_oid(self, oid):
        """Get snmp oid from switch"""
        if COMMON['tcp_only_mode']:
            self.error('Calling snmp in tcp-only mode')
            return None
        return snmp_get(oid, hostname=str(self.ip),
                        version=2, timeout=3).value

    def _setup_telnet_model(self):
        """Get model via telnet"""
        tn = pexpect.spawn(f'telnet {self.ip}', timeout=10, encoding="utf-8")
        matches = {
            'DXS-1210-12SC/A1': 'DXS-1210-12SC Switch',
            're':               r'[A-Z]{1,3}-?[0-9]{1,4}[^ ]*',
            'GEPON':            'EPON System',
            'S5328C-EI-24S':    'Login authentication',
            'GP3600-04':        'User Access Verification',
            'QSW-2800-28T-AC':  'in:',
            'unknown':          pexpect.TIMEOUT}
        m = tn.expect(list(matches.values()))
        if m == 1:
            model = tn.after
            if model == 'DXS-1210-12SC':
                model += '/A2'
            elif model == 'DGS-1210-28X/ME':
                model += '/B1'
        else:
            model = list(matches.keys())[m]
        tn.close()
        if model == 'unknown':
            raise RuntimeError('Failed to parse switch model!')
        self.model = model
        # set additional hardware revision for 3200
        if re.search('DES-3200', self.model):
            raw = self.send('sh sw')
            if re.search(r'Hardware Version +: C1', raw):
                self.model += '/C1'
        self.log.debug(f'model: {self.model}')

    @_models(restricted=['S5328C-EI-24S'])  # huawey
    def _telnet(self):
        """Connect via telnet and keep connection in returned object"""

        # check that connection is not established
        if not hasattr(self, '_connection') or not self._connection.isalive():
            # set credentials from secrets config file
            try:
                if re.search(r'DXS|3627G', self.model):
                    creds = SECRETS['admin_profile']
                else:
                    creds = SECRETS['user_profile']
                login = creds['login']
                password = creds['password']
            except KeyError as e:
                raise self.CredentialsError(
                    'Failed to parse secrets config') from e

            # set prompt
            if re.search(r'DXS-1210-12SC/A1|GP3600', self.model):
                prompt = '>'
            else:
                prompt = '#'

            # set endline
            if re.search(r'3627G|DXS-3600|3000|3200|3028|3026|3120',
                         self.model):
                self._endline = '\n\r'
            elif re.search(r'1210|QSW|LTP', self.model):
                self._endline = '\r\n'
            elif re.search('3526', self.model):
                self._endline = '\r\n\r'
            else:
                self._endline = '\r\n'

            self.log.debug('spawning telnet...')
            # codec_errors='ignore' - ignore non-unicode symbols
            tn = pexpect.spawn(f'telnet {self.ip}', timeout=120,
                               encoding='utf-8', codec_errors='ignore')

            login_promt = 'ame:|in:'
            fail_matches = {
                'refused': pexpect.EOF,
                'timed out': pexpect.TIMEOUT,
            }
            fail = tn.expect([login_promt] + list(fail_matches.values()))

            # check failed telnet connection
            if fail != 0:
                msg = f'Connection {list(fail_matches.keys())[fail-1]}'
                self.log.error(msg)
                raise self.UnavailableError(msg)

            # try to login
            tn.send(login+'\r')
            tn.expect('ord:')
            tn.send(password+'\r')
            # asking login again - wrong password
            if tn.expect([prompt, login_promt]) == 1:
                raise self.CredentialsError('Wrong login or password!')
            else:
                # GP3600-04 enable mode
                if self.model == 'GP3600-04':
                    tn.send('su'+'\r')
                    prompt = '#'
                    tn.expect(prompt)
                # calculate full prompt-line for further usage
                self._prompt = tn.before.split()[-1] + prompt

            self._connection = tn
            self.log.debug('telnet connection established')
        else:
            self.log.debug('telnet already connected')
        return self._connection

    def _close_telnet(self):
        """Close telnet connection"""
        if hasattr(self, '_connection'):
            self._connection.close()
            self.log.debug('telnet connection closed')

    def interact(self):
        """Interact with switch via telnet"""
        tn = self._telnet()
        # send empty line to immediately display standard promt
        tn.send('\r')
        tn.interact()

    # REFACTORING NEEDED
    def send(self, commands=[], template=None, **kwargs):
        """Send commands to switch

        Arguments:

        commands: It can be one command, list of commands, or plain text,
                  where commands are separated by newlines or symbols ';'.

        template: Load commands from j2 file of templates directory.
                  If specified, commands argument is ignored.

        kwargs:   Arguments passing into template

        Returns:  Result of running commands as plain text.

        """
        if template:
            self.log.debug(f'template: {template}')
            self.log.debug(f'kwargs: {kwargs}')
            try:
                # render template from templates dir
                j2 = j2env(loader=j2loader(ROOT_DIR/'templates'))
                commands = j2.get_template(template).render(sw=self, **kwargs)
            except Exception as e:
                self.log.error(
                    f'Template `{template}` loading error: {str(e)}')

        # exit on empty commands
        if not commands:
            self.log.warning('empty commands list')
            return ''

        self.log.debug(f'raw commands: {commands}')

        # if commands are plain text, split it to list, and trim extra spaces
        if type(commands) is not list:
            commands = list(
                map(str.strip, commands.replace('\n', ';').split(';')))
            self.log.debug(f'converted commands: {commands}')

        tn = self._telnet()

        output = ''
        for cmd in commands:
            # skip empty and commented commands
            if not cmd or re.search(r'^#', cmd):
                continue
            self.log.debug(f'command: {cmd}')
            tn.sendline(cmd)
            # gpon doesn't work without next line
            if re.search(r'GEPON|LTP-8X', self.model):
                tn.send('\r')

            # on dlink cli skip writing to output command confirmation
            if re.search(r'DGS|DES', self.model):
                match = tn.expect(['Command:', 'Available commands:'])
                # also check for incorrect command
                if match == 1:
                    self.log.error(f'Wrong command: {cmd}')
                    continue

            tn.expect(self._endline)

            # regex for cisco cli configure terminal mode
            conf_t = self._prompt[:-1] + r'\([a-z0-9-/]+\)#'

            # dict of expectations and key responses for them
            # prompt - break expect loop
            # All/More - page processing
            # Refresh - quit from monitoring
            # [y/n] (ignore case) - saving in cisco cli
            # ]? DXS-3600 confirm tftp backup
            # TODO: remove hardcode
            # GP3600 enter backup filename
            backup_path = f"{COMMON['backup_dir']}/{self.ip}.cfg\r"
            page_exp = {
                self._prompt: 'break',
                conf_t: 'break',
                '(?i)all\W': 'a',
                'More': ' ',
                'Refresh': 'q',
                '(?i)y/n]:': 'y\r',
                'Destination file name\[startup-config]\?': backup_path,
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
            self.log.debug(f'output: {cmd_out}')
            output += cmd_out

        # return result of commands
        return output.strip()

    def __del__(self):
        # close telnet connection on class destruction
        self._close_telnet()
        self.log.debug(f'switch object destroyed')

    @_models(restricted=['S5328C-EI-24S', 'GEPON'])
    def backup(self):
        """Backup via tftp

        Returns: string result.
        """
        server = f"192.168.{self.ip.words[2]}.{COMMON['backup_host']}"
        path = COMMON['backup_dir']
        start = time()
        result = self.send(template='backup.j2', server=server, path=path)
        end = time() - start
        r = r'(^|[ :])[Ss]uccess|finished|complete|Upload configuration.*Done'
        if re.search(r, result):
            res = f'backup sent in {end:.2f}s'
            self.log.info(res)
        else:
            res = {'error': f'backup failed: {result}'}
            self.log.error(result)
        return res

    @_models(restricted=['S5328C-EI-24S'])
    def save(self):
        """Save config

        Returns: string result.
        """
        start = time()
        result = self.send(template='save.j2')
        end = time() - start
        r = r'Done|Success|OK| success'
        if result and re.search(r, result):
            res = f'saved in {end:.2f}s'
            self.log.info(res)
        else:
            res = {'error': f'save failed: {result}'}
            self.log.error(result)
        return res

    @_models(r'DES|DGS|QSW|^DXS((?!A1).)*$')
    def get_port_state(self, port: int):
        """Get port state

        Returns:
            list of dicts with len 1 for simple ports and 2 for combo

        Dict:
            port: int           - port number
            type: str           - fiber or copper for combo ports
            state: bool         - administrative state
            speed: str          - port speed settings
            link: bool          - link status
            status: str         - link speed
            learning: bool      - mac learning state
            autodowngrade: bool - speed conf state on DGS switches
            desc: str           - port description
        """

        if re.search('QSW', self.model):
            raw = self.send(f'sh int eth 1/{port}')
            rgx = (
                r'Ethernet1/(?P<port>\d+) is (?P<state>[\w ]+)'
                r', line protocol is (?P<link>\w+)(?s:.*)'
                r'alias name is (?P<desc>.*[^\s]),(?s:.*)'
                r'Hardware is (?P<type>[-\w]+(, active is \w+)?),(?s:.*)'
                r'\s (?P<speed>[\w ,:-]+)\s+Flow'
            )
            res = re.search(rgx, raw).groupdict()
            # some magic to convert values in same format as dlink
            res['state'] = False if re.search(
                'admin', res['state']) else True
            res['link'] = str_to_bool(res['link'])
            if res['desc'] == '(null)':
                res['desc'] = None
            res['type'] = 'F' if re.search('Fiber', res['type']) else 'C'
            r = r'(?:Negotiation|Force) (\w+)'
            res['status'] = '/'.join(reversed(re.findall(r, res['speed'])))
            if re.search('Auto', res['speed']):
                res['speed'] = 'Auto'
            else:
                res['speed'] = res['status']
            if not res['link']:
                res['status'] = None
            res['port'] = int(res['port'])
            # workaround for frontend alarm
            res['learning'] = True

            result = [res]

        elif re.search(r'DES|DGS', self.model):
            raw = self.send(f'sh ports {port} desc')
            rgx = (
                r'(?P<port>\d{1,2})(?:\s*\((?P<type>C|F)\))?\s+'
                r'(?P<state>Enabled|Disabled)\s+'
                r'(?P<speed>Auto|10+\w/(?:Full|Half))/\w+\s+'
                r'(?P<link>Link ?Down|10+\w/(?:Full|Half)|Err[\w-]+)'
                r'(?:/\w+)?\s+'
                r'(?P<learning>Enabled|Disabled)\s+'
                r'(?P<autodowngrade>Enabled|Disabled|-)?'
                r'(?s:.*?)Desc[a-z]*: +(?P<desc>.*[^\s])?'
            )
            result = [m.groupdict() for m in re.finditer(rgx, raw)]
            # convert values
            for res in result:
                if re.search('3000|DGS-1210', self.model):
                    res['autodowngrade'] = str_to_bool(
                        res['autodowngrade'])
                else:
                    # on 3526 this field is trap
                    res['autodowngrade'] = None
                # set bool and str link status
                down = re.search(r'Down|Err', res['link'])
                res['status'] = res['link']
                res['link'] = False if down else True
                # clear status on link down (not error disabled)
                if down and down.group() == 'Down':
                    res['status'] = None
                res['state'] = str_to_bool(res['state'])
                res['learning'] = str_to_bool(res['learning'])
                res['port'] = int(res['port'])
                # set default fiber/copper type depending on the model
                if res['type'] is None:
                    if re.search(r'3627|3120|28F', self.model):
                        res['type'] = 'F'
                    else:
                        res['type'] = 'F' if int(port) > 24 else 'C'

        elif re.search('DXS', self.model):
            raw = self.send(f'sh int eth 1/0/{port}')
            rgx = (
                r'Eth1/0/(?P<port>\d+) is (?P<state>[\w]+?)'
                r',? link status is (?P<link>\w+)(?s:.*)'
                r'description: (?P<desc>.*)(?s:.*)'
                r'MAC(?s:.*?)(?:\r|\n) *(?P<speed>[\w\-\/ \,]+)(?s:.*)'
                r'flow-control(?s:.*?)(?:\r|\n) *(?P<status>[\w\-\/ \,]+)'
            )
            res = re.search(rgx, raw).groupdict()
            if re.search(r'(?i:down)', res['status']):
                res['status'] = None
            else:
                # convert 'Full-duplex, 10Gb/s' -> '10G/Full'
                res['status'] = re.sub(r'(\w+)-duplex, (\d+\w)b/s',
                                       r'\2/\1', res['status'])
            # convert 'Auto-duplex, 10G, auto-mdix' -> '10G/Auto'
            duplex, speed = re.sub(r'-\w+', '', res['speed']).split(', ')[:2]
            if re.match(r'\d+$', speed):
                speed += 'M'
            if duplex.lower() == speed.lower():
                res['speed'] = 'Auto'
            else:
                res['speed'] = f'{speed}/{duplex}'
            res['link'] = str_to_bool(res['link'])
            res['state'] = str_to_bool(res['state'])
            res['port'] = int(res['port'])
            res['learning'] = True
            # DXS-1210-12SC/A2 has combo ports, but no way to test yet
            # other DXS models have only fiber ports
            res['type'] = 'F'
            if res['desc'] == '':
                res['desc'] = None
            result = [res]

        return result

    def get_ports_state(self, ports: list = []):
        """Get multiple ports state

        if ports arg is ommited, returns all ports
        """
        if not ports:
            ports = self.access_ports + self.transit_ports

        # Processing ports one by one because pagination
        # is implemented differently on different switches.
        result = []
        for port in ports:
            res = self.get_port_state(port=port)
            if isinstance(res, list):
                result += self.get_port_state(port=port)
            else:
                result.append(res)

        return result

    def set_port_state(
            self, port: int, state: bool,
            comment: str = "", clear_comment: bool = False):
        """Dummy function, need to rework"""

        if comment == "" and not clear_comment:

            result = self.send(template='port_state.j2',
                               port=port, state=state)
        else:
            result = self.send(template='port_state.j2',
                               port=port, state=state, comment=comment)
        return result

    @_models(r'DES-(?!3026)|DGS-(3000|1210)|QSW')
    def get_acl(self, port: int):
        """Get port acl"""
        if re.search('QSW', self.model):
            raw = self.send(f'sh am int eth 1/{port}')
            rgx = (r'Interface Ethernet1/(?P<port>\d{1,2})'
                   r'\s+am port\s+am ip-pool\s+'
                   rf'(?P<ip>{RGX_IP})')
            res = [dict_fmt_int(m.groupdict()) for m in re.finditer(rgx, raw)]
        # workaround for 1210, which is too slow when requesting config
        elif re.search('1210', self.model):
            rgx = (r'Access ID: (?P<access_id>\d+)\s*'
                   r'Mode: (?P<mode>Permit|Deny)(?:[\s\w:]+)'
                   rf'Ports: (?P<port>{port})\s*'
                   rf'Source IP *: (?P<ip>{RGX_IP}) *'
                   rf'Source IP Mask *: (?P<mask>{RGX_IP})')
            res = []
            # separate command for each profile
            for p_id in [10, 20]:
                raw = self.send(f'show access_profile profile_id {p_id}')
                # manual insert profile_id
                for m in re.finditer(rgx, raw):
                    d = dict_fmt_int(m.groupdict())
                    d['profile_id'] = p_id
                    d['mode'] = d['mode'].lower()
                    res.append(d)
        else:
            raw = self.send(f'sh conf cur inc "port {port} "')
            rgx = (r'profile_id\s+(?P<profile_id>\d+)\s.*'
                   r'access_id\s+(?P<access_id>\d+)\s+.*'
                   rf'source_ip\s+(?P<ip>{RGX_IP})\s*'
                   rf'(.+mask\s+(?P<mask>{RGX_IP}))?'
                   r'\s+port\s+(?P<port>\d{1,2})\s+(?P<mode>\w+)')
            res = [dict_fmt_int(m.groupdict()) for m in re.finditer(rgx, raw)]
            # set default mask
            for i in res:
                if 'mask' in i.keys() and i['mask'] is None:
                    if i['profile_id'] == 10:
                        i['mask'] = '255.255.255.255'
                    elif i['profile_id'] == 20:
                        i['mask'] = '0.0.0.0'
        return res

    def add_acl(self, port, ip):
        """Add acl to switch port"""
        try:
            result = self.send(template='acl.j2', port=port, ip=ip)
        except Exception as e:
            self.log.error(f'add acl error: {e}')
            return False
        if re.search(r'ERROR|[Ff]ail', result):
            self.log.error(f'failed to add acl {ip} port {port}')
            return False
        else:
            return True

    def delete_acl(self, port):
        """Delete acl from switch port"""
        try:
            result = self.send(template='acl.j2', port=port, ip=None)
        except Exception as e:
            self.log.error(f'delete acl error: {e}')
            return False
        if re.search(r'ERROR|[Ff]ail', result):
            self.log.error(f'failed to delete acl {ip} port {port}')
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
            self.log.error(f'set acl error: {e}')
            return False
        if re.search(r'ERROR|[Ff]ail', result):
            self.log.error(f'failed to set acl {ip} port {port}')
            return False
        else:
            return True

    def get_vlan(self, vid=None):
        """Get tagged and untagged ports for vlan

        If vid is not defined, returns all vlans

        Returns: list of dicts:

                    [{'vid': int,
                    'tagged': [int, ...],
                    'untagged': [int, ...]
                    }, ...]
        """
        try:
            result_raw = self.send(template='vlan.j2', vid=vid)
        except Exception as e:
            self.log.error(f'get vlan error: {e}')
            return None
        if not result_raw:
            return None
        result = []
        if re.search('QSW', self.model):
            result_raw = result_raw.replace('\x08', '').replace('-', '')
            regex = (r'\n(?P<vid>\d+)\s+(?:.*Static.*?)'
                     r'(?P<ports>(?:\s+Ethernet.*(?:\s+\r|$))+)')
            for r in re.finditer(regex, result_raw):
                vid = r.group('vid')
                untagged = re.findall(r'Ethernet1/(\d+)(?:\s|$)\s*',
                                      r.group('ports'))
                tagged = re.findall(r'Ethernet1/(\d+)\(T\)(?:\s|$)\s*',
                                    r.group('ports'))
                result.append({'vid': int(vid),
                               'tagged': tagged,
                               'untagged': untagged})
        else:
            regex = (r'VID\s+:\s+(?P<vid>\d+)\s+(?s:.*?)'
                     r'Tagged [Pp]orts\s+:\s+'
                     r'(?P<tagged>[-,0-9]*)\s+(?s:.*?)'
                     r'Untagged [Pp]orts\s+:\s+(?P<untagged>[-,0-9]*)')
            for r in re.finditer(regex, result_raw):
                vid = r.group('vid')
                tagged = interval_to_list(r.group('tagged'))
                untagged = interval_to_list(r.group('untagged'))
                result.append({'vid': int(vid),
                               'tagged': tagged,
                               'untagged': untagged})
        return result

    def get_vlan_list(self):
        """Return list of all vlans"""
        return [v['vid'] for v in self.get_vlan()]

    def add_vlan(self, vid):
        """Add new vlan to switch"""
        vid = int(vid)
        # check vid is valid
        if not vid in range(1, 4095):
            self.log.error(f'vid {vid} out of range')
            return False
        check_vlan = self.get_vlan(vid=vid)
        if check_vlan:
            self.log.error(f'vlan {vid} already exists')
            return False
        elif check_vlan == None:
            self.log.error(f'vlan check failed (wrong model?)')
            return False
        try:
            result = self.send(template='vlan.j2',
                               vid=vid, action='add')
        except Exception as e:
            self.log.error(f'create vlan {vid} error: {e}')
            return False
        if not (re.search('Success', result) or result == ''):
            self.log.error(f'create vlan {vid} failed: {result}')
            return False
        else:
            self.log.info(f'created vlan {vid}')
            return True

    def add_vlans(self, vid_list):
        """Add new vlans to switch"""
        for vid in vid_list:
            self.add_vlan(vid)

    def delete_vlan(self, vid, force=False):
        """Delete vlan from switch"""
        vid = int(vid)
        if vid == 1:
            self.log.error('Cannot delete vid 1')
        check_vlan = self.get_vlan(vid=vid)
        if check_vlan == None:
            self.log.error(f'vlan check failed (wrong model?)')
            return False
        elif check_vlan == []:
            self.log.info(f'vlan {vid} does not exists. Skipping')
            return True
        if check_vlan[0]['untagged'] and not force:
            self.log.error(
                f'vlan {vid} is set untagged on ports: '
                f"{check_vlan[0]['untagged']} Skipping. "
                'Use `force=True` if you are really want to delete it.')
            return False

        try:
            result = self.send(template='vlan.j2',
                               vid=vid, action='delete')
        except Exception as e:
            self.log.error(f'delete vlan {vid} error: {e}')
            return False
        if not (re.search('Success', result) or result == ''):
            self.log.error(f'delete vlan {vid} failed: {result}')
            return False
        else:
            self.log.info(f'deleted vlan {vid}')
            return True

    def delete_vlans(self, vid_list):
        """Delete vlans from switch"""
        for vid in vid_list:
            self.delete_vlan(vid)

    def get_vlan_port(self, port):
        """Get vlan information from port

        Returns: dict:

            {'port': int,
            'untagged': [int,...],
            'tagged': [int,...]}

            {'error': e} - on exception
            """
        try:
            raw = self.send(template='vlan_port.j2', port=port)
        except Exception as e:
            self.log.error(f'get vlan port error: {e}')
            return {'error': e}
        tagged = []
        untagged = []
        if re.search('QSW', self.model):
            rgx = (
                r'Port VID :(?P<u>\d+)(?:\s+|$)'
                r'(?:.*(?:Trunk|tag) allowed Vlan: (?P<t>[-;0-9]+))?'
            )
            r = re.search(rgx, raw)
            untagged.append(int(r.group('u')))
            if r.group('t'):
                t = r.group('t').replace(';', ',')
                tagged = interval_to_list(t)
        else:
            rgx = r'\s+(?P<vid>\d+)(?:\s+(?P<u>[-X])\s+(?P<t>[-X])).*'
            for r in re.finditer(rgx, raw):
                if r.group('u') == 'X':
                    untagged.append(int(r.group('vid')))
                if r.group('t') == 'X':
                    tagged.append(int(r.group('vid')))

        return {'port': port, 'untagged': untagged, 'tagged': tagged}

    def get_vlan_ports(self, ports=[]):
        """Get vlan on several ports

        ports - if ommited, all ports are used"""

        if not ports:
            ports = self.access_ports + self.transit_ports

        result = []
        for port in ports:
            result.append(self.get_vlan_port(port=port))

        return result

    def add_vlan_port(self, port, vid, tag=False,
                      force_create=False,
                      force_replace=False,
                      unsafe=False):
        """Add tagged/untagged vlan to port

        port   (int)  - switch port
        vid    (int)  - vlan id
        tag   (bool)  - if True, set vlan tagged. Default False (untagged)

        force flags (default: False):

        force_create  - adding non-existing vlan,
        force_replace - replacing untagged vlan,
        unsafe        - skipping some safety checks."""

        port = int(port)
        vid = int(vid)
        # get current vlans from port for some checks
        cur_vlans = self.get_vlan_port(port=port)
        if not cur_vlans:
            self.log.error(f'failed to get vlans from port {port}')
            return False
        # check if vid exists on switch
        if not vid in self.get_vlan_list():
            if not force_create:
                self.log.error(
                    f'vlan {vid} does not exist. '
                    'Create it first or use `force_create=True` parameter.')
                return False
            else:
                # force create vlan before adding to port
                if not self.add_vlan(vid=vid):
                    self.log.error(f'force create vlan {vid} failed.')
                    return False
        # check if vlan already added
        if (
            (vid in cur_vlans['untagged'] and not tag)
            or (vid in cur_vlans['tagged'] and tag)
        ):
            self.log.info(
                f'vlan {vid} already set on port {port}. Skipping.')
            return True
        # check adding vid 1 to access port
        if vid == 1 and port in self.access_ports and not unsafe:
            self.log.error(
                'VID 1 on access port is probably not what you wanted. '
                'Use `unsafe=True` parameter to skip this check.')
            return False
        # check adding untagged vlan to transit port
        if not tag and port in self.transit_ports and vid != 1 and not unsafe:
            self.log.error(
                'Untagged vlan on transit port is probably not what you '
                'wanted. Use `unsafe=True` parameter to skip this check.')
            return False
        # check overlapping untagged ports
        if not tag and len(cur_vlans['untagged']) > 0:
            # q-tech workaround (vid 1 when no access vlan on port)
            if re.search('QSW', self.model) and cur_vlans['untagged'][0] == 1:
                pass
            elif not force_replace:
                self.log.error(
                    f'Untagged vlan overlapping on port {port}. '
                    f"Remove vlan {cur_vlans['untagged']} first, "
                    'or use `force_replace=True` parameter to replace')
                return False
            else:
                # if force - delete old vlan before adding new
                if not self.delete_vlan_port(
                        port=port, vid=cur_vlans['untagged'][0]):
                    self.log.error(
                        f'failed to replace vlan {vid} on port {port}')
                    return False
        # send commands to switch
        if tag:
            action = 'tag'
        else:
            action = 'untag'
        try:
            result = self.send(template='vlan_port.j2',
                               port=port, vid=vid, action=action)
        except Exception as e:
            self.log.error(
                f'add {action} vlan {vid} on port {port} error: {e}')
            return False
        if not (re.search(r'[Ss]uccess', result) or result == ''):
            self.log.error(
                f'add {action} vlan {vid} on port {port} failed: {result}')
            return False
        else:
            self.log.info(f'{action} vlan {vid} added on port {port}')
            return True

    def delete_vlan_port(self, port, vid, unsafe=False):
        """Delete vlan from port

        unsafe - skip check of vid 1 deleting from transit ports"""

        port = int(port)
        vid = int(vid)
        # get current vlans from port for some checks
        cur_vlans = self.get_vlan_port(port=port)
        if not cur_vlans:
            self.log.error(f'failed to get vlans from port {port}')
            return False
        # check if vlan already deleted
        if not (vid in cur_vlans['untagged'] or vid in cur_vlans['tagged']):
            self.log.info(
                f'vlan {vid} not set on port {port}. Skipping.')
            return True
        # check deleting vid 1 from transit port
        if vid == 1 and port in self.transit_ports and not unsafe:
            self.log.error(
                'Attention! Removing vid 1 from transit port may cause '
                'disconnection from switch and make it unavailable! '
                'Use `unsafe=True` parameter if you really want to do this.')
            return False
        # send commands
        try:
            result = self.send(template='vlan_port.j2',
                               port=port, vid=vid, action='delete')
        except Exception as e:
            self.log.error(
                f'delete vlan {vid} port {port} error: {e}')
            return False
        if not (re.search(r'[Ss]uccess', result) or result == ''):
            self.log.error(
                f'delete vlan {vid} port {port} failed: {result}')
            return False
        else:
            self.log.info(f'vlan {vid} deleted from port {port}')
            return True

    def add_vlans_ports(self, ports, vid_list,
                        force_untagged=False, force_create=False):
        """Add tagged vlans to ports

        ports    (list of int) - list of ports
        vid_list (list of int) - list of vlan id
        force_untagged  (bool) - replace existing untagged to tagged.
        force_create    (bool) - create vlan if not exists."""

        # if only one port in args
        if isinstance(ports, int):
            ports = [ports]
        # if ports are in dlink interval format
        elif isinstance(ports, str):
            ports = interval_to_list(ports)

        for port in ports:
            # get current vlans from port for some checks
            cur_vlans = self.get_vlan_port(port=port)
            if not cur_vlans:
                self.log.error(f'failed to get vlans from port {port}')
                # skip current port on error
                continue
            # vlan processing
            for vid in vid_list:
                vid = int(vid)
                if vid in cur_vlans['untagged'] and not force_untagged:
                    self.log.warning(
                        f'vlan {vid} already set untagged on port {port}. '
                        'Skipping. Use `force_untagged=True` to replace.')
                elif vid in cur_vlans['tagged']:
                    self.log.info(
                        f'vlan {vid} already set on port {port}. Skipping')
                else:
                    self.add_vlan_port(port=port, vid=vid, tag=True,
                                       force_create=force_create)

    def delete_vlans_ports(self, ports, vid_list=[], force_untagged=False):
        """Delete tagged vlans from ports

        ports           - list of ports or one port in int
        vid_list        - if ommited, all vlans will be deleted from port
        force_untagged  - delete also untagged vlan (default: False)
        """

        # if only one port in args
        if isinstance(ports, int):
            ports = [ports]
        # if ports are in dlink interval format
        elif isinstance(ports, str):
            ports = interval_to_list(ports)

        for port in ports:
            # get current vlans from port for some checks
            cur_vlans = self.get_vlan_port(port=port)
            if not cur_vlans:
                self.log.error(f'failed to get vlans from port {port}')
                # skip current port on error
                continue
            # delete all vlans on empty list
            if vid_list:
                del_list = vid_list
            else:
                del_list = cur_vlans['tagged']
                if cur_vlans['untagged']:
                    del_list.append(cur_vlans['untagged'])

            # vlan processing
            for vid in del_list:
                vid = int(vid)
                if vid == cur_vlans['untagged'] and not force_untagged:
                    self.log.warning(
                        f'port {port} vlan {vid} is untagged. '
                        'Skipping. Use `force_untagged=True` to delete.')
                elif not vid in cur_vlans['tagged']:
                    self.log.info(
                        f'no vlan {vid} on port {port}. Skipping')
                else:
                    self.delete_vlan_port(port=port, vid=vid)

    @_models(r'DES-(?!3026)|DGS-(3000|1210)|QSW')
    def check_cable(self, port: int):
        """Make cable diagnostic on port

        if len is not available, returns int 666 ;)"""

        # get raw result
        if re.search('QSW', self.model):
            raw = self.send(f'virtual-cable-test interface ethernet 1/{port}')
        elif (re.search('DES|3000', self.model)
              and not re.search('3026|F', self.model)):
            raw = self.send(f'cable_diag ports {port}')
        elif self.model == 'DGS-1210-28X/ME/B1':
            raw = self.send(f'cable diagnostic port {port}')
        else:
            return None
        # parse raw result
        if re.search('QSW', self.model):
            rgx = r'\)\t\t(?P<state>\w+)\t\t(?P<len>\w+)'
            pairs = [m.groupdict() for m in re.finditer(rgx, raw)]
            for i in range(len(pairs)):
                pairs[i]['pair'] = i+1
                try:
                    pairs[i]['len'] = int(pairs[i]['len'])
                except Exception:
                    pairs[i]['len'] = 666
            return pairs
        else:
            # first check multiline pair status
            rgx = r'Pair *(?P<pair>\d) +(?P<state>\w+) +(?:at +)?(?P<len>\d+)?'
            pairs = [m.groupdict() for m in re.finditer(rgx, raw)]
            for p in pairs:
                p['pair'] = int(p['pair'])
                try:
                    p['len'] = int(p['len'])
                except Exception:
                    p['len'] = 666

            # if no multiline result - return single string status
            if pairs == []:
                rgx = r'Link \w+\s+([\w ]+\w) +-'
                state = re.findall(rgx, raw)
                if len(state) > 0:
                    return state[0]
                return None
            return pairs

    @_models(r'DES|DGS|QSW|DXS-3600')
    def get_port_ddm(self, port: int):
        """Get transceiver ddm info"""

        if re.search(r'DES|DGS', self.model):
            raw = self.send(f'show ddm ports {port} status')
            rgx = r'[^-](-|[-+]?\d+[-+e.\d]*)\s'
            keys = ['port', 'temperature', 'voltage', 'bias_current',
                            'tx_power', 'rx_power']
            values = [float(item) if item != '-' else None
                      for item in re.findall(rgx, raw)]

        elif re.search(r'QSW', self.model):
            raw = self.send(f'show transceiver interface eth 1/{port}')
            rgx = r'[^-](N/A|[-+]?\d+[-+e.\d]*)(?:\s|$)'
            keys = ['port', 'temperature', 'voltage', 'bias_current',
                            'rx_power', 'tx_power']
            values = [float(item) if item != 'N/A' else None
                      for item in re.findall(rgx, raw)]

        elif self.model == 'DXS-3600-32S':
            raw = self.send(f'sh int eth 1/0/{port} transceiver')
            rgx = r'(-?\d+[-+e.\d]*)\s'
            keys = ['port', 'temperature', 'voltage', 'bias_current',
                            'tx_power', 'rx_power']
            # last two values - power in dbm
            values = list(map(float, re.findall(rgx, raw)[:6]))

        if len(keys) == len(values):
            res = dict(zip(keys, values))
        else:
            res = dict.fromkeys(keys)
            res['port'] = port

        return res

    @_models(r'DES|DGS')
    def clear_port_counters(self, port: int):
        """Clear counters on port"""
        result = self.send(f'clear counters ports {port}')
        if re.search(r'[Ss]uccess', result):
            return 'Success'

    @_models(r'DES|DGS|QSW|^DXS((?!A1).)*$')
    def get_port_counters(self, port: int):
        """Get port counters: errors and traffic in bytes"""

        # d-link cli
        if re.search(r'DES|DGS', self.model):
            # packets
            raw = self.send(f'show packet ports {port}')
            rgx = (r'RX Bytes\s+(?P<rx_total>\d+)\s+(?P<rx_speed>\d+)(?s:.*)'
                   r'TX Bytes\s+(?P<tx_total>\d+)\s+(?P<tx_speed>\d+)')

            res = dict_fmt_int(re.search(rgx, raw).groupdict())
            # errors
            raw = self.send(f'show error ports {port}')
            raw = raw.replace(' - ', ' 0 ')
            rgx = r'(\w[\w ]*?\w) +(\d+)(?: +(\w[\w ]*\w) +(\d+))?'
            res['rx_errors'] = []
            res['tx_errors'] = []
            for r in re.finditer(rgx, raw):
                if r[2] and r[2] != '0':
                    res['rx_errors'].append({'name': r[1],
                                             'count': int(r[2])})
                if r[4] and r[4] != '0':
                    res['tx_errors'].append({'name': r[3],
                                             'count': int(r[4])})

        # cisco cli
        else:
            if re.search('QSW', self.model):
                raw = self.send(f'show int eth 1/{port}')
                rgx = (r'second input rate (?P<rx_speed>\d+) bits/sec(?s:.*)'
                       r'second output rate (?P<tx_speed>\d+) bits/sec(?s:.*)'
                       r'Input(?s:.*) (?P<rx_total>\d+) bytes(?s:.*)'
                       r'(?P<rx_errors>\d+ input(?s:.*))'
                       r'Output(?s:.*) (?P<tx_total>\d+) bytes(?s:.*)'
                       r'(?P<tx_errors>\d+ output(?s:.*))')
                rgx_err = r'(?P<count>\d+) (?P<name>[\w ]+),?(?:,\s+)?'
            # TODO: try with DXS-1210-12SC/A2 (no way to test yet)
            elif re.search('DXS', self.model):
                raw = self.send(f'show int eth 1/0/{port}')
                rgx = (r'RX rate: (?P<rx_speed>\d+) \w+/sec, '
                       r'TX rate: (?P<tx_speed>\d+) \w+/sec\s+'
                       r'RX bytes: (?P<rx_total>\d+), '
                       r'TX bytes: (?P<tx_total>\d+)(?s:.*)'
                       r'(?P<rx_errors>RX CRC(?s:.*))'
                       r'(?P<tx_errors>TX CRC(?s:.*))')
                rgx_err = r'\wX (?P<name>[\w ]+): (?P<count>\d+),?(?:,\s+)?'

            res = dict_fmt_int(re.search(rgx, raw).groupdict())
            # format errors
            for key in ['rx_errors', 'tx_errors']:
                res[key] = [
                    dict_fmt_int(item.groupdict()) for item in re.finditer(
                        rgx_err, res[key]) if item['count'] != '0']
            # convert bits to bytes on DXS-3600
            if re.search('3600', self.model):
                for key in ['rx_speed', 'tx_speed']:
                    res[key] /= 8

        return res

    @_models(r'DES|DGS|QSW|^DXS((?!A1).)*$')
    def get_mac_table(self,
                      port: int = None,
                      vid: int = None,
                      mac: str = None):
        """Get port mac table"""
        if re.search(r'DES|DGS', self.model):
            cmd = 'show fdb'
            if port is not None:
                cmd += f' port {port}'
            if vid is not None:
                cmd += f' vlanid {vid}'
            if mac is not None:
                cmd += f' mac {mac}'
            rgx = (r'(?P<vid>\d+) +\w+ +'
                   r'(?P<mac>(?:\w\w-){5}\w\w) +'
                   r'(?P<port>\d+)')
        elif re.search(r'QSW|DXS', self.model):
            iface = '1/' if re.search('QSW', self.model) else '1/0/'
            cmd = 'show mac-address-table'
            if port is not None:
                cmd += f' interface ethernet {iface}{port}'
            if vid is not None:
                cmd += f' vlan {vid}'
            if mac is not None:
                cmd += f' address {mac}'
            rgx = (r'(?P<vid>\d+) +'
                   r'(?P<mac>(?:\w\w-){5}\w\w) +'
                   fr'[\w ]+{iface}(?P<port>\d+)')

        raw = self.send(cmd)
        res = [dict_fmt_int(m.groupdict()) for m in re.finditer(rgx, raw)]
        return res

    @_models(r'DXS-3600|DGS-3627G')
    def get_arp_table(self,
                      ip: str = None,
                      mac: str = None,
                      vid: int = None,
                      check_mac_state: bool = False):
        """Get arp table on l3 switches"""
        if ip is None and mac is None and vid is None:
            return []

        if self.model == 'DXS-3600-32S':
            cmd = 'sh arp '
            if ip is not None:
                cmd += ip
            elif mac is not None:
                cmd += mac
            elif vid is not None:
                cmd += f'int vlan {vid}'
            rgx = (r'(?P<ip>(?:\d+\.){3}\d+) +'
                   r'(?P<mac>(?:\w\w-){5}\w\w) +'
                   r'vlan(?P<vid>\d+)')

        elif self.model == 'DGS-3627G':
            cmd = 'sh arpen '
            if ip is not None:
                cmd += f'ipa {ip}'
            elif mac is not None:
                cmd += f'mac {mac}'
            elif vid is not None:
                cmd += f'ipif {vid}'
            rgx = (r'(?P<vid>\w+) +'
                   r'(?P<ip>(?:\d+\.){3}\d+) +'
                   r'(?P<mac>(?!(?:FF-){5}FF)(?:\w\w-){5}\w\w) +')

        raw = self.send(cmd)
        res = [dict_fmt_int(m.groupdict()) for m in re.finditer(rgx, raw)]

        # check arp entries in mac table
        if check_mac_state:
            for item in res:
                item['state'] = True if len(
                    self.get_mac_table(mac=item['mac'])) == 1 else False

        return res

    @_models('DXS-3600-32S')
    def get_aliases(self):
        """Get list of l3 interfaces ip and vid"""
        raw = self.send('sh ip interface brief | exclude down')
        rgx = r'vlan(?P<vid>\d+) +(?P<alias>(?:\d+\.){3}\d+)'
        res = [dict_fmt_int(m.groupdict()) for m in re.finditer(rgx, raw)]
        return res

    @_models(r'DES-(?!3026)|DGS-(3000|1210)')
    def get_mcast_ports(self):
        """Get lists of source and member multicast ports"""
        raw = self.send('show igmp_snooping multicast_vlan')
        rgx = (r'[^ ](?:Untagged )?Member(?:\(Untagged\))? [Pp]orts +: ?'
               r'(?P<member>[-,0-9]+)?(?s:.*)'
               r'[^ ]Source (?:\(Tagged\))?[Pp]orts +: ?'
               r'(?P<source>[-,0-9]+)?')
        d = re.search(rgx, raw).groupdict()
        return dict(zip(d.keys(), map(interval_to_list, d.values())))

    @_models(r'DES|DGS')
    def get_port_bandwidth(self, port: int):
        """Get port bandwidth limits"""
        raw = self.send(f'show bandwidth_control {port}')
        # if no limit - return null
        rgx = (r'\d\ +((?i:no[ _]limit)|(?P<rx>\d+)) +'
               r'((?i:no[ _]limit)|(?P<tx>\d+)) *')
        res = re.search(rgx, raw).groupdict()
        return dict_fmt_int(res)

    @_models(r'DES-(?!3026)|DGS-(3000|1210)')
    def get_port_mcast_groups(self, port: int):
        """Get list of multicast groups on port"""
        if re.search(r'1210|3000|c1', self.model):
            raw = self.send(f'show igmp_snooping group ports {port}')
        else:
            raw = self.send('show igmp_snooping group vlan 1500')
        rgx = (r'(?P<group>(?:\d+\.){3}\d+)(?s:.*?)'
               r'(?i:member[ \w]*: *)(?P<ports>\d+(?:[- ,0-9]*\d)?)')
        res = []
        # add only the groups, that contain selected port
        for m in re.finditer(rgx, raw):
            if port in interval_to_list(m['ports']):
                res.append(m['group'])
        return res

    @_models(r'DES-(?!3026)|DGS-(3000|1210)')
    def get_port_mcast_filters(self, port: int):
        """Get list of allowed multicast groups on port"""
        raw = self.send(f'show limited_multicast_addr ports {port}')

        if re.search(r'3028|1210', self.model):
            # this models shows only profile id, need to get groups
            rgx_profile = r'(?:Profile Id:|Permit) ?(?P<group_id>[-,0-9]*)'
            m = re.search(rgx_profile, raw)
            # if there are several profiles, check them all
            cmd = []
            for i in interval_to_list(m.groupdict()['group_id']):
                cmd.append(f'show mcast_filter_profile profile_id {i}')
            # no ids found - return empty list
            if len(cmd) == 0:
                return []
            # else - get groups from profiles
            raw = self.send(cmd)

        rgx = rf'({RGX_IP}[- ~]+{RGX_IP})'
        res = re.findall(rgx, raw)
        # convert values to the same form
        res = list(map(lambda s: re.sub(r'[- ~]+', ' - ', s), res))

        return res

########################################################################
# common functions


def ping(ip):
    """Ping with one packet"""
    result = icmp_ping(str(ip), count=1, timeout=0.1, privileged=False)
    return result


def full_ip(ip):
    """Convert x.x to 192.168.x.x"""
    rx = r'([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
    return re.sub(rf'^({rx}\.{rx})$', '192.168.\g<1>', str(ip))


def short_ip(ip):
    """Convert 192.168.x.x to x.x"""
    rx = r'([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
    return re.sub(rf'^192\.168\.({rx}\.{rx})$', '\g<1>', str(ip))


def interval_to_list(s):
    """Convert 1-3,5,7-9 to [1,2,3,5,7,8,9]"""
    if not s:
        return []
    ranges = list((a.split('-') for a in s.split(',')))
    l = []
    for r in ranges:
        l += list(range(int(r[0]), int(r[-1])+1))
    l = list(set(l))
    l.sort()
    return l


def str_to_bool(s):
    """Convert enabled/disabled values to boolean"""
    if re.search(r'(?i:enable|true|up)', s):
        return True
    elif re.search(r'(?i:disable|false|down)', s):
        return False
    else:
        return None


def str_to_int(s: str):
    """Convert str to int if possible"""
    if isinstance(s, str):
        try:
            return int(s)
        except Exception:
            return s
    return s


def dict_fmt_int(d: dict):
    """Convert all str values in dict to int if possible"""
    return dict(zip(d.keys(), map(str_to_int, d.values())))


def ipcalc(ip: str):
    """Return base info about ip address"""
    ip = netaddr.IPNetwork(str(ip))
    if ip.is_private():
        ip.prefixlen = 24
    else:
        for net in PIP_NETS:
            if ip in net:
                ip.prefixlen = net.prefixlen
    data = {
        'ip': str(ip.ip),
        'mask': str(ip.netmask),
        'gateway': str(next(ip.iter_hosts())),
        'prefix': ip.prefixlen,
    }
    return data


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
                log.error(f'{e}')
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
