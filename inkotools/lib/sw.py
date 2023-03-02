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
if COMMON['proxy_mode']:
    log.info('Working in tcp-only mode')
    import socks
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
        if COMMON['proxy_mode']:
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
                rgx = rf'(?P<ip>{RGX_IP})'
            elif re.search('DGS', self.model):
                raw = self.send('sh sw')
                rgx = rf'IP Address +: (?P<ip>{RGX_IP})'
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

        check availability: session --> arp --> icmp --> telnet
        arpreq is faster than icmp, but only works when
        there is a corresponding entry in the local arp table
        first two check are skipping in proxy mode
        """
        # established telnet session check
        if hasattr(self, '_connection') and self._connection.isalive():
            log.debug('Alive: established telnet session')
            return True
        # arp and icmp check
        if not COMMON['proxy_mode']:
            if arpreq(self.ip) or ping(self.ip).is_alive:
                log.debug('Alive: arp or ping')
                return True
        # third check is via tcp port 80 (web) and 23 (telnet)
        for p in [80, 23]:
            if COMMON['proxy_mode']:
                s = socks.socksocket(socks.socket.AF_INET,
                                     socks.socket.SOCK_STREAM)
                s.set_proxy(
                    socks.SOCKS5, COMMON['proxy_ip'], COMMON['proxy_port'])
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            try:
                if s.connect_ex((str(self.ip), p)) == 0:
                    s.close()
                    log.debug(f'Alive: {p} port')
                    return True
            except (socks.ProxyError, socket.timeout):
                pass
            s.close()
        return False

    def get_oid(self, oid):
        """Get snmp oid from switch"""
        if COMMON['proxy_mode']:
            self.log.error('Calling snmp in tcp-only mode')
            return None
        return snmp_get(oid, hostname=str(self.ip),
                        version=2, timeout=3).value

    def _setup_telnet_model(self):
        """Get model via telnet"""
        tn = pexpect.spawn(
            f"{COMMON['telnet_cmd']} {self.ip}", timeout=10, encoding='utf-8')
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
            if re.search(r'3627G|3000|3200|3028|3026|3120', self.model):
                self._endline = '\n\r'
            elif re.search('3526', self.model):
                self._endline = '\r\n\r'
            else:
                self._endline = '\r\n'

            self.log.debug('spawning telnet...')
            # codec_errors='ignore' - ignore non-unicode symbols
            tn = pexpect.spawn(
                f"{COMMON['telnet_cmd']} {self.ip}",
                timeout=120, encoding='utf-8', codec_errors='ignore')

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
            #    except startup-config for GP3600-04
            # TODO: remove hardcode
            page_exp = {
                self._prompt: 'break',
                conf_t: 'break',
                '(?i)[^-]all\W': 'a',
                'More': ' ',
                'Refresh': 'q',
                '(?i)y/n]:': 'y\r',
                '^(?!.*startup-config).*]\?': '\r',
            }
            cmd_out = ''
            while True:
                match = tn.expect(list(page_exp.keys()))
                cmd_out += tn.before
                send_key = list(page_exp.values())[match]
                log.debug(f'matched: {list(page_exp.keys())[match]}')
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
        filename = ''
        # add path if exists
        if COMMON['backup_dir'] != '':
            filename += COMMON['backup_dir']+'/'
        # default filename is ip address
        filename += str(self.ip)
        if self.model == 'DXS-1210-12SC/A1':
            filename += '.bin'
        else:
            filename += '.cfg'

        if self.model == 'DES-3026':
            cmd = f'upload configuration {server} {filename}'
        elif re.search(r'3000|3627G|3120|C1', self.model):
            cmd = f'upload cfg_toTFTP {server} dest_file {filename}'
        elif re.search(r'DES|DGS-1210', self.model):
            cmd = f'upload cfg_toTFTP {server} {filename}'
        elif self.model in ['DXS-3600-32S', 'DXS-1210-28S']:
            cmd = f'copy running-config tftp: //{server}/{filename}'
        elif re.search(r'QSW|DXS-1210-12SC/A2', self.model):
            cmd = f'copy running-config tftp://{server}/{filename}'
        elif self.model == 'LTP-8X':
            cmd = f'copy fs://config tftp://{server}/{filename}'
        elif self.model == 'DXS-1210-12SC/A1':
            cmd = f'copy startup-config tftp://{server}/{filename}'
        elif self.model == 'GP3600-04':
            cmd = f'copy startup-config tftp: {server}\r{filename}\r'

        # measure backup time
        start = time()
        raw = self.send(cmd)
        end = time() - start
        r = (r'(?i)(^|[ :\n\r])success|'
             r'finished|complete|Upload configuration.*Done')
        if re.search(r, raw):
            res = f'backup sent in {end:.2f}s'
            self.log.info(res)
        else:
            res = {'error': f'backup failed: {raw}'}
            self.log.error(raw)
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
                r'(?P<link>Link[ -]?Down|10+\w/(?:Full|Half)|Err[\w-]+)'
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
                result += res
            else:
                result.append(res)

        return result

    @_models(r'DES|DGS|QSW|^DXS((?!A1).)*$')
    def set_port_state(self, port: int, state: bool, desc: str = None):
        """Change port state and description

        Clear description if desc == ''
        """
        if re.search(r'DES|DGS', self.model):
            s = 'enable' if state else 'disable'
            if desc is None:
                # skip description change
                d = ''
            elif desc == '':
                # clear description
                d = 'description ""' if self.model == 'DES-3526' else 'clear'
            else:
                # trim description to 32 symbols
                desc = desc[:32]
                # set quotes for most models
                q = '' if re.search(r'3000|3120|3627|C1', self.model) else '"'
                d = f'description {q}{desc}{q}'
            cmd = f'conf ports {port} state {s} {d}'
        elif re.search(r'QSW|DXS', self.model):
            iface = '1/' if re.search('QSW', self.model) else '1/0/'
            s = 'no shutdown' if state else 'shutdown'
            cmd = ['conf t', f'interface ethernet {iface}{port}', s]
            if desc is not None:
                d = 'no description' if desc == '' else f'description {desc}'
                cmd.append(d)
            cmd += ['exit']*2
        res = self.send(cmd)
        if is_failed(res):
            self.log.error(res)
        else:
            st = 'enabled' if state else 'disabled'
            self.log.info(f'Port {port} {st} {d}')
        return res

    @_models(r'DES|DGS-(3000|1210)|QSW')
    def set_port_auto_speed(self, port: int):
        """Restore port speed autonegotiation"""
        if self.model == 'QSW-2800-28T-AC':
            cmd = ['conf t', f'int eth 1/{port}', 'speed-duplex auto', 'end']
        else:
            cmd = f'conf ports {port} speed auto'
        res = self.send(cmd)
        if is_failed(res):
            self.log.error(res)
        return res

    @_models(r'DES-(?!3026)|DGS-(3000|1210)|QSW')
    def get_acl(self, port: int):
        """Get port acl"""
        if re.search('QSW', self.model):
            raw = self.send(f'sh am int eth 1/{port}')
            rgx = (r'Interface Ethernet1/(?P<port>\d{1,2})'
                   r'\s+am port\s+am ip-pool\s+'
                   rf'(?P<ip>{RGX_IP})\s+(?P<mask>\d+)')
            res = re.search(rgx, raw)
            if res is not None:
                res = dict_fmt_int(res.groupdict())
                # convert am count to mask (count<32)
                res['mask'] = f"255.255.255.{256-res['mask']}"
                res['mode'] = 'permit'
                res = [res]
            else:
                res = []
        # workaround for 1210, which is too slow when requesting config
        elif re.search('1210', self.model):
            rgx = (r'Access ID: (?P<access_id>\d+)\s*'
                   r'Mode: (?P<mode>Permit|Deny)(?:[\s\w:]+)'
                   rf'Ports: (?P<port>{port}\s)(?:[\s\w:]*)'
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

    @_models(r'DES-(?!3026)|DGS-(3000|1210)|QSW')
    def add_acl(self, port: int,  mode: str, ip: str,
                mask: str = None, access_id: int = None):
        """Add ip acl to switch port
        mode: (permit|deny)
        mask: default 255.255.255.255 for permit and 0.0.0.0 for deny
              (not supported by 3526 and 3028G)
        access_id: default is the same as port number

        For QSW only permit rule is available, access_id is ignored
        """
        # set default values
        if mask is None:
            mask = '255.255.255.255' if mode == 'permit' else '0.0.0.0'
        elif re.search(r'3526|3028', self.model):
            log.warning(
                f'ACL mask not supported by {self.model}, will be ignored')
        if access_id is None:
            access_id = port

        if re.search('QSW', self.model):
            if mode != 'permit':
                log.warning('Skipping deny QSW rule')
                return
            # calculate am ip and count from mask
            net = netaddr.IPNetwork(f'{ip}/{mask}')
            ip = net[0]
            count = len(net)
            cmd = ['conf t', f'int eth 1/{port}', 'am port',
                   f'am ip-pool {ip} {count}', 'end']
        else:
            profile_id = 10 if mode == 'permit' else 20
            if re.search(r'3200|3000', self.model):
                mask_cmd = f'mask {mask} '
            elif re.search('1210', self.model):
                mask_cmd = f'source_ip_mask {mask} '
            else:
                mask_cmd = ''
            cmd = (f'config access_profile profile_id {profile_id} '
                   f'add access_id {access_id} ip source_ip {ip} {mask_cmd}'
                   f'port {port} {mode}')

        res = self.send(cmd)
        if is_failed(res):
            self.log.error(res)
        else:
            self.log.info(f'Port {port} added ACL: {mode} {ip} {mask}')
        return res

    @_models(r'DES-(?!3026)|DGS-(3000|1210)|QSW')
    def delete_acl(self, port: int,
                   profile_id: int = None, access_id: int = None):
        """Delete acl from switch port

        Delete all rules if no profile/access id provided"""
        if re.search('QSW', self.model):
            cmd = ['conf t', f'int eth 1/{port}', ' no am port', 'end']
        else:
            cmd = []
            acl_to_delete = []
            if profile_id is not None and access_id is not None:
                # single rule
                acl_to_delete.append(
                    {'profile_id': profile_id, 'access_id': access_id})
            else:
                # get all rules and select necessary
                for acl in self.get_acl(port):
                    if (acl['profile_id'] == profile_id
                        or acl['access_id'] == access_id
                            or access_id == profile_id):
                        acl_to_delete.append(acl)
            # delete rules
            for acl in acl_to_delete:
                cmd.append('config access_profile '
                           f"profile_id {acl['profile_id']} "
                           f"del access_id {acl['access_id']}")
        if len(cmd) == 0:
            self.log.info('No rules to delete')
            return
        res = self.send(cmd)
        if is_failed(res):
            self.log.error(res)
        else:
            self.log.info(f'Port {port} removed ACL')
        return res

    @_models(r'DES|DGS|QSW|^DXS((?!A1).)*$')
    def get_vlan(self, vid: int = None):
        """Get tagged and untagged ports for vlan

        If vid is not defined, returns all vlans

        Returns: list of dicts:

                    [{'vid': int,
                    'tagged': [int, ...],
                    'untagged': [int, ...]
                    }, ...]
        """
        cmd = 'sh vlan'
        if re.search('QSW', self.model):
            vid_cmd = f' id {vid}'
            rgx = (r'\n(?P<vid>\d+)\s+(?:.*Static.*?)'
                   r'(?P<ports>(?:\s*(?:Ethernet.*)*(?:\s+\r|$))+)')
        elif re.search('DXS', self.model):
            vid_cmd = f' {vid}'
            rgx = (r'VLAN (?P<vid>\d+)(?s:.*?)'
                   r'Tagged Member Ports +: (?P<tagged>[-/,\w]*)\s+'
                   r'Untagged Member Ports +: (?P<untagged>[-/,\w]*)(?s:.*?)')
        else:
            if self.model == 'DES-3026':
                vid_cmd = ' default' if vid == 1 else f' {vid}'
            else:
                vid_cmd = f' vlanid {vid}'
            rgx = (r'VID\s+:\s+(?P<vid>\d+)\s+(?s:.*?)'
                   r'Tagged [Pp]orts\s+:\s+'
                   r'(?P<tagged>[-,0-9]*)\s+(?s:.*?)'
                   r'Untagged [Pp]orts\s+:\s+(?P<untagged>[-,0-9]*)')
        if vid is not None:
            cmd += vid_cmd
        raw = self.send(cmd)
        # remove waste symbols from qsw raw
        if re.search('QSW', self.model):
            raw = raw.replace('\x08', '').replace('-', '')
        res = [r.groupdict() for r in re.finditer(rgx, raw)]
        for item in res:
            item['vid'] = int(item['vid'])
            # QSW workaround
            if 'ports' in item.keys():
                p = item.pop('ports')
                item['tagged'] = list(map(int, re.findall(
                    r'Ethernet1/(\d+)\(T\)(?:\s|$)\s*', p)))
                item['untagged'] = list(map(int, re.findall(
                    r'Ethernet1/(\d+)(?:\s|$)\s*', p)))
            else:
                # convert ports interval to list
                for i in ['tagged', 'untagged']:
                    item[i] = interval_to_list(item[i])
        return res

    def get_vlan_list(self):
        """Return list of all vlans"""
        return [v['vid'] for v in self.get_vlan()]

    @_models(r'DES|DGS|QSW|^DXS((?!A1).)*$')
    def add_vlan(self, vid: int):
        """Add new vlan to switch"""
        if len(self.get_vlan(vid)) > 0:
            log.warning(f'VID {vid} already exists. Skipping.')
            return
        if re.search(r'QSW|DXS', self.model):
            cmd = ['conf t', f'vlan {vid}', f'name {vid}', 'end']
        else:
            cmd = f'create vlan {vid} tag {vid}'
        res = self.send(cmd)
        if is_failed(res):
            self.log.error(res)
        else:
            self.log.info(f'VID {vid} added')
        return res

    def add_vlans(self, vid_list):
        """Add new vlans to switch"""
        for vid in vid_list:
            self.add_vlan(vid)

    @_models(r'DES|DGS|QSW|^DXS((?!A1).)*$')
    def delete_vlan(self, vid, force=False):
        """Delete vlan from switch"""
        if len(self.get_vlan(vid)) == 0:
            log.warning(f'VID {vid} not found. Skipping.')
            return
        if re.search(r'QSW|DXS', self.model):
            cmd = ['conf t', f'no vlan {vid}', 'end']
        else:
            cmd = f'delete vlan {vid}'
        res = self.send(cmd)
        if is_failed(res):
            self.log.error(res)
        else:
            self.log.info(f'VID {vid} removed')
        return res

    def delete_vlans(self, vid_list):
        """Delete vlans from switch"""
        for vid in vid_list:
            self.delete_vlan(vid)

    @_models(r'DES|DGS|QSW|^DXS((?!A1).)*$')
    def get_vlan_port(self, port: int):
        """Get vlan information from port

        Returns: dict with keys:
            port: int
            mode: str (access|trunk|hybrid)
            native: int
            untagged: [int,...]
            tagged: [int,...]
        """
        res = {'port': port, 'mode': None, 'native': None,
               'untagged': [], 'tagged': []}

        if re.search('QSW', self.model):
            raw = self.send(f'sh switchport interface ethernet 1/{port}')
            rgx = (
                r'Ethernet1/(?P<port>\d+)(?s:.*?)'
                r'Mode :(?P<mode>\w+)(?:\s+)'
                r'Port VID :(?P<native>\d+)(?:\s+|$)'
                r'(?:(?:Trunk|Hybrid tag) allowed Vlan: (?P<tagged>[-;0-9]+))?'
                r'(?:\s*Hybrid untag allowed Vlan: (?P<untagged>[-;0-9]+))?'
            )
            res = re.search(rgx, raw).groupdict()

        elif re.search('DXS', self.model):
            raw = self.send(f'sh vlan interface ethernet 1/0/{port}')
            rgx = (
                r'(?i)eth1/0/(?P<port>\d+)(?s:.*?)'
                r'mode +: (?P<mode>\w+)(?:\s+)'
                r'(?:native|access) [\w ]+: (?P<native>\d+)(?:.*)?'
                r'(?:\s*hybrid untagged [\w ]+: (?P<untagged>[-,0-9]+)?)?'
                r'(?:\s*(?:trunk|.* tagged) [\w ]+: (?P<tagged>[-,0-9\s]+\d))?'
            )
            res = re.search(rgx, raw).groupdict()

        elif self.model == 'DES-3026':
            # 3026 has no command for port vlan information
            # workaround is to recombine the result of get_vlan function
            for vlan in self.get_vlan():
                if port in vlan['tagged']:
                    res['tagged'].append(vlan['vid'])
                elif port in vlan['untagged']:
                    res['untagged'].append(vlan['vid'])

        else:
            raw = self.send(f'sh vlan port {port}')
            rgx = (r'\s+(?P<vid>\d+)'
                   r'(?:\s+(?P<untagged>[-X])\s+(?P<tagged>[-X])).*')
            for r in re.finditer(rgx, raw):
                for k in ['untagged', 'tagged']:
                    if r.group(k) == 'X':
                        res[k].append(int(r.group('vid')))

        if res['mode'] is None:
            # workaround for d-link cli
            res['mode'] = 'hybrid'
        else:
            res['mode'] = res['mode'].lower()

        if res['native'] is None:
            if len(res['untagged']) > 0:
                res['native'] = res['untagged'][0]
        else:
            res['native'] = int(res['native'])

        # convert port intervals to lists
        for k in ['untagged', 'tagged']:
            if not isinstance(res[k], list):
                res[k] = interval_to_list(res[k])

        if len(res['untagged']) == 0 and res['mode'] == 'access':
            res['untagged'].append(res['native'])

        return res

    def get_vlan_ports(self, ports=[]):
        """Get vlan on several ports

        ports - if ommited, all ports are used"""

        # convert args to list
        if isinstance(ports, int):
            ports = [ports]
        elif isinstance(ports, str):
            ports = interval_to_list(ports)

        if len(ports) == 0:
            ports = self.access_ports + self.transit_ports

        result = []
        for port in ports:
            result.append(self.get_vlan_port(port=port))

        return result

    @_models(r'DES|DGS|QSW|^DXS((?!A1).)*$')
    def add_vlan_port(self, port: int, vid: int,
                      tagged: bool = False,
                      force_create: bool = False,
                      force_replace: bool = False):
        """Add tagged/untagged vlan to port

        port    (int) - switch port
        vid     (int) - vlan id
        tagged (bool) - if True, set vlan tagged (default is untagged)

        force bool flags (default: False):

        force_create  - add non-existing vlan
        force_replace - replace untagged vlan
        """

        # check vlan existence and create if needed
        if not vid in self.get_vlan_list():
            self.log.warning(f'vlan {vid} does not exist')
            if force_create:
                self.add_vlan(vid)
            else:
                self.log.error(
                    f'Cannot add non-existent vlan {vid} on port {port}. '
                    'Use `force_create = True` to create it before adding.')
                return

        # get current vlans from port for some checks
        cur_vlans = self.get_vlan_port(port)

        # check if vlan already added
        if ((vid in cur_vlans['untagged'] and not tagged)
                or (vid in cur_vlans['tagged'] and tagged)):
            self.log.info(f'vlan {vid} already set on port {port}. Skipping.')
            return

        # check overlapping untagged ports
        if not tagged and len(cur_vlans['untagged']) > 0:
            # cisco cli workaround
            # (vid 1 is set if there is no access vlan on port)
            if re.search(r'QSW|DXS', self.model) and cur_vlans['native'] == 1:
                force_replace = True
            if not force_replace:
                self.log.error(
                    f'Cannot add untagged vlan {vid} on port {port}, '
                    f"already set vlan {cur_vlans['untagged']}. "
                    'Use `force_replace = True` to replace it.')
                return
            else:
                # remove old vlan from port before adding new
                self.delete_vlan_port(port=port, vid=cur_vlans['untagged'][0])

        if re.search(r'QSW|DXS', self.model):
            # templates for handling differences between QSW and DXS
            hybrid_add = 'switchport hybrid allowed vlan add '
            hybrid_remove = 'switchport hybrid allowed vlan remove '
            if re.search('QSW', self.model):
                interface = f'1/{port}'
                hybrid_add += '{vid} {tag}'
                hybrid_remove += '{vid} {tag}'
            else:
                interface = f'1/0/{port}'
                hybrid_add += '{tag} {vid}'
                hybrid_remove += '{vid}'
            cmd = ['conf t', f'int eth {interface}']
            if cur_vlans['mode'] == 'access':
                if tagged:
                    # change mode to hybrid
                    self.log.warning(f'Changing port {port} mode to hybrid')
                    cmd.append('switchport mode hybrid')
                    # restore old native/untagged vlan
                    cmd.append('switchport hybrid native vlan ' +
                               f"{cur_vlans['native']}")
                    cmd.append(hybrid_remove.format(vid=1,
                                                    tag='untag'))
                    cmd.append(hybrid_add.format(vid=cur_vlans['native'],
                                                 tag='untag'))
                    # add new tagged vlan
                    cmd.append(hybrid_add.format(vid=vid, tag='tag'))
                else:
                    cmd.append(f'switchport access vlan {vid}')
            elif cur_vlans['mode'] == 'trunk':
                if tagged:
                    cmd.append(f'switchport trunk allowed vlan add {vid}')
                else:
                    cmd.append(f'switchport trunk native vlan {vid}')
            elif cur_vlans['mode'] == 'hybrid':
                t = 'tag' if tagged else 'untag'
                cmd.append(hybrid_add.format(vid=vid, tag=t))
                if not tagged:
                    cmd.append(f'switchport hybrid native vlan {vid}')
            cmd.append('end')

        else:
            if re.search(r'3026|3627G', self.model):
                vid_cmd = 'default' if vid == 1 else vid
            else:
                vid_cmd = f'vlanid {vid}'
            cmd = f'conf vlan {vid_cmd} add '
            if not tagged:
                cmd += 'un'
            cmd += f'tagged {port}'

        res = self.send(cmd)
        if is_failed(res):
            self.log.error(res)
        else:
            msg = 'Tagged' if tagged else 'Untagged'
            msg += f' vlan {vid} added to port {port}'
            self.log.info(msg)
        return res

    @_models(r'DES|DGS|QSW|^DXS((?!A1).)*$')
    def delete_vlan_port(self, port: int, vid: int):
        """Delete vlan from port"""

        cur_vlans = self.get_vlan_port(port=port)
        if not vid in cur_vlans['untagged'] + cur_vlans['tagged']:
            self.log.info(f'vlan {vid} not set on port {port}. Skipping.')
            return

        tagged = True if vid in cur_vlans['tagged'] else False

        if re.search(r'QSW|DXS', self.model):
            interface = '1/' if self.model == 'QSW-2800-28T-AC' else '1/0/'
            interface += str(port)
            mode = cur_vlans['mode']
            cmd = ['conf t', f'int eth {interface}']
            if mode == 'access':
                cmd.append('no switchport access vlan')
            else:
                if vid == cur_vlans['native'] and vid != 1:
                    self.log.warning(
                        f'native vlan {vid} will be replaced by vid 1')
                    cmd.append(f'no switchport {mode} native vlan')
                if mode == 'hybrid' and self.model == 'QSW-2800-28T-AC':
                    t = 'tag' if tagged else 'untag'
                else:
                    t = ''
                cmd.append(f'switchport {mode} allowed vlan remove {vid} {t}')
            cmd.append('end')

        else:
            if re.search(r'3026|3627G', self.model):
                vid_cmd = 'default' if vid == 1 else vid
            else:
                vid_cmd = f'vlanid {vid}'
            cmd = f'conf vlan {vid_cmd} delete {port}'

        res = self.send(cmd)
        if is_failed(res):
            self.log.error(res)
        else:
            msg = 'Tagged' if tagged else 'Untagged'
            msg += f' vlan {vid} removed from port {port}'
            self.log.info(msg)
        return res

    @_models(r'DES|DGS|QSW|^DXS((?!A1).)*$')
    def add_vlans_ports(self, ports, vid_list):
        """Add list of tagged vlans to list of ports

        `ports` and `vid_list`can be also string interval or single int

        Missing vlan will be created.
        Existing untagged vlan on port will be replaced by tagged.
        """

        # convert args to lists
        if isinstance(ports, int):
            ports = [ports]
        elif isinstance(ports, str):
            ports = interval_to_list(ports)
        if isinstance(vid_list, int):
            vid_list = [vid_list]
        elif isinstance(vid_list, str):
            vid_list = interval_to_list(vid_list)

        for port in ports:
            cur_vlans = self.get_vlan_port(port)
            for vid in vid_list:
                vid = int(vid)
                if vid in cur_vlans['untagged']:
                    self.log.warning(
                        f'Found untagged {vid} on port {port}. Removing.')
                    self.delete_vlan_port(port, vid)
                if vid in cur_vlans['tagged']:
                    self.log.info(
                        f'Found tagged {vid} on port {port}. Skipping.')
                else:
                    self.add_vlan_port(port, vid,
                                       tagged=True, force_create=True)

    @_models(r'DES|DGS|QSW|^DXS((?!A1).)*$')
    def delete_vlans_ports(self, ports, vid_list: list = [],
                           force_untagged: bool = False):
        """Delete list of vlans from list of ports

        `ports` and `vid_list`can be also string interval or single int
         if `vid_list` is ommited, all vlans will be deleted from port

        by default only tagged vlans will be deleted,
        use `force_untagged = True` to delete also untagged vlan

        """

        # convert args to lists
        if isinstance(ports, int):
            ports = [ports]
        elif isinstance(ports, str):
            ports = interval_to_list(ports)
        if isinstance(vid_list, int):
            vid_list = [vid_list]
        elif isinstance(vid_list, str):
            vid_list = interval_to_list(vid_list)

        for port in ports:
            # get current vlans from port for some checks
            cur_vlans = self.get_vlan_port(port=port)
            # delete all vlans on empty list
            if len(vid_list) == 0:
                vid_list = cur_vlans['tagged']+cur_vlans['untagged']
            # vlan processing
            for vid in vid_list:
                vid = int(vid)
                if vid in cur_vlans['untagged'] and not force_untagged:
                    self.log.warning(
                        f'port {port} vlan {vid} is untagged. '
                        'Skipping. Use `force_untagged = True` to delete.')
                elif not vid in cur_vlans['tagged']+cur_vlans['untagged']:
                    self.log.info(
                        f'vlan {vid} not found on port {port}. Skipping.')
                else:
                    self.delete_vlan_port(port, vid)

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

    @_models(r'DES|DGS|QSW')
    def clear_port_counters(self, port: int):
        """Clear counters on port"""
        iface = 'int eth 1/' if re.search('QSW', self.model) else 'ports '
        result = self.send(f'clear counters {iface}{port}')
        if not is_failed(result):
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
            rgx = (rf'(?P<ip>{RGX_IP}) +'
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
                   rf'(?P<ip>{RGX_IP}) +'
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
        rgx = rf'vlan(?P<vid>\d+) +(?P<alias>{RGX_IP})'
        res = [dict_fmt_int(m.groupdict()) for m in re.finditer(rgx, raw)]
        return res

    @_models(r'DES-(?!3026)|DGS-(3000|1210)|QSW')
    def get_mcast_ports(self):
        """Get lists of source and member multicast ports"""
        if self.model == 'QSW-2800-28T-AC':
            # get config for each port and search within it
            raw = self.send('sh run | begin Interface')
            rgx = r'Interface Ethernet1/(?P<port>\d+)(?s:(?P<cfg>.*?))!'
            member = []
            for m in re.finditer(rgx, raw):
                if re.search('switchport association multicast-vlan 1500',
                             m['cfg']):
                    member.append(int(m['port']))
            # hardcode: transit ports as source for qsw
            res = {'member': member, 'source': self.transit_ports}
        else:
            raw = self.send('show igmp_snooping multicast_vlan')
            rgx = (r'[^ ](?:Untagged )?Member(?:\(Untagged\))? [Pp]orts +: ?'
                   r'(?P<member>[-,0-9]+)?(?s:.*)'
                   r'[^ ]Source (?:\(Tagged\))?[Pp]orts +: ?'
                   r'(?P<source>[-,0-9]+)?')
            d = re.search(rgx, raw).groupdict()
            res = dict(zip(d.keys(), map(interval_to_list, d.values())))
        return res

    @_models(r'DES|DGS')
    def get_port_bandwidth(self, port: int):
        """Get port bandwidth limits"""
        raw = self.send(f'show bandwidth_control {port}')
        # if no limit - return null
        rgx = (r'\d\ +((?i:no[ _]limit)|(?P<rx>\d+)) +'
               r'((?i:no[ _]limit)|(?P<tx>\d+)) *')
        res = re.search(rgx, raw).groupdict()
        return dict_fmt_int(res)

    @_models(r'DES|DGS')
    def set_port_bandwidth(self, port: int, limit: int):
        """Set port bandwidth in megabits"""
        val = 1024*int(limit) if limit > 0 else 'no_limit'
        cmd = f'config bandwidth_control {port} rx_rate {val} tx_rate {val}'
        res = self.send(cmd)
        if is_failed(res):
            self.log.error(res)
        else:
            self.log.info(f'Port {port} limited to {limit} Mbit/s')
        return res

    @_models(r'DES-(?!3026)|DGS-(3000|1210)|QSW')
    def get_port_mcast_groups(self, port: int):
        """Get list of multicast groups on port"""
        if re.search('QSW', self.model):
            raw = self.send(
                f'sh ip igmp snooping vlan 1500 groups int eth 1/{port}')
            rgx = rf'(?P<group>{RGX_IP})'
            res = re.findall(rgx, raw)
        else:
            if re.search(r'1210|3000|c1', self.model):
                raw = self.send(f'show igmp_snooping group ports {port}')
            else:
                raw = self.send('show igmp_snooping group vlan 1500')
            rgx = (rf'(?P<group>{RGX_IP})(?s:.*?)'
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

    @_models(r'DES-(?!3026)|DGS-(3000|1210)')
    def get_port_mcast_profile(self, port: int):
        """Get list of mcast limit profiles on port"""
        raw = self.send(f'show limited_multicast_addr ports {port}')
        if re.search(r'3028|1210', self.model):
            rgx = r'(?:Profile Id:|Permit) ?(?P<id>[-,0-9]*)'
            m = re.search(rgx, raw).groupdict()
            res = interval_to_list(m['id'])
        else:
            rgx = r'\d+ +(?P<id>\d+) +(?s:.*?)'
            res = list(map(int, re.findall(rgx, raw)))
        return res

    @_models(r'DES-(?!3026)|DGS-(3000|1210)')
    def set_port_mcast_profile(self, port: int, profile_id: int):
        """Set mcast limit profile by id

         removes all other profiles
         """

        profiles = self.get_port_mcast_profile(port)
        # check and remove old profiles
        if profile_id in profiles:
            profiles.remove(profile_id)
            if len(profiles) > 0:
                # remove otherother profiles
                for i in profiles:
                    self.delete_port_mcast_profile(port, i)
            self.log.info(
                f'profile {profile_id} already set on port {port}. Skipping.')
            return
        if len(profiles) > 0:
            # remove old profiles
            self.delete_port_mcast_profile(port)

        if self.model == 'DES-3526':
            cmd = [(f'config limited_multicast_addr ports {port} '
                    f'add multicast_range {profile_id}'),
                   (f'config limited_multicast_addr ports {port} '
                    'access permit state enable')]
        else:
            cmd = (f'config limited_multicast_addr ports {port} '
                   f'add profile_id {profile_id}')

        res = self.send(cmd)
        if is_failed(res):
            self.log.error(res)
        else:
            self.log.info(f'Port {port} mcast profile {profile_id}')
        return res

    @_models(r'DES-(?!3026)|DGS-(3000|1210)')
    def delete_port_mcast_profile(self, port: int, profile_id=None):
        """Remove mcast limit profile from port

        if `profile_id` is ommited, removes all mcast profiles from port
        """

        profiles = self.get_port_mcast_profile(port)
        if profile_id is None:
            del_list = profiles
        elif profile_id not in profiles:
            self.log.info(
                f'profile {profile_id} not found on port {port}. Skipping.')
            return
        else:
            del_list = [profile_id]
        cmd = []
        p = 'multicast_range' if self.model == 'DES-3526' else 'profile_id'
        v = 'ipv4' if '1210' in self.model else ''
        for i in del_list:
            cmd.append(f'config limited_multicast_addr ports {port} '
                       f'{v} delete {p} {i}')
        if len(cmd) == 0:
            self.log.info('No profiles to delete')
            return
        res = self.send(cmd)
        if is_failed(res):
            self.log.error(res)
        else:
            self.log.info(f'Profile {del_list} removed from port {port}')
        return res

    @_models(r'DES-(?!3026)|DGS-(3000|1210)|QSW')
    def set_mcast_member(self, port: int, state: bool):
        """Add/delete multicast member port"""
        action = 'add' if state else 'delete'
        members = self.get_mcast_ports()['member']
        if state and port in members or not state and not port in members:
            self.log.info(f'{action} port {port} already done. Skipping.')
            return
        if self.model == 'QSW-2800-28T-AC':
            no = '' if state else 'no'
            cmd = ['conf t',
                   f'int eth 1/{port}',
                   f'{no} switchport association multicast-vlan 1500',
                   'end']
        elif self.model == 'DES-3526':
            if state:
                members.append(port)
            else:
                members.remove(port)
            ports = ','.join(map(str, members))
            cmd = f'conf igmp_sn multicast_vlan 1500 member {ports}'
        else:
            cmd = f'conf igmp_sn multicast_vlan 1500 {action} member {port}'
        res = self.send(cmd)
        if is_failed(res):
            self.log.error(res)
        else:
            self.log.info(f'{action} port {port}')
        return res

    @_models(r'DES|DGS-(3000|1210)|QSW')
    def wipe_port(self, port: int, desc: str = ''):
        """Wipe port config and set description"""

        if self.model != 'DES-3026':
            # remove all acl rules
            self.delete_acl(port)
            # remove multicast vlan
            self.set_mcast_member(port, False)

            if self.model != 'QSW-2800-28T-AC':
                # remove all multicast filters
                self.delete_port_mcast_profile(port)

        # disable port and set description
        self.set_port_state(port, False, desc)
        # set autonegotiation
        self.set_port_auto_speed(port)
        # remove all vlans
        self.delete_vlans_ports(port, force_untagged=True)

        if re.search('DGS', self.model):
            # restore bandwidth
            self.set_port_bandwidth(port, 100)

    @_models(r'DES|DGS-(3000|1210)|QSW')
    def free_ports(self):
        """Search for free ports"""
        res = []
        for p in self.get_ports_state(self.access_ports):
            # port must be disabled
            if p['state']:
                continue
            # port must not be broken (check by desc)
            rgx = r'(?i)bad|sgorel|lbd|loop|broken|dead'
            if p['desc'] is not None and re.search(rgx, p['desc']):
                continue
            # port must not have vlans
            v = self.get_vlan_port(p['port'])
            if len(v['tagged']+v['untagged']) > 0:
                continue
            # check cable length
            if p['type'] == 'C':
                try:
                    cable = self.check_cable(p['port'])
                except self.ModelError:
                    cable = None
                if isinstance(cable, list):
                    p['cable'] = cable
                else:
                    p['status'] = cable
            # add port to result
            res.append(p)
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
    # covert cisco cli interfaces to ports
    s = re.sub(r'(?:eth)?1/(?:0/)?(\d+)', r'\1', s)
    # qsw ranges are separated by `;`
    s = s.replace(';', ',')
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


def is_failed(raw: str):
    """Check string output for errors"""
    rgx = r'(?i)error|fail|lock|invalid|possible completions'
    res = True if re.search(rgx, str(raw)) else False
    return res


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
                log.error(f'[{ip}] {e}')
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
