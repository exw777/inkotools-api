#!/usr/bin/env python3
# lib/sw.py

# internal imports
import asyncio
import concurrent.futures
import logging
import re
import socket
from time import time

# external imports
import netaddr
import pexpect
from arpreq import arpreq
from colorama import Fore, Back, Style
from easysnmp import snmp_get
from icmplib import ping as icmp_ping
from jinja2 import Environment as j2env
from jinja2 import FileSystemLoader as j2loader

# local imports
from .config import ROOT_DIR, SECRETS, NETS, MODEL_COLORS

# module logger
log = logging.getLogger(__name__)


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

    def __init__(self, ip, offline_data=None):
        """Init of switch class

        Arguments:

        ip: Any format of IP address, supported by netaddr.
        """

        # logger with ip name
        self.log = logging.getLogger(str(ip))

        # set ip address
        self.ip = netaddr.IPAddress(ip)

        # check availability via telnet
        if not self.is_alive_telnet():
            raise self.UnavailableError(
                f'Host {str(self.ip)} is not available!')

        # none-snmp mode for using with proxychains
        if offline_data:
            self.log.warning('Working in none-snmp mode')
            self.log.debug(f'Got data: {offline_data}')
            self.mac = offline_data['mac']
            self.model = offline_data['model']
            self.location = offline_data['location']
            self.mgmt_ip = self.ip
        else:
            # set model
            self.model = re.search(r'[A-Z]{1,3}-?[0-9]{1,4}[^ ]*|GEPON',
                                   self.get_oid('1.3.6.1.2.1.1.1.0'))[0]
            # add HW revision for DXS-1210-12SC
            if self.model == 'DXS-1210-12SC':
                self.model += '/' + self.get_oid('1.3.6.1.2.1.47.1.1.1.1.8.1')

            # set system location
            self.location = self.get_oid('1.3.6.1.2.1.1.6.0')

            # set managment ip for L3 switches, we need the first interface in
            # snmp_walk 1.3.6.1.2.1.16.19.11.1.1
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
                self.log.warning(
                    f'Address {self.ip} is out of inkotel switches range')

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
                elif re.search(r'3600|3526', self.model):
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

        self.log.debug(f'switch object created')

    class UnavailableError(Exception):
        """Custom exception when switch is not available"""
        pass

    def is_alive_telnet(self):
        """Check if tcp port 23 is available"""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        res = s.connect_ex((str(self.ip), 23))
        s.close()
        if res == 0:
            return True
        else:
            return False

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
            self.log.error(f'huawey is restricted for telnet connection')
            return None

        # check that connection is not established
        if not hasattr(self, '_connection') or not self._connection.isalive():
            # set credentials from secrets config file
            if re.search(r'DXS|3627G', self.model):
                creds = SECRETS['admin_profile']
            else:
                creds = SECRETS['user_profile']

            # set prompt
            if re.search('DXS-1210-12SC/A1', self.model):
                prompt = '>'
            else:
                prompt = '#'

            # set endline
            if re.search(r'3627G|3600|3000|3200|3028|3026|3120', self.model):
                self._endline = '\n\r'
            elif re.search(r'1210|QSW|LTP', self.model):
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
                self.log.critical('Wrong password!')
                exit(f"Verify contents of 'secrets.yml' and try again.")
            else:
                # calculate full prompt-line for further usage
                self._prompt = tn.before.split()[-1] + prompt

            self._connection = tn
            self.log.debug(f'new telnet connection')
        else:
            self.log.debug(f'telnet already connected')
        return self._connection

    def _close_telnet(self):
        """Close telnet connection"""
        if hasattr(self, '_connection'):
            self._connection.close()
            self.log.debug(f'telnet connection closed')

    def interact(self):
        """Interact with switch via telnet"""
        tn = self._telnet()
        if not tn:
            self.log.debug('telnet object is empty')
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
            self.log.warning(f'empty commands list')
            return None

        self.log.debug(f'raw commands: {commands}')

        # if commands are plain text, split it to list, and trim extra spaces
        if type(commands) is not list:
            commands = list(
                map(str.strip, commands.replace('\n', ';').split(';')))
            self.log.debug(f'converted commands: {commands}')

        tn = self._telnet()
        if not tn:
            self.log.debug('telnet object is empty')
            return None

        output = ''
        for cmd in commands:
            # skip empty commands
            if not cmd:
                continue
            self.log.debug(f'command: {cmd}')
            tn.sendline(cmd)
            # gpon doesn't work without next line
            if re.search(r'GEPON|LTP-8X', self.model):
                tn.send('\r')

            # on dlink cli skip writing to output command confirmation
            if re.search(r'DGS|DES', self.model):
                tn.expect('Command:')
            tn.expect(self._endline)

            # regex for cisco cli configure terminal mode
            conf_t = self._prompt[:-1] + r'\([a-z0-9-/]+\)#'

            # dict of expectations and key responses for them
            # prompt - break expect loop
            # All/More - page processing
            # Refresh - quit from monitoring
            # [y/n] (ignore case) - saving in cisco cli
            # ]? DXS-3600 confirm tftp backup
            page_exp = {
                self._prompt: 'break',
                conf_t: 'break',
                '(?i)all\W': 'a',
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
            self.log.debug(f'output: {cmd_out}')
            output += cmd_out

        # return result of commands
        return output.strip()

    def __del__(self):
        # close telnet connection on class destruction
        self._close_telnet()
        self.log.debug(f'switch object destroyed')

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
            self.log.error(f'backup error: {e}')
            return None
        end = time() - start
        r = r' successful|Success|finished|complete|Upload configuration.*Done'
        if result and re.search(r, result):
            self.log.info(f'backup sent in {end:.2f}s')
            return True
        else:
            self.log.error(f'backup result is: {result}')
            return result

    def save(self):
        """Save config"""
        start = time()
        try:
            result = self.send(template='save.j2')
        except Exception as e:
            self.log.error(f'saving error: {e}')
            return None
        end = time() - start
        r = r'Done|Success|OK| success'
        if result and re.search(r, result):
            self.log.info(f'saved in {end:.2f}s')
            return True
        else:
            self.log.error(f'wrong saving result: {result}')
            return result

    def get_acl(self, port=None):
        """Get acl from switch

        If port is not defined, returns all entries
        """
        try:
            result = self.send(template='acl.j2', port=port)
        except Exception as e:
            self.log.error(f'get acl error: {e}')
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
            regex = (r'access_id\s+(?P<id>\d+)\s+.+source_ip\s+'
                     r'(?P<ip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s*'
                     r'(.+mask\s+(?P<mask>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}))?'
                     r'\s+port\s+(?P<port>\d{1,2})')
        result = [m.groupdict() for m in re.finditer(regex, result)]
        # check if there are non-standart mask in acl rules
        for i in result:
            if 'mask' in i.keys() and i['mask'] \
                    and i['mask'] != '255.255.255.255':
                self.log.warning(f"port {i['port']} acl {i['ip']}"
                                 f" has non-standard mask: {i['mask']}")
        # check if there are several acl for one port
        ports = list(map(lambda x: x['port'], result))
        for p in set(ports):
            cnt = ports.count(p)
            if cnt > 1:
                self.log.warning(f'port {p} has {cnt} acl rules')
        return result

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
            'untagged': int,
            'tagged': [int,...]}

            False - on error with several untagged vlans
            """

        # check port is valid
        if port and not port in (self.access_ports + self.transit_ports):
            self.log.error(f'port {port} out of range')
            return False

        try:
            result_raw = self.send(template='vlan_port.j2', port=port)
        except Exception as e:
            self.log.error(f'get vlan port error: {e}')
            return None
        if not result_raw:
            return None
        tagged = []
        untagged = []
        if re.search('QSW', self.model):
            regex = (
                r'Port VID :(?P<u>\d+)(?:\s+|$)'
                r'(?:.*(?:Trunk|tag) allowed Vlan: (?P<t>[-;0-9]+))?'
            )
            r = re.search(regex, result_raw)
            untagged.append(int(r.group('u')))
            if r.group('t'):
                t = r.group('t').replace(';', ',')
                tagged = interval_to_list(t)
        else:
            regex = (
                r'\s+(?P<vid>\d+)(?:\s+(?P<u>[-X])\s+(?P<t>[-X])).*'
            )
            for r in re.finditer(regex, result_raw):
                if r.group('u') == 'X':
                    untagged.append(int(r.group('vid')))
                if r.group('t') == 'X':
                    tagged.append(int(r.group('vid')))
        # try to workaround common situation:
        # double vlan on access port and one of them is default (vid 1)
        if (
            len(untagged) == 2
            and 1 in untagged
            and port in self.access_ports
        ):
            tmp = set(untagged)
            tmp.remove(1)
            untagged = list(tmp)
            self.log.warning(
                f'Check configuration! Ignoring vid 1 '
                f'with double untagged vlan on access port {port}'
            )
        # check for several untagged vlans and raise error
        if len(untagged) > 1:
            self.log.error(
                f'several untagged vlans on one port! '
                f'port {port}, vlans: {untagged}'
            )
            return False
        elif untagged:
            untagged = int(untagged[0])
        else:
            untagged = None

        return {'port': port, 'untagged': untagged, 'tagged': tagged}

    def get_vlan_ports(self, ports=[]):
        """Get vlan on several ports

        ports - if ommited, all ports are used"""

        if not ports:
            ports = self.access_ports+self.transit_ports

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
            (vid == cur_vlans['untagged'] and not tag)
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
        if not tag and cur_vlans['untagged']:
            # q-tech workaround (vid 1 when no access vlan on port)
            if re.search('QSW', self.model) and cur_vlans['untagged'] == 1:
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
                        port=port, vid=cur_vlans['untagged']):
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

        # get current vlans from port for some checks
        cur_vlans = self.get_vlan_port(port=port)
        if not cur_vlans:
            self.log.error(f'failed to get vlans from port {port}')
            return False
        # check if vlan already deleted
        if not (vid == cur_vlans['untagged'] or vid in cur_vlans['tagged']):
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

        for port in ports:
            # get current vlans from port for some checks
            cur_vlans = self.get_vlan_port(port=port)
            if not cur_vlans:
                self.log.error(f'failed to get vlans from port {port}')
                # skip current port on error
                continue
            # vlan processing
            for vid in vid_list:
                if vid == cur_vlans['untagged'] and not force_untagged:
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
                if vid == cur_vlans['untagged'] and not force_untagged:
                    self.log.warning(
                        f'port {port} vlan {vid} is untagged. '
                        'Skipping. Use `force_untagged=True` to delete.')
                elif not vid in cur_vlans['tagged']:
                    self.log.info(
                        f'no vlan {vid} on port {port}. Skipping')
                else:
                    self.delete_vlan_port(port=port, vid=vid)


########################################################################
# common functions


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
