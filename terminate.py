#!/usr/bin/env python3
# terminate.py

import logging
import re
import subprocess
from datetime import date

from netaddr import IPNetwork

from inkotools.lib.sw import Switch, full_ip, RGX_IP
from inkotools.lib.cfg import COMMON, SECRETS
from inkotools.lib.gdb import GRAYDB

# https://github.com/truman369/operlog_client
from operlog_client.cli import operlog

log = logging.getLogger()

git_dir = COMMON['backup_path']
git_author = COMMON['git_author']

GDB = GRAYDB(COMMON['GRAYDB_URL'], SECRETS['gray_database'])


def client_terminate(contract_id: str, ignore_acl=False):
    """Remove config and terminate contract"""

    # flag to remove config from port
    remove_config = True
    terminated = False
    ticket_comment = ''

    # check tickets
    tickets = GDB.search_ticket(contract_id, r'растор\w+',
                                search_in_comments=True)
    if len(tickets) == 0:
        log.error(f'[{contract_id}] No termination tickets found. Aborting.')
        return

    # check that billing ip is empty
    try:
        ips = GDB.get_client_ip_list(contract_id)
    except GDB.NotFoundError:
        ips = []
    if len(ips) > 0:
        log.error(f'[{contract_id}] Found ip in billing: {ips}. Aborting.')
        return

    # get data from gray database
    client_data = GDB.get_client_data(contract_id)
    sw_ip = full_ip(client_data['sw_ip'])
    port = client_data['port']

    # validate switch ip and port
    if sw_ip == '':
        log.warning(f'[{contract_id}] Empty switch ip.')
        ticket_comment += 'IP-адрес коммутатора не указан. '
        remove_config = False
    elif port == '':
        log.warning(f'[{contract_id}] Empty port.')
        ticket_comment += 'Порт не указан. '
        remove_config = False
    elif not re.match(rf'^{RGX_IP}$', sw_ip):
        log.error(f'[{contract_id}] Wrong switch ip: {sw_ip}')
        return
    else:
        try:
            port = int(port)
        except ValueError:
            log.error(f'[{contract_id}] Wrong switch port: {port}')
            return

    # check port acl
    if remove_config:
        acl_ip = []
        try:
            sw = Switch(sw_ip)
        except Switch.UnavailableError:
            log.error(f'[{contract_id}] Switch is unavailable: {sw_ip}')
            return
        try:
            for r in sw.get_acl(port):
                if r['mode'] == 'permit' and r['ip'] != '0.0.0.0':
                    acl_ip += map(str, IPNetwork(f"{r['ip']}/{r['mask']}"))
        except Switch.ModelError:
            # skip 3026
            pass
        if len(acl_ip) > 0:
            # find ip in gray database
            for i in acl_ip:
                try:
                    c = GDB.get_contract_by_ip(i)
                    # get switch ip and port for found contract
                    d = GDB.get_client_data(c)
                    if (full_ip(d['sw_ip']) == sw_ip
                            and str(port) in d['port'].split()):
                        log.warning(
                            f'[{contract_id}] Port is used by client: {c}')
                        ticket_comment += (f'В порт подключен абонент {c}. '
                                           'Настройки убирать не требуется. ')
                        remove_config = False
                except GDB.NotFoundError:
                    pass
        else:
            # log.warning(f'[{contract_id}] Empty ACL')
            # TODO: show port state and config to user and ask for termination
            # TODO: check for already removed config
            if not ignore_acl:
                log.error(f'[{contract_id}] Empty ACL')
                return

    # remove config from switch
    if remove_config:
        dt = date.today().strftime('%Y-%m-%d')
        sw.wipe_port(port, f'FREE {contract_id} TERMINATED {dt}')
        ticket_comment += 'Настройки на порту убрал. '

    else:
        log.warning(f'[{contract_id}] Skipping port wipe.')

    # terminate contract in gray database
    if client_data['terminated']:
        terminated = True
        log.warning(f'[{contract_id}] Already terminated')
        ticket_comment += 'Договор уже расторгнут.'
    else:
        terminated = GDB.terminate_contract(contract_id)
        if terminated:
            log.info(f'[{contract_id}] TERMINATED')
            ticket_comment += 'Договор расторг.'
        else:
            log.error(f'[{contract_id}] Termination failed')

    # add comment to ticket(s)
    if ticket_comment != '':
        log.info(f'[{contract_id}] Comment: {ticket_comment}')
        for t in tickets:
            GDB.add_comment(contract_id, t['ticket_id'], ticket_comment)
            log.info(f"[{contract_id}] Ticket: {t['issue']} ({t['master']})")

    # build output
    res = {}
    for k in ['contract_id', 'remove_config', 'sw_ip', 'port',
              'terminated', 'ticket_comment']:
        res[k] = eval(k)

    return res


def main():

    import argparse

    parser = argparse.ArgumentParser(description='Terminate contracts.')
    parser.add_argument('contract', nargs='+', help='contract id')
    parser.add_argument('--ignore-acl', action='store_true',
                        help='ignore empty acl')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='print more info messages')

    ARGS = parser.parse_args()

    MODIFIED = {}  # key: sw_ip, val: [contract_id,...]
    SKIPPED = []
    TERMINATED = []

    if ARGS.verbose:
        log.setLevel(logging.INFO)
    else:
        log.setLevel(logging.WARNING)

    contracts = ARGS.contract

    for c in contracts:
        res = client_terminate(c, ARGS.ignore_acl)
        if res is None:
            SKIPPED.append(c)
        elif res['remove_config']:
            # update modified switches
            if res['sw_ip'] in MODIFIED:
                MODIFIED[res['sw_ip']].append(res['contract_id'])
            else:
                MODIFIED[res['sw_ip']] = [res['contract_id']]

    for sw_ip in MODIFIED:
        # TODO: get sw instance from pool
        sw = Switch(sw_ip)
        # backup
        sw.backup()
        # commit to git
        msg = f"Termination: {', '.join(map(str,MODIFIED[sw_ip]))}"
        try:
            params = {'shell': True, 'check': True}
            subprocess.run(f'git -C {git_dir} add {sw_ip}.*', **params)
            subprocess.run((f'git -C {git_dir} commit --quiet -m "{msg}" '
                            f'--author "{git_author}"'), **params)
        except subprocess.CalledProcessError as e:
            log.error(f'[{sw_ip}] failed to commit: {e}')
        # message to operlog
        operlog.add_item(
            f'Изменение настроек на {sw_ip} ({sw.location})', msg)
        # save
        sw.save()

    log.setLevel(logging.INFO)

    if len(SKIPPED) > 0:
        log.warning(f'Skipped contracts: {SKIPPED}')
        TERMINATED = list(set(contracts)-set(SKIPPED))
    else:
        TERMINATED = contracts
    log.info(f'Terminated contracts: {TERMINATED}')


if __name__ == '__main__':
    main()
