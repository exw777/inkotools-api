#!/usr/bin/env python3
# cli.py

# internal imports
import argparse
import logging
import signal
from getpass import getpass
from time import time

# external imports

# local imports
from lib.config import COMMON, NETS, write_cfg
from lib.db import DB
from lib.sw import Switch, full_ip

# module logger
log = logging.getLogger(__name__)

# init db
db = DB(COMMON['DB_FILE'])


def exit_handler(signal_received, frame):
    """Handler to exit on signals"""
    exit()


def serve_module(module):
    """User-interactive cli for module functions"""
    # TODO: add completions and history
    prompt = f'{module}>'
    while True:
        try:
            cmd = input(prompt)
        except EOFError:
            print(f'\n{prompt}')
            continue
        if cmd == 'exit':
            break
        elif cmd != '':
            try:
                print(eval(f'{module}.{cmd}'))
            except Exception as e:
                log.error(e)


def update_database():
    """Full update of database"""
    log.info('Scanning for new switches, please wait...')
    start = time()
    cnt = 0
    for ip in NETS:
        try:
            sw = Switch(ip)
        except Switch.UnavailableError:
            log.debug(f'{ip} is unavailable, skipping')
            # check if unavailable switch is in database
            if db.get(ip) is not None:
                log.warning(f'{ip} is unavailable')
        else:
            cnt += db.add(sw)
    end = time() - start
    log.info(f'Done in {end:.2f}s, {cnt} items added/updated.')


def config_setup():
    """User-interactive secrets setup"""
    secrets = dict()
    for profile in ['user_profile', 'admin_profile']:
        print(f'Setting up {profile}')
        secrets[profile] = dict()
        secrets[profile]['login'] = input('login: ')
        secrets[profile]['password'] = getpass('password: ')
    write_cfg('secrets', secrets)


def main():

    # exit on ctrl+c and ctrl+z
    signal.signal(signal.SIGINT, exit_handler)
    signal.signal(signal.SIGTSTP, exit_handler)

    main_parser = argparse.ArgumentParser()
    module_parser = main_parser.add_subparsers(dest='module')

    # sw module
    sw_parser = module_parser.add_parser('sw')
    sw_parser.add_argument('ip', type=str)
    sw_parser.add_argument('-p', '--proxychains', action='store_true')
    sw_parser.add_argument('-i', '--interact', action='store_true')

    # db module
    db_parser = module_parser.add_parser('db')
    db_parser.add_argument('-u', '--update', action='store_true')

    # cfg module
    cfg_parser = module_parser.add_parser('cfg')
    cfg_parser.add_argument('-s', '--setup', action='store_true')

    # parse arguments
    ARGS = main_parser.parse_args()

    # main logic
    if ARGS.module == 'sw':
        ip = full_ip(ARGS.ip)
        data = None
        if ARGS.proxychains:
            log.debug('proxychains mode enabled')
            # get local data
            data = db.get(ip)
            if data is None:
                log.fatal('Failed to get data from local database')
                exit(1)
        try:
            sw = Switch(ip, offline_data=data)
        except Switch.UnavailableError as e:
            exit(e)
        try:
            if ARGS.interact:
                sw.interact()
            else:
                serve_module('sw')
        except Switch.CredentialsError as e:
            log.error(e)
            exit('Run cfg --setup')

    elif ARGS.module == 'db':
        if ARGS.update:
            update_database()
        serve_module('db')

    elif ARGS.module == 'cfg':
        if ARGS.setup:
            config_setup()


if __name__ == '__main__':
    main()
