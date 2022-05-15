#!/usr/bin/env python3
# cli.py

# internal imports
import argparse
import logging
import signal
from getpass import getpass
from time import time

# external imports
from colorama import Fore, Back, Style

# local imports
from lib.cfg import COMMON, NETS, write_cfg
from lib.db import DB
from lib.sw import Switch, full_ip, short_ip

# module logger
log = logging.getLogger(__name__)

# init db
db = DB(COMMON['DB_FILE'])

# make model colors from colorama values
MODEL_COLORS = {}
for model in COMMON['MODEL_COLORS']:
    vals = []
    for key in COMMON['MODEL_COLORS'][model]:
        vals.append(f"{key}.{COMMON['MODEL_COLORS'][model][key]}")
    MODEL_COLORS[model] = eval(' + '.join(vals))


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


def sw_interact(sw):

    if sw.model in MODEL_COLORS:
        model_color = MODEL_COLORS[sw.model]
    else:
        model_color = MODEL_COLORS['DEFAULT']

    prompt_line = Fore.YELLOW + sw.model + Fore.RESET \
        + ' [' + Fore.CYAN + short_ip(sw.ip) + Fore.RESET + '] ' \
        + model_color + sw.location + Fore.RESET + Style.RESET_ALL

    # set terminal title
    term_title = f'[{short_ip(sw.ip)}] {sw.location}'
    print(f'\33]0;{term_title}\a', end='', flush=True)

    print(prompt_line)
    sw.interact()
    print('\nInteraction completed')


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


def update_aliases():
    """Update aliases for l3 switches"""
    for s in db.search('DXS-3600-32S')['data']:
        sw = Switch(s['ip'])
        log.info(f'Adding aliases for {sw.ip}')
        cnt = db.add_aliases(sw.ip, sw.get_aliases())
        log.info(f'Done, {cnt} entries added/updated.')


def migrate_database(version: str):
    """Migrate database"""
    db.migrate(version)


def config_setup():
    """User-interactive secrets setup"""
    secrets = dict()
    for profile in ['user_profile', 'admin_profile', 'gray_database']:
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
    sw_parser.add_argument('-i', '--interact', action='store_true')

    # db module
    db_parser = module_parser.add_parser('db')
    db_parser.add_argument('-u', '--update', action='store_true')
    db_parser.add_argument('--update-aliases', action='store_true')
    db_parser.add_argument('--migrate', metavar='VERSION', type=str)

    # cfg module
    cfg_parser = module_parser.add_parser('cfg')
    cfg_parser.add_argument('-s', '--setup', action='store_true')

    # parse arguments
    ARGS = main_parser.parse_args()

    # main logic
    if ARGS.module == 'sw':
        ip = full_ip(ARGS.ip)
        data = None
        if COMMON['tcp_only_mode']:
            # get local data
            data = db.get(ip)
        try:
            global sw
            if data is not None:
                sw = Switch(**data)
            else:
                sw = Switch(ip)
                if COMMON['tcp_only_mode']:
                    db.add(sw)

            if ARGS.interact:
                sw_interact(sw)
            else:
                serve_module('sw')

        except (Switch.UnavailableError, Switch.ModelError) as e:
            exit(e)
        except Switch.CredentialsError as e:
            log.error(e)
            exit('Run cfg --setup')

    elif ARGS.module == 'db':
        if ARGS.migrate:
            migrate_database(ARGS.migrate)
        if ARGS.update:
            update_database()
        if ARGS.update_aliases:
            update_aliases()
        # serve_module('db')

    elif ARGS.module == 'cfg':
        if ARGS.setup:
            config_setup()


if __name__ == '__main__':
    main()
