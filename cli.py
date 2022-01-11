#!/usr/bin/env python3
# cli.py

# internal imports
import argparse
import logging
import signal

# external imports

# local imports
from lib.config import COMMON
from lib.db import DB
from lib.sw import Switch, full_ip

# module logger
log = logging.getLogger(__name__)


# Exit on ctrl+c and ctrl+z
def exit_handler(signal_received, frame):
    exit()


signal.signal(signal.SIGINT, exit_handler)  # ctlr + c
signal.signal(signal.SIGTSTP, exit_handler)  # ctlr + z


def serve_module(module):
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


main_parser = argparse.ArgumentParser()
module_parser = main_parser.add_subparsers(dest='module')

sw_parser = module_parser.add_parser('sw')
sw_parser.add_argument('ip', type=str)
sw_parser.add_argument('-p', '--proxychains',  action='store_true')
sw_parser.add_argument('-i', '--interact', action='store_true')

db_parser = module_parser.add_parser('db')

ARGS = main_parser.parse_args()

if ARGS.module == 'sw':
    ip = full_ip(ARGS.ip)
    data = None
    if ARGS.proxychains:
        log.debug('proxychains mode enabled')
        # get local data
        db = DB(COMMON['DB_FILE'])
        data = db.get(ip)
        if data is None:
            log.fatal('Failed to get data from local database')
            exit(1)
    try:
        sw = Switch(ip, offline_data=data)
    except Switch.UnavailableError as e:
        exit(e)
    if ARGS.interact:
        sw.interact()
    else:
        serve_module('sw')

elif ARGS.module == 'db':
    db = DB(COMMON['DB_FILE'])
    serve_module('db')
