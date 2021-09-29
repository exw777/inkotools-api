#!/usr/bin/env python3
# db.py

import sqlite3
from contextlib import contextmanager
from sw import Switch
from netaddr import IPAddress as ip, EUI as mac
from pprint import pprint

DATABASE = 'data/switches.db'

SCHEMA = '''CREATE TABLE IF NOT EXISTS switches (
        ip integer PRIMARY KEY,
        mac integer NOT NULL UNIQUE,
        model text NOT NULL,
        location text NOT NULL)'''

UPSERT = '''INSERT INTO switches (ip, mac, model, location)
            VALUES ({ip},{mac},'{model}','{location}')
            ON CONFLICT(ip) DO
            UPDATE SET
                mac=excluded.mac,
                model=excluded.model,
                location=excluded.location
            WHERE
                switches.mac != excluded.mac OR
                switches.model != excluded.model OR
                switches.location != excluded.location;'''

SEARCH = '''SELECT * from switches
            WHERE model LIKE '%{word}%'
            or location LIKE '%{word}%';
            '''


def _row_convert(row):
    r = list(row)
    r[0] = str(ip(r[0]))
    r[1] = str(mac(r[1]))
    r = tuple(r)
    return r


@contextmanager
def _cursor():
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    yield cur
    conn.commit()
    conn.close()


def _db_init():
    with _cursor() as cur:
        cur.execute(SCHEMA)


def sw_list():
    l = []
    with _cursor() as cur:
        for row in cur.execute('SELECT ip from switches ORDER BY ip;'):
            l.append(str(ip(row[0])))
    result = {'switches': l, 'total': len(l)}
    return result


def sw_get(sw_ip):
    with _cursor() as cur:
        cur.execute(f"SELECT * from switches WHERE ip = '{int(ip(sw_ip))}';")
        result = cur.fetchone()
        if result:
            result = _row_convert(tuple(result))
    return result


def sw_delete(sw_ip):
    with _cursor() as cur:
        cur.execute(f"DELETE from switches WHERE ip = '{int(ip(sw_ip))}';")
        result = cur.rowcount
    return result


def sw_add(sw_ip):
    """Add new switch or update changes
    Returns:
     1 - Added or updated
     0 - Nothing to change
    -1 - Switch is unavailable
    """
    try:
        sw = Switch(sw_ip)
        with _cursor() as cur:
            query = UPSERT.format(ip=int(sw.ip),
                                  mac=int(sw.mac),
                                  model=sw.model,
                                  location=sw.location)
            cur.execute(query)
            result = cur.rowcount
    except Switch.UnavailableError:
        result = -1
    return result


def sw_search(word):
    """Search word in model or location"""
    l = []
    query = SEARCH.format(word=word)
    with _cursor() as cur:
        for row in cur.execute(query):
            l.append(_row_convert(row))
    result = {'result': l, 'total': len(l)}
    return result


_db_init()

if __name__ == '__main__':
    import argparse
    from sw import NETS, full_ip

    CMD = ['generate', 'list']
    IP_CMD = ['add', 'get', 'delete']

    arg_parser = argparse.ArgumentParser()
    arg_commands = arg_parser.add_subparsers(dest='command')

    for c in CMD:
        arg_commands.add_parser(c)
    for c in IP_CMD:
        a = arg_commands.add_parser(c)
        a.add_argument('ip', type=str)

    arg_commands.add_parser('search').add_argument('word', type=str)

    args = arg_parser.parse_args()

    if args.command == 'generate':
        with _cursor() as cur:
            print('Flushing table')
            cur.execute('DELETE FROM switches;')
            for i in NETS:
                try:
                    sw = Switch(i)
                except Switch.UnavailableError:
                    pass
                else:
                    print(f'Adding {i}')
                    query = UPSERT.format(ip=int(sw.ip),
                                          mac=int(sw.mac),
                                          model=sw.model,
                                          location=sw.location)
                    cur.execute(query)
        print('Done')

    if args.command == 'list':
        sw_list = sw_list()
        for i in sw_list:
            print(i)
        print(f'Total: {len(sw_list)} swithces')

    if args.command in IP_CMD:
        print(eval(f'sw_{args.command}(full_ip(args.ip))'))

    if args.command == 'search':
        s = sw_search(args.word)
        for r in s['result']:
            print(f'{r[0]:<15}| {r[1]} | {r[2]:<18} | {r[3]}')
        print(f"Total: {s['total']}")
