#!/usr/bin/env python3
# db.py

import sqlite3
from contextlib import contextmanager
from sw import Switch, NETS
from netaddr import IPAddress as ip, EUI as mac

DATABASE = 'data/switches.db'

SCHEMA = '''CREATE TABLE IF NOT EXISTS switches (
        ip integer PRIMARY KEY,
        mac integer NOT NULL UNIQUE,
        model text NOT NULL,
        location text NOT NULL)'''


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
    result = []
    with _cursor() as cur:
        for row in cur.execute('SELECT ip from switches ORDER BY ip'):
            result.append(str(ip(row[0])))
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


def sw_upsert(sw_ip):
    try:
        sw = Switch(sw_ip)
        with _cursor() as cur:
            r = f'''INSERT INTO switches (ip, mac, model, location) VALUES
                    ({int(sw.ip)},{int(sw.mac)},'{sw.model}','{sw.location}')
                    ON CONFLICT(ip) DO UPDATE SET
                        mac=excluded.mac,
                        model=excluded.model,
                        location=excluded.location
                    WHERE
                        switches.mac != excluded.mac OR
                        switches.model != excluded.model OR
                        switches.location != excluded.location;
                    '''
            cur.execute(r)
            result = cur.rowcount
    except Exception as e:
        result = e
    return result


def db_generate():
    with _cursor() as cur:
        cur.execute('DELETE FROM switches;')
        for i in NETS:
            try:
                sw = Switch(i)
            except Exception:
                pass
            else:
                print(f'Adding {i}')
                r = f'''INSERT INTO switches (ip, mac, model, location) VALUES
                    ({int(sw.ip)},{int(sw.mac)},'{sw.model}','{sw.location}')
                    '''
                cur.execute(r)
        result = cur.rowcount
    return result


_db_init()

if __name__ == '__main__':
    import argparse

    arg_parser = argparse.ArgumentParser()
    arg_commands = arg_parser.add_subparsers(dest='command')
    arg_commands.add_parser('generate')
    arg_commands.add_parser('list')
    cmd_get = arg_commands.add_parser('get')
    cmd_get.add_argument('ip', type=str)
    cmd_del = arg_commands.add_parser('delete')
    cmd_del.add_argument('ip', type=str)
    cmd_add = arg_commands.add_parser('add')
    cmd_add.add_argument('ip', type=str)

    args = arg_parser.parse_args()

    if args.command == 'generate':
        db_generate()

    if args.command == 'list':
        sw_list = sw_list()
        for i in sw_list:
            print(i)
        print(f'Total: {len(sw_list)} swithces')

    if args.command == 'get':
        print(sw_get(args.ip))
    if args.command == 'add':
        print(sw_upsert(args.ip))
    if args.command == 'delete':
        print(sw_delete(args.ip))
