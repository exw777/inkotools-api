#!/usr/bin/env python3
# lib/db.py

# internal imports
import logging
import pathlib
import sqlite3
from collections import namedtuple
from threading import Lock

# external imports
import netaddr
from cryptography.fernet import Fernet

# local imports
from .cfg import ROOT_DIR, SECRETS

# module logger
log = logging.getLogger(__name__)

# thread lock
lock = Lock()


class DB:
    """Local switches sqlite database

    Stored in `data` directory. Filename is defined in init.

    Inside database:
    ip stored in integer format (e.g. 2130706433)
    mac stored in plain text (for fuzzy search)
    as bytes without any colons `:` or hyphens `-` (e.g. 0123456789AB)

    In output functions:
    ip displayed as integer octets separated by dots (e.g. 127.0.0.1),
    mac displayed as bytes separated by hyphens (e.g. 01-23-45-67-89-AB)

    """

    # some multiline sql queries used in class

    SCHEMA = '''CREATE TABLE IF NOT EXISTS switches (
                    ip integer PRIMARY KEY,
                    mac text NOT NULL UNIQUE,
                    model text NOT NULL,
                    location text NOT NULL);

                CREATE TABLE IF NOT EXISTS aliases (
                    alias integer PRIMARY KEY,
                    vid integer NOT NULL,
                    ip integer NOT NULL,
                    FOREIGN KEY (ip) REFERENCES switches(ip)
                        ON DELETE CASCADE ON UPDATE CASCADE);

                CREATE TABLE IF NOT EXISTS gdb_users (
                    username text NOT NULL UNIQUE,
                    password text NOT NULL,
                    token text NOT NULL UNIQUE);
            '''

    UPSERT = '''INSERT INTO switches (ip, mac, model, location)
                VALUES ({ip},'{mac}','{model}','{location}')
                ON CONFLICT(ip) DO
                UPDATE SET
                    mac=excluded.mac,
                    model=excluded.model,
                    location=excluded.location
                WHERE
                    switches.mac != excluded.mac OR
                    switches.model != excluded.model OR
                    switches.location != excluded.location;'''

    UPSERT_ALIAS = '''INSERT INTO aliases (alias, vid, ip)
                    VALUES ({alias},{vid},{ip})
                    ON CONFLICT(alias) DO
                    UPDATE SET
                        vid=excluded.vid,
                        ip=excluded.ip
                    WHERE
                        aliases.vid != excluded.vid OR
                        aliases.ip != excluded.ip;
                    '''

    SEARCH = '''SELECT *, count(*) OVER() AS full_count
                FROM switches
                WHERE model LIKE '%{word}%'
                or location LIKE '%{word}%'
                or mac LIKE '%{mac}%'
                LIMIT {limit} OFFSET {offset};
                '''

    def __init__(self, db_name, open_on_init=False):
        # create datadir if not exists
        db_path = ROOT_DIR/'data'
        pathlib.Path(db_path).mkdir(parents=True, exist_ok=True)
        # declare database file to open
        self.db_file = db_path.joinpath(db_name).with_suffix('.db')
        # declare connection status flag
        self.is_connected = False
        # exec initial sql if database file not exists
        if not self.db_file.exists():
            log.warning('No db file found, creating new...')
            self._open()
            if self._cursor.executescript(self.SCHEMA) is not None:
                self._connection.commit()
                log.info('New database created')
        # init cryptography module
        self._crypto = Fernet(SECRETS['secret_key'])
        log.debug('Database initialized')
        # open connection if needed
        if open_on_init and not self.is_connected:
            self._open()

    def __del__(self):
        # close database on exit
        if self.is_connected:
            self._close()

    def _open(self):
        try:
            self._connection = sqlite3.connect(
                self.db_file, check_same_thread=False)
            # use output in sqlite3.Row instead of tuple
            self._connection.row_factory = sqlite3.Row
            # enable foreign keys
            self._connection.execute("PRAGMA foreign_keys = 1")
            self._cursor = self._connection.cursor()
        except Exception as e:
            log.error(e)
        else:
            log.debug('Database opened')
            self.is_connected = True

    def _close(self):
        try:
            self._connection.commit()
            self._connection.close()
        except Exception as e:
            log.error(e)
        else:
            self.is_connected = False
            log.debug('Database closed')

    def _exec(self, sql_query):
        if not self.is_connected:
            self._open()
        log.debug(f'Executing sql: {sql_query}')
        try:
            lock.acquire(True)
            result = self._cursor.execute(sql_query)
        except Exception as e:
            log.error(e)
            return None
        else:
            return result
        finally:
            lock.release()

    def _encrypt(self, s: str):
        return self._crypto.encrypt(bytes(s, 'utf-8')).decode()

    def _decrypt(self, s: str):
        return self._crypto.decrypt(bytes(s, 'utf-8')).decode()

    def migrate(self, version: str):
        """Make migration from file"""
        with open(ROOT_DIR/'migrations'/f'{version}.sql', 'r') as f:
            sql = f.read()
            if not self.is_connected:
                self._open()
            log.info(f'Migrating to {version}')
            if self._cursor.executescript(sql) is not None:
                self._connection.commit()
                log.info('Finished successful')

    def add(self, sw):
        """Add new switch or update changes

        sw: can be either Switch class object,
            either dict of strings (ip, mac, model, location)

        Returns:
            1 - Added or updated
            0 - Skipped (no changes)
        """

        # check sw type, convert dict to named tuple
        if isinstance(sw, dict):
            sw = namedtuple('Switch', sw)(**sw)

        query = self.UPSERT.format(
            ip=int(netaddr.IPAddress(str(sw.ip))),
            mac=netaddr.EUI(sw.mac).format(netaddr.mac_bare),
            model=sw.model,
            location=sw.location
        )
        result = self._exec(query)
        if result is not None:
            if result.rowcount == 0:
                log.debug(f'{sw.ip} already exists')
            else:
                self._connection.commit()
                log.info(f'{sw.ip} added to database')
            return result.rowcount
        else:
            log.error(f'{sw.ip} failed')
            return None

    def add_many(self, sw_list):
        """Same as add, but for list of switches

        Returns: count of added/updated items
        """
        cnt = 0
        for sw in sw_list:
            cnt += self.add(sw)
        log.info(f'Added {cnt} items')
        return cnt

    def get(self, sw_ip):
        """Get switch entry

        Returns: dict of strings (ip, mac, model, location)
        """
        query = "SELECT * from switches WHERE ip = '{ip}';".format(
            ip=int(netaddr.IPAddress(str(sw_ip))))
        result = self._exec(query).fetchone()
        if result is not None:
            return sw_row_format(result)
        else:
            log.debug(f'{sw_ip} not found')
            return None

    def delete(self, sw_ip):
        """Delete switch by ip

        Returns:
            1 - Deleted
            0 - Skipped (no changes)
        """
        query = "DELETE from switches WHERE ip = '{ip}';".format(
            ip=int(netaddr.IPAddress(str(sw_ip))))
        result = self._exec(query)
        if result is not None:
            if result.rowcount == 0:
                log.debug(f'{sw_ip} already deleted')
            else:
                self._connection.commit()
                log.info(f'{sw_ip} deleted from database')
            return result.rowcount
        else:
            log.error(f'{sw_ip} failed')
            return None

    def clear(self):
        """Flush all entries

        Returns: count of deleted items
        """
        query = "DELETE from switches;"
        result = self._exec(query)
        if result is not None:
            if result.rowcount == 0:
                log.debug('No changes')
            else:
                self._connection.commit()
                log.info(f'Cleared {result.rowcount} items')
            return result.rowcount
        else:
            log.error(f'Failed to clear database')
            return None

    def search(self, word, per_page=10, page=1):
        """Search by mac, model or location

        Returns: list of dicts of strings (ip, mac, model, location)
        """
        # for mac search without '-' and ':'
        query = self.SEARCH.format(
            word=word,
            mac=word.replace(':', '').replace('-', ''),
            limit=per_page,
            offset=(page-1)*per_page)
        result = []
        full_count = 0
        for row in self._exec(query):
            if full_count == 0:
                full_count = row['full_count']
            result.append(sw_row_format(row))
        count = len(result)
        page_count = full_count // per_page
        if full_count > (page_count * per_page):
            page_count += 1
        if count == 0 and page == 1:
            return {"error": "Not found", "status_code": 404}
        elif count == 0 and page > 1:
            return {"error": "Page out of range", "status_code": 422}

        meta = {
            "entries": {
                "current": count,
                "total": full_count,
                "per_page": per_page},
            "pages": {
                "current": page,
                "total": page_count}
        }
        return {"data": result, "meta": meta}

    def ip_list(self):
        """Get list of all ip addresses"""
        result = []
        query = 'SELECT ip from switches ORDER BY ip;'
        for row in self._exec(query):
            result.append(str(netaddr.IPAddress(row['ip'])))
        return result

    def add_aliases(self, sw_ip, aliases):
        """Add list of aliases to database"""
        cnt = 0
        for item in aliases:
            query = self.UPSERT_ALIAS.format(
                alias=int(netaddr.IPAddress(str(item['alias']))),
                vid=item['vid'],
                ip=int(netaddr.IPAddress(str(sw_ip)))
            )
            res = self._exec(query)
            if res is not None:
                if res.rowcount == 0:
                    log.debug(f"{item['alias']} already exists")
                else:
                    self._connection.commit()
                    log.info(f"{item['alias']} added to database")
                    cnt += res.rowcount
            else:
                log.error(f"{item['alias']} failed")
        return cnt

    def get_aliases(self, alias: str = None, vid: int = None, ip: str = None):
        """Search in aliases"""
        query = 'SELECT * from aliases'
        if alias is not None or vid is not None or ip is not None:
            query += ' WHERE'
            if alias is not None:
                query += " alias = '{alias}'".format(
                    alias=int(netaddr.IPAddress(str(alias))))
            if vid is not None:
                query += " vid = '{vid}'".format(vid=vid)
            if ip is not None:
                query += " ip = '{ip}'".format(
                    ip=int(netaddr.IPAddress(str(ip))))
        query += ';'

        return [alias_row_format(row) for row in self._exec(query)]

    def add_gdb_user(self, username: str, password: str, token: str):
        """Add or update graydatabase user credentials"""
        user = self.get_gdb_user(username)
        if user is not None:
            # check changes in password or token
            if user['password'] != password or user['token'] != token:
                msg = f'Updating user [{username}]'
                sql = "UPDATE gdb_users \
                        SET password = '{password}', token = '{token}' \
                        WHERE username = '{username}';"
            else:
                msg = f'Nothing to change for [{username}]'
                log.debug(msg)
                return msg
        else:
            msg = f'Adding new user [{username}]'
            sql = "INSERT INTO gdb_users (username, password, token) \
                        VALUES ('{username}','{password}','{token}');"

        query = sql.format(
            username=username,
            password=self._encrypt(password),
            token=token)

        res = self._exec(query)
        if res is None:
            msg += ' failed'
            log.error(msg)
            return {"error": msg}
        else:
            self._connection.commit()
            msg += ' succeeded'
            log.info(msg)
            return msg

    def get_gdb_user(self, keyword: str):
        """Get user by name or token"""
        sql = "SELECT * FROM gdb_users \
                    WHERE username = '{keyword}' OR token = '{keyword}'"
        query = sql.format(keyword=keyword)
        res = self._exec(query).fetchone()
        if res is None:
            log.debug(f'{keyword} not found')
        else:
            res = dict(res)
            res['password'] = self._decrypt(res['password'])
        return res

    def delete_gdb_user(self, username: str):
        """Remove gdb user from database"""
        sql = "DELETE FROM gdb_users WHERE username = '{username}'"
        query = sql.format(username=username)
        res = self._exec(query)
        msg = f'Deleting [{username}]'
        if res is not None:
            if res.rowcount == 0:
                msg += ' skipped (not found)'
                log.debug(msg)
            else:
                self._connection.commit()
                msg += ' succeeded'
                log.info(msg)
            return msg
        else:
            msg += ' failed'
            log.error(msg)
            return {"error": msg}


def sw_row_format(row):
    """Format sqlite switch row output to dict"""
    row = dict(row)
    row['ip'] = str(netaddr.IPAddress(row['ip']))
    row['mac'] = str(netaddr.EUI(row['mac']))
    # remove full_count from search
    if 'full_count' in row.keys():
        row.pop('full_count')
    return row


def alias_row_format(row):
    """Format sqlite alias row output to dict"""
    row = dict(row)
    row['alias'] = str(netaddr.IPAddress(row['alias']))
    row['ip'] = str(netaddr.IPAddress(row['ip']))
    return row
