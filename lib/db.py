#!/usr/bin/env python3
# lib/db.py

# internal imports
import logging
import pathlib
import sqlite3
from collections import namedtuple

# external imports
import netaddr

# local imports
from .config import ROOT_DIR

# module logger
log = logging.getLogger(__name__)


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
            location text NOT NULL)'''

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

    SEARCH = '''SELECT * from switches
                WHERE model LIKE '%{word}%'
                or location LIKE '%{word}%'
                or mac LIKE '%{mac}%';
                '''

    def __init__(self, db_name):
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
            if self._exec(self.SCHEMA) is not None:
                self._connection.commit()
                log.info('New database created')

    def __del__(self):
        # close database on exit
        if self.is_connected:
            self._close()

    def _open(self):
        try:
            self._connection = sqlite3.connect(self.db_file)
            # use output in sqlite3.Row instead of tuple
            self._connection.row_factory = sqlite3.Row
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
            result = self._cursor.execute(sql_query)
        except Exception as e:
            log.error(e)
            return None
        else:
            return result

    def _row_format(self, row):
        """Format sqlite row output to dict"""
        row = dict(row)
        row['ip'] = str(netaddr.IPAddress(row['ip']))
        row['mac'] = str(netaddr.EUI(row['mac']))
        return row

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
            ip=int(netaddr.IPAddress(sw.ip)),
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
        return(cnt)

    def get(self, sw_ip):
        """Get switch entry

        Returns: dict of strings (ip, mac, model, location)
        """
        query = "SELECT * from switches WHERE ip = '{ip}';".format(
            ip=int(netaddr.IPAddress(sw_ip)))
        result = self._exec(query).fetchone()
        if result is not None:
            return self._row_format(result)
        else:
            log.error(f'{sw_ip} failed')
            return None

    def delete(self, sw_ip):
        """Delete switch by ip

        Returns:
            1 - Deleted
            0 - Skipped (no changes)
        """
        query = "DELETE from switches WHERE ip = '{ip}';".format(
            ip=int(netaddr.IPAddress(sw_ip)))
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

    def search(self, word):
        """Search by mac, model or location

        Returns: list of dicts of strings (ip, mac, model, location)
        """
        result = []
        # for mac search without '-' and ':'
        query = self.SEARCH.format(
            word=word, mac=word.replace(':', '').replace('-', ''))
        for row in self._exec(query):
            result.append(self._row_format(row))
        return result

    def ip_list(self):
        """Get list of all ip addresses"""
        result = []
        query = 'SELECT ip from switches ORDER BY ip;'
        for row in self._exec(query):
            result.append(str(netaddr.IPAddress(row['ip'])))
        return result
