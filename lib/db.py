#!/usr/bin/env python3
# lib/db.py

# internal imports
import asyncio
from contextlib import contextmanager
import logging
import pathlib
import sqlite3
from time import time

# external imports
import netaddr

# local imports
from .config import ROOT_DIR, NETS
from .sw import Switch, batch_async

# module logger
log = logging.getLogger(__name__)

# debug
log.setLevel(10)

DATA_PATH = ROOT_DIR/'data'
DATABASE = DATA_PATH/'switches2.db'


class DB:

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

        # Check datadir exists
        db_path = ROOT_DIR/'data'
        pathlib.Path(db_path).mkdir(parents=True, exist_ok=True)

        self.db_file = db_path.joinpath(db_name).with_suffix('.db')

        # declare connection status flag
        self.is_connected = False

        # check database exists
        if not self.db_file.exists():
            log.warning('No db file found, creating new...')
            if self._exec(self.SCHEMA):
                self._connection.commit()
                log.info('New database created')

        log.debug('DB class created')

    def __del__(self):
        if self.is_connected:
            self._close()
        log.debug('DB class deleted')

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
        Returns:
        1 - Added or updated
        0 - Skipped (no changes)
        """

        query = self.UPSERT.format(
            ip=int(sw.ip), mac=sw.mac.format(netaddr.mac_bare),
            model=sw.model, location=sw.location)
        result = self._exec(query)
        if result:
            if result.rowcount == 0:
                log.debug(f'{sw.ip} already exists, skipping')
            else:
                self._connection.commit()
                log.info(f'{sw.ip} added to database')
            return result.rowcount
        else:
            log.error(f'adding {sw.ip} failed')
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
        if result:
            if result.rowcount == 0:
                log.debug(f'{sw_ip} already deleted, skipping')
            else:
                self._connection.commit()
                log.info(f'{sw_ip} deleted from database')
            return result.rowcount
        else:
            log.error(f'deleting {sw_ip} failed')
            return None

    def update(self):
        """Add all available switches to database"""
        # TODO: check tainted swithces
        log.info('Database generation started')
        cnt = 0
        start = time()
        # asyncio.run(batch_async(NETS, self.add, external=True))
        # TODO: async run, generate sql query and run it once
        for ip in NETS:
            try:
                sw = Switch(ip)
            except Switch.UnavailableError:
                log.debug(f'Skipping {ip}')
            else:
                log.debug(f'Adding {ip}')
                if self.add(sw):
                    cnt += 1
        end = time() - start
        log.info(
            f'Database generation finished in {end:.2f}s (added {cnt} items)')
        return cnt

    def clear(self):
        query = "DELETE from switches;"
        result = self._exec(query)
        if result:
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
        """Search by mac, model or location"""
        result = []
        # for mac search without '-' and ':'
        query = self.SEARCH.format(
            word=word, mac=word.replace(':', '').replace('-', ''))
        for row in self._exec(query):
            result.append(self._row_format(row))
        return result

    def ip_list(self):
        result = []
        query = 'SELECT ip from switches ORDER BY ip;'
        for row in self._exec(query):
            result.append(str(netaddr.IPAddress(row['ip'])))
        return result
