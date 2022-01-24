#!/usr/bin/env python3
# wsgi.py

# internal imports
import logging

# external imports
from flask import Flask, request, jsonify

# local imports
from lib.config import COMMON
from lib.db import DB
from lib.sw import Switch

# module logger
log = logging.getLogger(__name__)

# init db
db = DB(COMMON['DB_FILE'])

# init flask
app = Flask(__name__)

# init switches storage
SWITCHES = {}


def get_sw_instance(ip):
    if ip in SWITCHES:
        log.debug(f'attaching to existing instance of {ip}')
        sw = SWITCHES[ip]
    else:
        if COMMON['no_snmp_mode']:
            data = db.get(ip)
        else:
            data = None
        log.debug(f'creating new switch {ip}')
        try:
            sw = Switch(ip, offline_data=data)
        except Switch.UnavailableError as e:
            log.error(e)
            return None
        SWITCHES[ip] = sw
    return sw


@app.route('/db/list')
def db_list():
    return jsonify(db.ip_list())


@app.route('/db/search', methods=['POST'])
def db_search():
    data = request.json
    log.debug(f"Got data: {data}")
    try:
        keyword = data['keyword']
    except KeyError:
        return "no keyword\n", 400
    else:
        return jsonify(db.search(str(keyword)))


@app.route('/db/sw/<ip>', methods=['GET'])
def db_sw_get(ip):
    try:
        result = db.get(ip)
    except Exception as e:
        return f'{e}\n', 500
    if result is None:
        return f'Switch {ip} not found\n', 404
    else:
        return jsonify(result)


@app.route('/db/sw/<ip>', methods=['DELETE'])
def db_sw_delete(ip):
    try:
        result = db.delete(ip)
    except Exception as e:
        return f'{e}\n', 500
    if result == 0:
        return f'{ip} skipped (not found)\n'
    elif result == 1:
        return f'{ip} removed from database\n'
    else:
        return 501


@app.route('/db/sw/<ip>', methods=['POST'])
def db_sw_add(ip):
    try:
        sw = get_sw_instance(ip)
        result = db.add(sw)
    except Switch.UnavailableError:
        return f'{ip} is not available\n', 404
    except Exception as e:
        return f'{e}\n', 500
    if result == 0:
        return f'{ip} skipped (no changes)\n'
    elif result == 1:
        return f'{ip} added to database\n'
    else:
        return 501


@app.route('/sw/<ip>', methods=['GET'])
def sw_ip(ip):
    try:
        data = db.get(ip)
        sw = get_sw_instance(ip)
    except Exception as e:
        return f'{e}\n', 500
    if sw is None and data is None:
        return f'{ip} not found\n', 404
    status = False
    if sw is not None:
        status = sw.is_alive()
    data['status'] = status
    return jsonify(data)


@app.route('/sw/<ip>/<func>', methods=['GET', 'POST'])
def sw_ip_func(ip, func):
    # TODO: func validation
    sw = get_sw_instance(ip)
    if sw is None:
        return f'{ip} is not available\n', 404
    data = request.json
    log.debug(f'[{ip}] request func: {func}, data: {data}')
    try:
        if data is None:
            result = eval(f'sw.{func}()')
        else:
            result = eval(f'sw.{func}(**data)')
    except Exception as e:
        return f'{e}\n', 500
    else:
        return jsonify(result)
