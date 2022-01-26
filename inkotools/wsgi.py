#!/usr/bin/env python3
# wsgi.py

# internal imports
import logging

# external imports
from flask import Flask, request, jsonify
from netaddr import valid_glob as valid_ip

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


def json_err(title, status=None, detail=None):
    """Returns error according to json api standart"""
    args = locals()
    err = {}
    for k, v in args.items():
        if v is not None:
            err[k] = str(v)
    return jsonify(errors=[err])


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


@app.route('/sw/<ip>/', methods=['GET'])
def sw_ip(ip):
    if not valid_ip(ip):
        return json_err('Invalid ip address', 400), 400
    try:
        data = db.get(ip)
        sw = get_sw_instance(ip)
    except Exception as e:
        return json_err("Server error", 500, e), 500
    if sw is None and data is None:
        return json_err('Switch not found', 404), 404
    status = False
    if sw is not None:
        status = sw.is_alive()
    data['status'] = status
    return jsonify(data=data)


# TODO: api routes based on functions

@app.route('/sw/<ip>/<func>', methods=['GET', 'POST'])
def sw_ip_func(ip, func):
    if not valid_ip(ip):
        return json_err('Invalid ip address', 400), 400
    sw = get_sw_instance(ip)
    if sw is None:
        return json_err('Switch not found', 404), 404

    func_args = request.json
    log.debug(f'[{ip}] request func: {func}, args: {func_args}')

    # first check if func is sw property
    if func in sw.__dict__:
        result = eval(f'sw.{func}')
    elif not func in sw.help():
        return json_err('Wrong function', 400), 400
    else:
        try:
            if func_args is None:
                result = eval(f'sw.{func}()')
            else:
                result = eval(f'sw.{func}(**func_args)')
        except TypeError as e:
            return json_err("Type error", 400, e), 400
        except Exception as e:
            return json_err("Server error", 500, e), 500

    return jsonify(data=result)
