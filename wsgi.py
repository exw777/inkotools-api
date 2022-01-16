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


@app.route('/db/<ip>', methods=['GET', 'POST', 'DELETE'])
def db_ip(ip):
    # replace http methods to functions names
    r = request.method.lower().replace('post', 'add')
    result = eval(f'db.{r}(ip)')
    return jsonify(result)


@app.route('/sw/<ip>', methods=['GET'])
def sw_ip(ip):
    data = db.get(ip)
    sw = get_sw_instance(ip)
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
    log.debug(f'request func: {func}, data: {data}')
    if data is None:
        result = eval(f'sw.{func}()')
    else:
        result = eval(f'sw.{func}(**data)')
    return jsonify(result)
