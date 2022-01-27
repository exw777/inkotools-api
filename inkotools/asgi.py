#!/usr/bin/env python3
# asgi.py

# internal imports
import logging
from ipaddress import IPv4Address

# external imports
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# local imports
from lib.config import COMMON
from lib.db import DB
from lib.sw import Switch

# module logger
log = logging.getLogger(__name__)


# init db
db = DB(COMMON['DB_FILE'])

# init fastapi
app = FastAPI()

# init switches storage
SWITCHES = {}


def get_sw_instance(sw_ip):
    # convert sw_ip from ipaddr.IPv4Address type to string
    sw_ip = str(sw_ip)
    try:
        if sw_ip in SWITCHES:
            log.debug(f'attaching to existing instance of {sw_ip}')
            sw = SWITCHES[sw_ip]
            if not sw.is_alive():
                raise Switch.UnavailableError()
        else:
            if COMMON['no_snmp_mode']:
                data = db.get(sw_ip)
            else:
                data = None
            log.debug(f'creating new switch {sw_ip}')
            sw = Switch(sw_ip, offline_data=data)
            SWITCHES[sw_ip] = sw

    except Switch.UnavailableError as e:
        log.warning(e)
        if db.get(sw_ip) is None:
            raise HTTPException(
                status_code=404, detail=f'{sw_ip} not found')
        else:
            raise HTTPException(
                status_code=503, detail=f'{sw_ip} is not available')
    else:
        return sw


class SearchModel(BaseModel):
    keyword: str


@app.post('/db/search')
def database_search(search: SearchModel):
    data = db.search(search.keyword)
    return {"data": data, "meta": {"count": len(data)}}


@app.get('/db/sw/{sw_ip}/')
def database_get_switch(sw_ip: IPv4Address):
    result = db.get(sw_ip)
    if result is None:
        raise HTTPException(
            status_code=404, detail=f'{sw_ip} not found')
    return {"data": result}


@app.delete('/db/sw/{sw_ip}/')
def database_delete_switch(sw_ip: IPv4Address):
    result = db.delete(sw_ip)
    if result == 0:
        return {"details": f'{sw_ip} skipped (not found)'}
    elif result == 1:
        return {"details": f'{sw_ip} removed from database'}
    else:
        raise HTTPException(
            status_code=500, detail=f'failed to remove {sw_ip}')


@app.post('/db/sw/{sw_ip}/')
def database_add_switch(sw_ip: IPv4Address):
    sw = get_sw_instance(sw_ip)
    if sw is None:
        raise HTTPException(
            status_code=404, detail=f'{sw_ip} is not available')
    result = db.add(sw)
    if result == 0:
        return {"details": f'{sw_ip} skipped (no changes)'}
    elif result == 1:
        return {"details": f'{sw_ip} added to database'}
    else:
        raise HTTPException(
            status_code=500, detail=f'failed to add {sw_ip}')


@app.get('/sw/{sw_ip}/')
def switch_get_summary(sw_ip: IPv4Address):
    # get offline data
    data = db.get(sw_ip)
    try:
        sw = get_sw_instance(sw_ip)
    except HTTPException:
        status = False
    else:
        status = sw.is_alive()
    # if switch is online, get online data
    if status:
        new_data = {"ip": str(sw.ip),
                    "mac": str(sw.mac),
                    "model": sw.model,
                    "location": sw.location}
        # update offline data on changes
        if new_data != data:
            data = new_data
            db.add(data)
    if data is None:
        raise HTTPException(
            status_code=404, detail=f'{sw_ip} not found')
    data['status'] = status
    return {"data": data}


@app.get('/sw/{sw_ip}/save')
def switch_save(sw_ip: IPv4Address):
    sw = get_sw_instance(sw_ip)
    result = sw.save()
    if result is None:
        raise HTTPException(
            status_code=500, detail=f'failed to save {sw_ip}')
    return {"details": result}


@app.get('/sw/{sw_ip}/backup')
def switch_backup(sw_ip: IPv4Address):
    sw = get_sw_instance(sw_ip)
    result = sw.backup()
    if result is None:
        raise HTTPException(
            status_code=500, detail=f'failed to backup {sw_ip}')
    return {"details": result}


@app.get('/sw/{sw_ip}/ports/')
def switch_get_ports_list(sw_ip: IPv4Address):
    sw = get_sw_instance(sw_ip)
    if len(sw.access_ports + sw.transit_ports) == 0:
        raise HTTPException(
            status_code=422, detail=f'{sw.model} not supported')
    data = {"access_ports": sw.access_ports,
            "transit_ports": sw.transit_ports}
    return {"data": data}


@app.get('/sw/{sw_ip}/ports/{port_id}/')
def switch_get_port_summary(sw_ip: IPv4Address, port_id: int):
    sw = get_sw_instance(sw_ip)
    ports_range = sw.access_ports + sw.transit_ports
    if len(ports_range) == 0:
        raise HTTPException(
            status_code=422, detail=f'{sw.model} not supported')
    if port_id not in ports_range:
        raise HTTPException(
            status_code=422, detail=f'port {port_id} is out of range')
    result = sw.get_port_state(port_id)
    if result is None:
        raise HTTPException(
            status_code=500, detail=f'failed to get port summary')
    return {"data": result}
