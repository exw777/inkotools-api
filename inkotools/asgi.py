#!/usr/bin/env python3
# asgi.py

# internal imports
import logging
import re
from ipaddress import IPv4Address
from typing import Optional

# external imports
from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError, validator

# local imports
from lib.cfg import COMMON, NETS
from lib.db import DB
from lib.sw import Switch, ipcalc

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
            log.debug(f'creating new switch {sw_ip}')
            if COMMON['tcp_only_mode']:
                if sw_ip in NETS:
                    data = db.get(sw_ip)
                else:
                    # workaround not to get model via telnet on arp requests
                    data = {"ip": sw_ip, "model": "DXS-3600-32S"}
            else:
                data = None

            if data is not None:
                sw = Switch(**data)
            else:
                sw = Switch(sw_ip)

            SWITCHES[str(sw.ip)] = sw

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


def fmt_result(data, meta=None):
    """Format value according to internal api standart"""
    if isinstance(data, str):
        return {"detail": data}
    elif isinstance(data, dict) and 'error' in data.keys():
        # parse error returned from function
        detail = str(data['error'])
        try:
            status_code = int(data['status_code'])
        except Exception:
            status_code = 500

        raise HTTPException(status_code=status_code, detail=detail)

    # add additional info
    if meta is not None:
        return {"data": data, "meta": meta}

    return {"data": data}


def validate_port(sw: Switch, port_id: int):
    """Check if port is in switch ports range"""
    ports_range = sw.access_ports + sw.transit_ports
    if len(ports_range) == 0:
        raise HTTPException(
            status_code=422, detail=f'{sw.model} not supported')
    if port_id not in ports_range:
        raise HTTPException(
            status_code=422, detail=f'port {port_id} is out of range')


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    """Override validation errors formatting"""
    detail = ', '.join(
        map(lambda err: err["loc"][-1]+' - ' + err["msg"], exc.errors()))
    return JSONResponse({"detail": detail}, status_code=422)


class ArpSearchModel(BaseModel):
    ip: Optional[IPv4Address] = None
    vid: Optional[int] = None
    mac: Optional[str] = None

    @validator('ip')
    def ip_range(cls, v):
        if int(str(v).split('.')[2]) in [57, 58, 59, 60, 47, 49, 123]:
            raise ValueError(f'{v} is not from clients subnet')
        return v

    @validator('vid')
    def vid_range(cls, v):
        if (not (v in range(255) or v in [1148, 1150, 1151, 1152])
                or v in [57, 58, 59, 60, 47, 49, 123]):
            raise ValueError(f'{v} is not valid for client subnet')
        return v

    @validator('mac')
    def mac_valid(cls, v):
        if not re.match(r'^([a-fA-F0-9]{2}[:-]?){5}[a-fA-F0-9]{2}$', v):
            raise ValueError('must be valid MAC address')
        return v

    @validator('mac')
    def vid_required(cls, v, values):
        if values['vid'] is None:
            raise ValueError('VID is required for MAC search')
        return v


@app.post('/arpsearch')
def arp_search(req: ArpSearchModel):
    if req.ip is None and req.mac is None and req.vid is None:
        raise HTTPException(status_code=422,
                            detail=('At least one of the following values '
                                    'must be provided: ip, mac, vid'))
    gw = None
    ip = None
    if req.ip is not None:
        ip = str(req.ip)
        gw = ipcalc(req.ip)['gateway']
    elif req.vid is not None:
        if req.vid in [1148, 1150, 1151, 1152]:
            HTTPException(
                satus_code=409,
                detail=f'Search MAC for VID {req.vid} not implemented yet')
        gw = f'192.168.{str(req.vid)}.1'

    if gw is None:
        raise HTTPException(
            status_code=500, detail='Failed to determine gateway')
    sw = get_sw_instance(gw)
    data = sw.get_arp_table(ip=ip, vid=req.vid, mac=req.mac)
    return fmt_result(data, meta={"entries": len(data)})


class SearchModel(BaseModel):
    keyword: str


@app.post('/db/search')
def database_search(search: SearchModel):
    data = db.search(search.keyword)
    return fmt_result(data, meta={"entries": len(data)})


@app.get('/db/sw/{sw_ip}/')
def database_get_switch(sw_ip: IPv4Address):
    result = db.get(sw_ip)
    if result is None:
        raise HTTPException(
            status_code=404, detail=f'{sw_ip} not found')
    return fmt_result(result)


@app.delete('/db/sw/{sw_ip}/')
def database_delete_switch(sw_ip: IPv4Address):
    result = db.delete(sw_ip)
    if result == 0:
        return fmt_result(f'{sw_ip} skipped (not found)')
    elif result == 1:
        return fmt_result(f'{sw_ip} removed from database')
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
        return fmt_result(f'{sw_ip} skipped (no changes)')
    elif result == 1:
        return fmt_result(f'{sw_ip} added to database')
    else:
        raise HTTPException(
            status_code=500, detail=f'failed to add {sw_ip}')


@app.get('/ipcalc/{ip}/')
def get_ipcalc_summary(ip: IPv4Address):
    data = ipcalc(ip)
    if data['prefix'] == 32:
        raise HTTPException(
            status_code=404, detail=f'{ip} not found in client subnets')
    return fmt_result(data)


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
    return fmt_result(data)


@app.get('/sw/{sw_ip}/save')
def switch_save(sw_ip: IPv4Address):
    sw = get_sw_instance(sw_ip)
    result = sw.save()
    if result is None:
        raise HTTPException(
            status_code=500, detail=f'failed to save {sw_ip}')
    return fmt_result(result)


@app.get('/sw/{sw_ip}/backup')
def switch_backup(sw_ip: IPv4Address):
    sw = get_sw_instance(sw_ip)
    result = sw.backup()
    if result is None:
        raise HTTPException(
            status_code=500, detail=f'failed to backup {sw_ip}')
    return fmt_result(result)


@app.get('/sw/{sw_ip}/vlans/')
def switch_get_vlans_list(sw_ip: IPv4Address):
    sw = get_sw_instance(sw_ip)
    return fmt_result(sw.get_vlan_list())


@app.get('/sw/{sw_ip}/ports/')
def switch_get_ports_list(sw_ip: IPv4Address):
    sw = get_sw_instance(sw_ip)
    # check that switch has at least one port
    validate_port(sw, 1)
    data = {"access_ports": sw.access_ports,
            "transit_ports": sw.transit_ports}
    return fmt_result(data)


@app.get('/sw/{sw_ip}/ports/{port_id}/')
def switch_get_port_summary(sw_ip: IPv4Address, port_id: int):
    sw = get_sw_instance(sw_ip)
    validate_port(sw, port_id)
    result = sw.get_port_state(port_id)
    if result is None:
        raise HTTPException(
            status_code=500, detail=f'failed to get port summary')
    elif (isinstance(result[0], dict)
          and not result[0]['link']
          and port_id in sw.access_ports):
        cable = sw.check_cable(port_id)
        if isinstance(cable, str):
            result[0]['status'] = cable
        else:
            result[0]['cable'] = cable

    return fmt_result(result)


@app.get('/sw/{sw_ip}/ports/{port_id}/acl')
def switch_get_port_acl(sw_ip: IPv4Address, port_id: int):
    sw = get_sw_instance(sw_ip)
    validate_port(sw, port_id)
    return fmt_result(sw.get_acl(port_id))


@app.get('/sw/{sw_ip}/ports/{port_id}/vlan')
def switch_get_port_vlan(sw_ip: IPv4Address, port_id: int):
    sw = get_sw_instance(sw_ip)
    validate_port(sw, port_id)
    return fmt_result(sw.get_vlan_port(port_id))


@app.get('/sw/{sw_ip}/ports/{port_id}/counters')
def switch_get_port_counters(sw_ip: IPv4Address, port_id: int):
    sw = get_sw_instance(sw_ip)
    validate_port(sw, port_id)
    return fmt_result(sw.get_port_counters(port_id))


@app.delete('/sw/{sw_ip}/ports/{port_id}/counters')
def switch_clear_port_counters(sw_ip: IPv4Address, port_id: int):
    sw = get_sw_instance(sw_ip)
    validate_port(sw, port_id)
    return fmt_result(sw.clear_port_counters(port_id))


@app.get('/sw/{sw_ip}/ports/{port_id}/mac')
def switch_get_port_mac_table(sw_ip: IPv4Address, port_id: int):
    sw = get_sw_instance(sw_ip)
    validate_port(sw, port_id)
    data = sw.get_mac_table(port=port_id)
    return fmt_result(data, meta={"entries": len(data)})
