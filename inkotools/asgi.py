#!/usr/bin/env python3
# asgi.py

# internal imports
import logging
import re
import secrets
from ipaddress import IPv4Address
from typing import Optional

# external imports
from fastapi import FastAPI, HTTPException, Body
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError, validator

# local imports
from lib.cfg import COMMON, NETS, SECRETS
from lib.db import DB
from lib.sw import Switch, ipcalc
from lib.gdb import GRAYDB

# module logger
log = logging.getLogger(__name__)


# init db
db = DB(COMMON['DB_FILE'])

# init fastapi
app = FastAPI()

# init switches storage
SWITCHES = {}

# init gdb users storage
GDB_USERS = {}

# TODO: move this part to pool
# gdb account for common use
GDB = GRAYDB(COMMON['GRAYDB_URL'], SECRETS['gray_database'])


def get_sw_instance(sw_ip):
    # convert sw_ip from ipaddr.IPv4Address type to string
    sw_ip = str(sw_ip)
    try:
        # check if ip is l3 alias
        if sw_ip not in NETS:
            log.debug(f'Searching aliases for {sw_ip}')
            res = db.get_aliases(alias=sw_ip)
            if len(res) == 1:
                sw_ip = res[0]['ip']
                log.debug(f'Found: {sw_ip}')
            else:
                log.debug(f'Alias for {sw_ip} not found')
                raise Switch.UnavailableError(f'{sw_ip} not found')

        if sw_ip in SWITCHES:
            log.debug(f'attaching to existing instance of {sw_ip}')
            sw = SWITCHES[sw_ip]
            if not sw.is_alive():
                raise Switch.UnavailableError(f'{sw_ip} is not available')
        else:
            log.debug(f'creating new switch {sw_ip}')
            if COMMON['tcp_only_mode']:
                data = db.get(sw_ip)
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


def get_gdb_instance(token):
    if token in GDB_USERS:
        log.debug('Attaching to existing gdb instance')
    else:
        # search for user in database
        user = db.get_gdb_user(token)
        if user is None:
            raise GRAYDB.CredentialsError('Invalid token')
        creds = {"login": user['username'], "password": user['password']}
        GDB_USERS[token] = GRAYDB(COMMON['GRAYDB_URL'], creds)
        log.debug(f"New gdb instance for [{user['username']}]")
    return GDB_USERS[token]


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
            status_code=422, detail='no supported ports found')
    if port_id not in ports_range:
        raise HTTPException(
            status_code=422, detail=f'port {port_id} is out of range')


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    """Override validation errors formatting"""
    detail = ', '.join(
        map(lambda err: err["loc"][-1] + ' - ' + err["msg"], exc.errors()))
    return JSONResponse(content={"detail": detail}, status_code=422)


@app.exception_handler(GRAYDB.NotFoundError)
async def graydb_404_exception_handler(request, exc):
    """Gray database not found error handler"""
    return JSONResponse(content={"detail": str(exc)}, status_code=404)


@app.exception_handler(GRAYDB.CredentialsError)
async def graydb_creds_exception_handler(request, exc):
    """Gray database credentials error handler"""
    return JSONResponse(content={"detail": str(exc)}, status_code=401)


@app.exception_handler(Switch.ModelError)
async def sw_model_exception_handler(request, exc):
    """Switch wrong model error handler"""
    return JSONResponse(content={"detail": str(exc)}, status_code=422)


@app.exception_handler(Switch.UnavailableError)
async def sw_unavailable_exception_handler(request, exc):
    """Switch unavailable error handler"""
    return JSONResponse(content={"detail": str(exc)}, status_code=503)


class ArpSearchModel(BaseModel):
    ip: Optional[IPv4Address] = None
    gw_ip: Optional[IPv4Address] = None
    src_sw_ip: Optional[IPv4Address] = None
    vid: Optional[int] = None
    mac: Optional[str] = None

    @validator('ip')
    def ip_range(cls, v):
        if int(str(v).split('.')[2]) in COMMON['SERVICE_VLANS']:
            raise ValueError(f'{v} is not from clients subnet')
        return v

    @validator('vid')
    def vid_range(cls, v):
        if (not (v in range(2, 255) or v in COMMON['PIP_VLANS'])
                or v in COMMON['SERVICE_VLANS']):
            raise ValueError(f'{v} is not valid for client subnet')
        return v

    @validator('vid')
    def vid_src_required(cls, v, values):
        if (v in COMMON['PIP_VLANS']
            and 'ip' not in values
            and 'src_sw_ip' not in values
                and 'gw_ip' not in values):
            raise ValueError('PIP VID search needs src_sw_ip or gw_ip')
        return v

    @validator('mac')
    def mac_valid(cls, v):
        if not re.match(r'^([a-fA-F0-9]{2}[:-]?){5}[a-fA-F0-9]{2}$', v):
            raise ValueError('must be valid MAC address')
        return v

    @validator('mac')
    def mac_src_required(cls, v, values):
        if 'src_sw_ip' not in values and 'gw_ip' not in values:
            raise ValueError('MAC search needs src_sw_ip or gw_ip')
        return v


@app.post('/arpsearch')
def arp_search(req: ArpSearchModel):
    if req.ip is None and req.mac is None and req.vid is None:
        raise HTTPException(status_code=422,
                            detail=('At least one of the following values '
                                    'must be provided: ip, mac, vid'))

    ip = None if req.ip is None else str(req.ip)
    gw = None if req.gw_ip is None else str(req.gw_ip)
    src_sw = None if req.src_sw_ip is None else str(req.src_sw_ip)

    if gw is None:
        if ip is not None:
            gw = ipcalc(req.ip)['gateway']
        elif req.vid is not None and req.vid in range(255):
            gw = f'192.168.{req.vid}.1'
        elif src_sw is not None:
            # get first client subnet from source switch for gateway
            sw = get_sw_instance(src_sw)
            for vl in sw.get_vlan_list():
                if vl in range(255) and vl not in COMMON['SERVICE_VLANS']:
                    gw = f'192.168.{vl}.1'
                    break

    if gw is None:
        raise HTTPException(
            status_code=500, detail='Failed to determine gateway')
    sw = get_sw_instance(gw)
    data = sw.get_arp_table(ip=ip, vid=req.vid, mac=req.mac,
                            check_mac_state=True)
    meta = {"entries": len(data), "gateway": str(sw.ip)}
    return fmt_result(data, meta)


class AliasesModel(BaseModel):
    alias: Optional[IPv4Address] = None
    vid: Optional[int] = None
    ip: Optional[IPv4Address] = None


@app.post('/db/aliases')
def database_aliases_search(search: AliasesModel):
    data = db.get_aliases(**dict(search))
    return fmt_result(data, meta={"entries": len(data)})


class SearchModel(BaseModel):
    keyword: str
    per_page: Optional[int] = 10
    page: Optional[int] = 1


@app.post('/db/search')
def database_search(search: SearchModel):
    res = db.search(search.keyword, search.per_page, search.page)
    try:
        # try to extract data and meta
        return fmt_result(**res)
    except Exception:
        # if returned error
        return fmt_result(res)


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


class ContractID(str):
    """Contract id field type"""

    @classmethod
    def __get_validators__(cls):
        yield cls.validate_contract_id

    @classmethod
    def validate_contract_id(cls, v):
        if not re.search(r'^\d{5}$', v):
            raise ValueError('invalid contract id')
        return cls(v)


class CredsModel(BaseModel):
    login: str
    password: str


@app.get('/gdb/user')
def gdb_get_user(token: str = Body(..., embed=True)):
    gdb = get_gdb_instance(token)
    username = gdb.credentials['login']
    return fmt_result({"username": username})


# @app.delete('/gdb/user')
# def gdb_delete_user(username: str = Body(..., embed=True)):
#     res = db.delete_gdb_user(username)
#     return fmt_result(res)


@app.post('/gdb/user/get_token')
def gdb_user_get_token(creds: CredsModel):
    # search user in db
    user = db.get_gdb_user(creds.login)
    if user is not None and user['password'] == creds.password:
        log.debug(f'Using existing token for [{creds.login}]')
        token = user['token']
    else:
        # generate new 32-bytes token
        log.info(f'Generating new token for [{creds.login}]')
        token = secrets.token_hex(32)
        # create new gdb instance for password validation
        GDB_USERS[token] = GRAYDB(COMMON['GRAYDB_URL'], dict(creds))
        # add user to database
        db.add_gdb_user(username=creds.login, password=creds.password,
                        token=token)
    return fmt_result({"token": token})


@app.get('/gdb/user/tickets')
def gdb_get_user_tickets(token: str = Body(..., embed=True)):
    gdb = get_gdb_instance(token)
    data = gdb.get_tickets()
    meta = {"entries": len(data), "username": gdb.credentials['login']}
    return fmt_result(data, meta)


@app.post('/gdb/{contract_id}/tickets/{ticket_id}/')
def gdb_add_ticket_comment(contract_id: ContractID, ticket_id: int,
                           token: str = Body(..., embed=True),
                           comment: str = Body(..., embed=True)):
    gdb = get_gdb_instance(token)
    res = gdb.add_comment(contract_id=contract_id, ticket_id=ticket_id,
                          comment=comment)
    return fmt_result(res)


@app.get('/gdb/{contract_id}/')
def gdb_get_client_by_contract_full(contract_id: ContractID, style: str = ''):
    if style == 'short':
        data = GDB.get_client_data(contract_id)
    elif style == 'billing':
        data = GDB.get_billing_accounts(contract_id)
    # default: full
    else:
        data = GDB.get_client_data(contract_id)
        data['billing_accounts'] = GDB.get_billing_accounts(contract_id)
    return fmt_result(data)


@app.get('/gdb/by-ip/{client_ip}/')
def gdb_get_client_by_ip_full(client_ip: IPv4Address, style: str = ''):
    contract_id = GDB.get_contract_by_ip(client_ip)
    return gdb_get_client_by_contract_full(contract_id, style)


@app.get('/ipcalc/{ip}/')
def get_ipcalc_summary(ip: IPv4Address):
    data = ipcalc(ip)
    if data['prefix'] == 32:
        raise HTTPException(
            status_code=404, detail=f'{ip} not found in client subnets')
    return fmt_result(data)


@app.get('/pool')
def pool_get_list():
    data = list(SWITCHES.keys())
    return fmt_result(data, meta={"entries": len(data)})


@app.delete('/pool')
def pool_clear():
    SWITCHES.clear()
    return fmt_result("Pool cleared")


@app.delete('/pool/{sw_ip}/')
def pool_delete_item(sw_ip: IPv4Address):
    sw_ip = str(sw_ip)
    if not sw_ip in SWITCHES:
        raise HTTPException(
            status_code=404, detail=f'{sw_ip} instance not found in pool')
    del SWITCHES[sw_ip]
    return fmt_result(f'{sw_ip} instance removed from pool')


@app.post('/pool/{sw_ip}/')
def pool_add_item(sw_ip: IPv4Address):
    sw_ip = str(sw_ip)
    # remove old instance if exists
    if sw_ip in SWITCHES:
        del SWITCHES[sw_ip]
        msg = 'recreated in'
    else:
        msg = 'added to'
    # create new instance
    get_sw_instance(sw_ip)
    return fmt_result(f'{sw_ip} instance {msg} pool')


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
        data = db.get(sw.ip)
        new_data = {"ip": str(sw.ip),
                    "mac": str(sw.mac),
                    "model": sw.model,
                    "location": sw.location}
        # update offline data on changes
        if new_data != data:
            log.info(f'Updating offline data for {sw.ip}')
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
    return fmt_result(result)


@app.get('/sw/{sw_ip}/backup')
def switch_backup(sw_ip: IPv4Address):
    sw = get_sw_instance(sw_ip)
    result = sw.backup()
    return fmt_result(result)


@app.get('/sw/{sw_ip}/vlans/')
def switch_get_vlans_list(sw_ip: IPv4Address):
    sw = get_sw_instance(sw_ip)
    return fmt_result(sw.get_vlan_list())


@app.get('/sw/{sw_ip}/multicast')
def switch_get_mcast_ports(sw_ip: IPv4Address):
    sw = get_sw_instance(sw_ip)
    return fmt_result(sw.get_mcast_ports())


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
    for port in result:
        # add cable diagnostics for copper ports without link
        if port['type'] == 'C' and not port['link']:
            try:
                cable = sw.check_cable(port_id)
            except Switch.ModelError:
                cable = None
            if isinstance(cable, str):
                # 'no cable' string
                port['status'] = cable
            else:
                port['cable'] = cable
        # add ddm transceiver info for fiber ports
        elif port['type'] == 'F':
            try:
                ddm = sw.get_port_ddm(port_id)
                # remove port item (duplicated in common summary)
                ddm.pop('port')
                # clear object if all values are None
                if set(ddm.values()) == {None}:
                    ddm = None
                port['ddm'] = ddm
            except Switch.ModelError:
                pass

    return fmt_result(result)


@app.get('/sw/{sw_ip}/ports/{port_id}/acl')
def switch_get_port_acl(sw_ip: IPv4Address, port_id: int):
    sw = get_sw_instance(sw_ip)
    validate_port(sw, port_id)
    return fmt_result(sw.get_acl(port_id))


@app.get('/sw/{sw_ip}/ports/{port_id}/ddm')
def switch_get_port_ddm(sw_ip: IPv4Address, port_id: int):
    sw = get_sw_instance(sw_ip)
    validate_port(sw, port_id)
    return fmt_result(sw.get_port_ddm(port_id))


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


@app.get('/sw/{sw_ip}/ports/{port_id}/bandwidth')
def switch_get_port_bandwidth(sw_ip: IPv4Address, port_id: int):
    sw = get_sw_instance(sw_ip)
    validate_port(sw, port_id)
    data = sw.get_port_bandwidth(port=port_id)
    return fmt_result(data)


@app.get('/sw/{sw_ip}/ports/{port_id}/mcast/groups')
def switch_get_port_mcast_groups(sw_ip: IPv4Address, port_id: int):
    sw = get_sw_instance(sw_ip)
    validate_port(sw, port_id)
    data = sw.get_port_mcast_groups(port=port_id)
    return fmt_result(data)


@app.get('/sw/{sw_ip}/ports/{port_id}/mcast/filters')
def switch_get_port_mcast_filters(sw_ip: IPv4Address, port_id: int):
    sw = get_sw_instance(sw_ip)
    validate_port(sw, port_id)
    data = sw.get_port_mcast_filters(port=port_id)
    return fmt_result(data)
