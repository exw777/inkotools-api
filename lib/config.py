#!/usr/bin/env python3
# lib/config.py

# internal imports
import logging
import logging.config
import pathlib
import yaml

# external imports
from colorama import Fore, Back, Style
import netaddr

# module logger
log = logging.getLogger(__name__)

# app root path is relative to lib
ROOT_DIR = pathlib.Path(__file__).parents[1]


def load_cfg(cfg_name):
    """load config from yml file"""
    conf = (ROOT_DIR/'config').joinpath(cfg_name).with_suffix('.yml')
    if not conf.exists():
        log.warning(
            f'{conf.name} not found, trying to copy from default sample...')
        try:
            conf.write_text(conf.with_suffix('.sample.yml').read_text())
        except FileNotFoundError:
            log.error(f'Configuration for `{cfg_name}` not found')
            return None
    try:
        result = yaml.safe_load(conf.read_text())
    except Exception as e:
        log.error(f'Error while loading {conf.name}: {str(e)}')
        return None
    else:
        log.debug(f'{conf.name} loaded')
        return result


# load global logger settings
logging.config.dictConfig(load_cfg('logger'))

# credetials
SECRETS = load_cfg('secrets')

# common settings
COMMON = load_cfg('common')

# calculate possible net ranges for switches
NETS = netaddr.IPSet()
for net in COMMON['NETS']:
    NETS.add(netaddr.IPRange(net['start'], net['end']))

# make model colors from colorama values
MODEL_COLORS = {}
for model in COMMON['MODEL_COLORS']:
    vals = []
    for key in COMMON['MODEL_COLORS'][model]:
        vals.append(f"{key}.{COMMON['MODEL_COLORS'][model][key]}")
    MODEL_COLORS[model] = eval(' + '.join(vals))
