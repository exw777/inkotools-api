#!/usr/bin/env python3
# config.py

import pathlib
import yaml
import logging

log = logging.getLogger()

CONF_DIR = pathlib.Path.cwd() / 'config'

config = {'secrets': {},
          'logger': {},
          }

# check configuration files, copy from defaults if not exists
for key in config.keys():
    conf = CONF_DIR.joinpath(key).with_suffix('.yml')
    if not conf.exists():
        log.warning(f'{conf.name} - copying from default sample...')
        conf.write_text(conf.with_suffix('.sample.yml').read_text())
    try:
        config[key] = yaml.safe_load(conf.read_text())
    except Exception as e:
        log.error(f'Error while loading {conf.name}: {str(e)}')
