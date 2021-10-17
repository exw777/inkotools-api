#!/usr/bin/env python3
# config.py

import pathlib
import yaml
import logging

CONF_DIR = pathlib.Path.cwd() / 'config'

log = logging.getLogger()
# check configuration files, copy from defaults if not exists
for sample in CONF_DIR.glob('*.sample.yml'):
    conf = CONF_DIR / sample.stem.replace('.sample', '.yml')
    if not conf.exists():
        log.warning(f'{conf.name} - copying from default sample...')
        conf.write_text(sample.read_text())

    # load conf from file name.yml to var NAME
    try:
        exec(f'{conf.stem.upper()} = yaml.safe_load(conf.read_text())')
    except Exception as e:
        log.error(f'Error while loading {conf.name}: {str(e)}')
