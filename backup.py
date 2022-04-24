#!/usr/bin/env python3
# backup.py

# batch backup and save switches

import asyncio
import logging
import subprocess
import time
from inkotools.lib.db import DB
from inkotools.lib.sw import batch_async
from inkotools.lib.cfg import COMMON

log = logging.getLogger()

db = DB(COMMON['DB_FILE'])

git_dir = COMMON['backup_path']
git_author = COMMON['git_author']


def backup_and_save(sw):
    try:
        sw.backup()
    except sw.ModelError:
        pass
    except Exception as e:
        sw.log.error(f'Backup exception: {e}')
    try:
        sw.save()
    except sw.ModelError:
        pass
    except Exception as e:
        sw.log.error(f'Saving exception: {e}')


def main():
    # backup and save swithces
    log.setLevel(logging.ERROR)
    asyncio.run(batch_async(db.ip_list(), backup_and_save, external=True))

    # commit and push changes
    log.setLevel(logging.INFO)
    try:
        params = {'shell': True, 'check': True,
                  'text': True, 'capture_output': True}
        subprocess.run(f'git -C {git_dir} add .', **params)
        r = subprocess.run(f'git -C {git_dir} status --short', **params)
        if r.stdout == '':
            log.info('No changes - nothing to commit')
            exit()
        [log.info(l) for l in r.stdout.strip().split('\n')]
        subprocess.run(
            (f'git -C {git_dir} commit '
             f"-m \"Automatic backup at {time.strftime('%F %T')}\" "
             f'--author "{git_author}"'), **params)
        subprocess.run(f'git -C {git_dir} push', **params)
    except subprocess.CalledProcessError as e:
        log.error(e)


if __name__ == '__main__':
    main()
