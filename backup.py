#!/usr/bin/env python3
# backup.py

# batch backup and save switches

import asyncio
import logging
import re
import subprocess
import time
from inkotools.lib.db import DB
from inkotools.lib.sw import batch_async
from inkotools.lib.cfg import COMMON

log = logging.getLogger()


def is_failed(res):
    return isinstance(res, dict) and 'error' in res


def backup_and_save(sw):
    try:
        res = sw.backup()
    except sw.ModelError:
        pass
    except Exception as e:
        sw.log.error(f'Backup exception: {e}')
    else:
        # if backup is failed try again one more time
        if is_failed(res) and is_failed(sw.backup()):
            failed_backup.append(str(sw.ip))

    try:
        res = sw.save()
    except sw.ModelError:
        pass
    except Exception as e:
        sw.log.error(f'Saving exception: {e}')


def do_backup(sw_list=[]):
    failed_backup = []
    asyncio.run(batch_async(sw_list, backup_and_save, external=True))
    if len(failed_backup) > 0:
        log.warning(f'Failed switches: {failed_backup}')
    return failed_backup


def do_git(failed_backup=[]):
    git_dir = COMMON['backup_path']
    git_author = COMMON['git_author']
    try:
        params = {'shell': True, 'check': True,
                  'text': True, 'capture_output': True}
        subprocess.run(f'git -C {git_dir} add .', **params)
        r = subprocess.run(f'git -C {git_dir} status --short', **params)
        if r.stdout == '':
            log.info('No changes - nothing to commit')
            exit()
        commit_files = r.stdout.strip().split('\n')
        rgx = r' (?P<file>(?P<ip>[\d.]+)\.\w+)'
        for line in commit_files:
            r = re.search(rgx, line)
            # restore files with failed backup
            if r['ip'] in failed_backup:
                log.warning(f"Restored {r['file']}")
                subprocess.run(
                    (f'git -C {git_dir} restore '
                     f"--staged --worktree {r['file']}"), **params)
            else:
                log.info(f"Commited {r['file']}")
        subprocess.run(
            (f'git -C {git_dir} commit '
             f"-m \"Automatic backup at {time.strftime('%F %T')}\" "
             f'--author "{git_author}"'), **params)
        subprocess.run(f'git -C {git_dir} push', **params)
    except subprocess.CalledProcessError as e:
        log.error(e)


def main():
    # backup and save swithces
    db = DB(COMMON['DB_FILE'])
    sw_list = db.ip_list()
    log.setLevel(logging.ERROR)
    failed_backup = do_backup(sw_list)

    # commit and push changes
    log.setLevel(logging.INFO)
    do_git(failed_backup)


if __name__ == '__main__':
    main()
