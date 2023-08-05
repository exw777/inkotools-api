#!/usr/bin/env sh

set -eo pipefail
# DEBUG
# set -x

USER_ID=$(id -u)

export GUNICORN_CMD_ARGS="--worker-class uvicorn.workers.UvicornWorker --threads $GUNICORN_THREADS --bind $LISTEN_IP:$LISTEN_PORT"

if [ "$USER_ID" == "0"  ]; then
    exec su-exec user $@
else
    exec $@
fi
