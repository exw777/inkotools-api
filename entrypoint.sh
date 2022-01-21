#!/usr/bin/env sh

set -eo pipefail
# DEBUG
# set -x

USER_ID=$(id -u)

export GUNICORN_CMD_ARGS="--worker-class gthread --threads $GUNICORN_THREADS --bind 0.0.0.0:$LISTEN_PORT"

if [ -n "$PROXYCHAINS_ENABLED" ]; then
    echo "Proxychains enabled, starting with config:"
    cat $PROXYCHAINS_CONFIG_FILE
    if [ "$USER_ID" == "0"  ]; then
        exec su-exec user proxychains -q -f $PROXYCHAINS_CONFIG_FILE $@
    else
        exec proxychains -f $PROXYCHAINS_CONFIG_FILE $@
    fi
else
    if [ "$USER_ID" == "0"  ]; then
        exec su-exec user $@
    else
        exec $@
    fi
fi
