FROM python:3.10-alpine AS base

FROM base AS build
WORKDIR /deps

COPY requirements.txt /
RUN apk update && apk add --update-cache \
        gcc \
        libc-dev \
        build-base \
        net-snmp-dev && \
    pip install --target=/deps -r /requirements.txt

FROM base 
WORKDIR /app/

RUN mkdir /app/data/ && \
    chown 1000:1000 /app/data/

VOLUME ["/app/data/", "/app/config/"]

RUN apk update && apk add --no-cache \
        su-exec \
        busybox-extras \
        proxychains-ng \
        net-snmp-libs \
        tzdata && \
    pip install gunicorn && \
    adduser --disabled-password -u 1000 -s /bin/sh user

ENV GUNICORN_THREADS=4 \
    LISTEN_PORT=9999 \
    PROXYCHAINS_ENABLED="" \
    PROXYCHAINS_CONFIG_FILE="/etc/proxychains/proxychains.conf" \
    PYTHONPATH="${PYTHONPATH}:/deps"

EXPOSE $LISTEN_PORT

ENTRYPOINT ["/entrypoint.sh"]

CMD ["gunicorn", "asgi:app"]

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

COPY --from=build /deps /deps

COPY --chown=1000 ./inkotools/ /app/
