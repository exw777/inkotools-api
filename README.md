[![Publish Status](https://img.shields.io/github/workflow/status/truman369/inkotools-api/Publish%20to%20Docker%20Hub?label=publish&logo=docker&style=plastic)](https://hub.docker.com/r/truman369/inkotools-api/tags)
[![Latest Version](https://img.shields.io/docker/v/truman369/inkotools-api?label=latest&logo=github&sort=semver&style=plastic)](https://github.com/truman369/inkotools-api/tags)
# Inko Tools 
> Скрипты для упрощения работы с коммутаторами в сети ИНКО

> **Внимание!** Проект находится в стадии разработки. Возможны изменения, ломающие обратную совместимость. Данное руководство может иметь незавершенные разделы или отсутствующие описания функций. Для актуальной информации рекомендуется смотреть непосредственно текущий код.

Возможные варианты работы:
- Выполнение команд через утилиту CLI
- Выполнение команд через сервер API
- Использование в собственных скриптах через импорт

## Установка

### Ручная установка из репозитория

Для использования cli достаточно склонировать репозиторий и установить зависимости из `requirements.txt`

> Если при установке зависимости `easysnmp` возникает ошибка, возможно, в системе не установлена библиотека `net-snmp`. Подробнее в руководстве [easysnmp](https://easysnmp.readthedocs.io/en/latest/#installation).

> Если при запуске скриптов возникает ошибка привилегий, возможно, значение параметра ядра `net.ipv4.ping_group_range` равно `1 0`, нужно исправить его на `0 2147483647`. В разных дистрибутивах используются разные значения по умолчанию. Подробнее в документации [icmplib](https://github.com/ValentinBELYN/icmplib/blob/main/docs/6-use-icmplib-without-privileges.md).

Для запуска api потребуется ASGI сервер, например, [uvicorn](https://github.com/encode/uvicorn)

### Запуск в контейнерах docker

Для удобства запуска api в репозитории есть `Dockerfile` для сборки образа. Также можно использовать [готовые образы](https://hub.docker.com/r/truman369/inkotools-api/tags), которые публикуются автоматически при изменениях в репозитории.

> В зависимости от настроек хостовой системы может потребоваться дополнительная настройка параметра ядра `net.ipv4.ping_group_range` для контейнера.

Пример файла `docker-compose.yml`:
```yaml
---
version: "3.7"
services:
  inkotools-api:
    image: truman369/inkotools-api:latest
    container_name: inkotools-api
    hostname: inkotools-api
    init: true
    environment:
      TZ: Europe/Moscow
      # PROXYCHAINS_ENABLED: "yes"
    sysctls:
      net.ipv4.ping_group_range: 0 2147483647
    user: "1000"
    volumes:
      - ./data:/app/data
      - ./config/inkotools:/app/config/user:ro
      # - ./config/proxychains.conf:/etc/proxychains/proxychains.conf:ro
    restart: unless-stopped
    ports:
      - "127.0.0.1:9999:9999"
...
```

## Структура проекта
- `inkotools/`
  - `config/` - директория для конфигурационных файлов.
    - `default/` - системные конфигурационные файлы, **менять их не нужно**. Для внесения изменений скопируйте необходимые параметры в пользовательский файл с тем же именем.
    - `user/` - пользовательские конфигурационные файлы, имеют больший приоритет и перезаписывают системные значения параметров. Все изменения настроек нужно производить в них. 
  - `data/` - директория для файлов баз данных.
  - `lib/` - основные библиотеки проекта.
    - `cfg.py` - функции для инициализации и работы с конфигурацией.
    - `db.py` - функции для работы с внутренней базой данных.
    - `gdb.py` - функции для работы с серой базой.
    - `sw.py` - функции для работы с коммутаторами.
  - `templates/` - директория для шаблонов jinja2.
  - `asgi.py` - приложение API.
  - `cli.py` - утилита CLI.

## Настройка

### Логины и пароли

Для корректной работы необходимо указать логины и пароли для доступа к коммутаторам в файле `secrets.yml`:
- `admin_profile` - узловые коммутаторы
- `user_profile` - коммутаторы доступа
- `gray_database` - учетная запись для доступа к серой базе

Можно скопировать и отредактировать содержимое файла `secrets.sample.yml`, либо задать пароли через утилиту cli:
```shell
./cli.py cfg --setup
```

### Логирование

Настройки логирования хранятся в файле `logger.yml`. Для большинства случаев изменение стандартных настроек не требуется.

Пример изменения уровня оповещений:
```yaml
---
loggers:
  '':
    level: DEBUG
...
```

### Общие настройки
<!-- TODO: описание всех настроек -->
`tcp_only_mode` - при включении не будут импортироваться модули `icmplib`, `easysnmp` и `arpreq`. Вся информация с коммутаторов будет браться только через telnet, а доступность проверяться tcp-запросами на 80 и 23 порты. Данный режим добавлен для возможности использования совместно с [proxychains](https://github.com/rofl0r/proxychains-ng).

## CLI

Подключение через telnet:
```shell
./cli.py sw 59.75 --interact
```

Поиск и добавление в базу новых коммутаторов:
```shell
./cli.py db --update
```

Обновление базы L3-интерфейсов узловых коммутаторов:
```shell
./cli.py db --update-aliases
```

Настройка паролей доступа:
```shell
./cli.py cfg --setup
```

## API

## Описание классов и функций

## Структура базы данных
