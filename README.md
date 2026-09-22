# WS-Smuggler

WS-Smuggler — учебный проект для анализа и демонстрации уязвимостей WebSocket, связанных с десинхронизацией и смешением кадров (frame smuggling). Проект сочетает в себе низкоуровневую работу с TCP/TLS и ручную сборку WebSocket-фреймов по спецификации RFC 6455.

Проект предназначен для лабораторной проверки поведения прокси, балансировщиков и WebSocket-серверов при аномальных заголовках и нестандартных фреймах.

---
## Архитектура и Структура проекта

Проект спроектирован по модульному принципу. Для обеспечения полного контроля над структурой сетевых пакетов и манипуляции битами кадров (RFC 6455) логика утилиты построена на использовании низкоуровневых системных сокетов.

## Что входит в проект

- низкоуровневое подключение через Python `socket` и `ssl`;
- HTTP Upgrade handshake для WebSocket;
- проверка `Sec-WebSocket-Accept` по RFC 6455;
- сборка кадров вручную через побитовые операции;
- локальный Docker-стенд для демонстрации трафика и проксирования;
- базовые unit-тесты на проверку корректности handshake и frame-builder.

---

## Структура проекта

```text
utility/
├── README.md
├── requirements.txt
├── .gitignore
├── src/
│   ├── main.py
│   ├── __init__.py
│   └── core/
│       ├── __init__.py
│       ├── connection.py
│       ├── frame_builder.py
│       └── traffic_logger.py
├── tests/
│   └── test_frames.py
├── config/
│   └── default_payloads.json
├── dumps/
│   └── test.pcap
├── reports/
│   └── test.json
├── WebStand/
│   ├── docker-compose.yml
│   ├── cert-generator/
│   ├── certs/
│   ├── logs/
│   ├── haproxy-spring/
│   ├── nginx-nodejs/
│   └── nginx-python/
└── venv/
```

---
## Технологический Стек

* **Язык разработки:** Python 3.11+
* **Сетевой уровень:** `socket`, `ssl`
* **Интерфейс (TUI):** 
  * `rich` — визуальное оформление таблиц, логов и Hex-дампов.
  * `prompt_toolkit` — интерактивный ввод с поддержкой истории и автодополнения.
* **Автоматизация CLI:** `click` / `argparse`

---
## Основные компоненты

### 1. WSConnection

Класс в [src/core/connection.py](src/core/connection.py) отвечает за:

- создание TCP-соединения;
- TLS-обёртку для `wss://`;
- отправку HTTP Upgrade запроса;
- чтение HTTP-ответа;
- валидацию `Sec-WebSocket-Accept`;
- корректное закрытие сокета при ошибках.

### 2. FrameBuilder

Класс в [src/core/frame_builder.py](src/core/frame_builder.py) отвечает за:

- сборку WebSocket frame через побитовые операции;
- поддержку `FIN` и `RSV1-3`;
- поддержу opcode: text, binary, close, ping, pong;
- маскирование payload со стороны клиента;
- параметр `custom_length` для fuzzing и desync-тестов.

### 3. WebStand

Локальный тестовый стенд в [WebStand/docker-compose.yml](WebStand/docker-compose.yml) используется для проверки поведения прокси и серверов в условиях реального сетевого взаимодействия.

---

## Установка и запуск

### 1. Клонирование репозитория и подготовка
```bash
git clone https://github.com/la1n-1wakura/utility.git
cd ws-smuggler
```

### 2. Подготовка окружения

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Запуск unit-тестов

```bash
python3 -m pytest -q tests/test_frames.py
```

### 4. Запуск CLI утилиты

После запуска утилита показывает TUI-меню выбора режима:

- **Ручной режим** — интерактивная сборка и отправка кадров;
- **Автоматический режим** — запланированные сценарии fuzzing;
- **Запись трафика** — будущая запись сырого обмена в hex/pcap.

Пример запуска:

```bash
python3 src/main.py --host localhost --port 8080 --path /ws/ --ssl --insecure --timeout 5
```

Для запуска ручного режима без меню используется флаг `--manual`.

### Интерактивная консоль

Если запустить программу без `--manual`, открывается постоянная консоль в
стиле инструментов для интерактивного тестирования:

```bash
python3 src/main.py
```

Пример сессии:

```text
ws-smuggler > set host localhost
ws-smuggler > set port 8080
ws-smuggler > set path /ws/
ws-smuggler > show options
ws-smuggler > connect
ws-smuggler > use manual
ws-smuggler > run
ws-smuggler > disconnect
ws-smuggler > exit
```

Основные команды: `help`, `show options`, `set`, `use`, `connect`, `run`,
`disconnect` и `exit`. Параметры TLS задаются так: `set ssl on`, затем
`set insecure on` для локального самоподписанного сертификата или
`set ca_file /path/to/ca.crt` для проверки через собственный CA.

Параметры подключения:

| Сценарий                      | Команда                                                             |
| Обычный WebSocket             | `python3 src/main.py --host localhost --port 8080`                  |
| TLS с проверкой сертификата   | `python3 src/main.py --host example.com --port 443 --ssl`           |
| TLS с собственным CA          | `python3 src/main.py --host localhost --port 8443 --ssl --ca-file WebStand/certs/ca.crt` |
| Лабораторный TLS без проверки | `python3 src/main.py --host localhost --port 8443 --ssl --insecure` |

`--insecure` и `--ca-file` нельзя использовать одновременно. Оба параметра
требуют флаг `--ssl`. Режим `--insecure` предназначен только для локального
стенда с самоподписанным сертификатом.

### 5. Ручная отправка WebSocket-фреймов

После успешного handshake можно оставить соединение открытым и отправлять кадры
через `FrameBuilder` в интерактивном режиме:

```bash
python3 src/main.py --host localhost --port 8080 --path /ws/ --manual --timeout 5
```

В ручном режиме утилита запрашивает payload, opcode, флаги `FIN` и `Mask`, а
также необязательный `custom_length`. Значение `custom_length` позволяет
проверять реакцию прокси и backend на расхождение между заявленной длиной и
фактическим payload. Для завершения введите `:quit`.

---

## Запуск локального стенда

```bash
docker compose -f WebStand/docker-compose.yml up --build
```

После запуска можно проверить доступность сервисов через порты:

- `8080` — Nginx + Python backend
- `8081` — Nginx + Node.js backend
- `8082` — HAProxy + Spring backend

---

## Текущие цели проекта

Проект направлен на исследование следующих классов уязвимостей:

- WebSocket Frame Smuggling;
- десинхронизация между прокси и backend;
- аномальная длина кадров;
- обработка маскированных и немаскированных сообщений;
- дифференциация корректного и аномального `Sec-WebSocket-Accept`.

---

## Функциональные возможности

* **Низкоуровневый конструктор (Manual Mode):** Возможность вручную выставлять биты `FIN`, `Opcode`, управлять флагом маскирования (`Mask`), а также намеренно искажать длину Payload в заголовке кадра для проверки реакций прокси-серверов.
* **Автоматизированные сценарии (Automated Mode):** Готовые тест-кейсы для симуляции атак десинхронизации (например, внедрение скрытого кадра внутрь Payload легитимного сообщения).
* **Контроль трафика:** Логирование отправленных аномальных байт в формате Hex-дампа и экспорт сессий в `.pcap` для последующего анализа в Wireshark.
* **Отчетность:** Выгрузка структурированных отчетов в формате JSON/HTML для интеграции с процессами DevSecOps.
---

## Ограничения и безопасность

Данный проект используется исключительно в лабораторных и учебных целях для исследования сетевой безопасности. Не используйте его против систем, к которым у вас нет права доступа.

---

## Disclaimer

Данный проект создан в рамках исследовательской и образовательной работы и предназначен для легального аудита сетевой безопасности и анализа протоколов.
