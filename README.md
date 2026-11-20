# OTP Secure

**INAI Autumn Hackathon 2026 — задание №6.** REST API выдачи и проверки одноразовых кодов (OTP) с защитой от перебора, спама и гонок.

> **Самое важное для жюри**
>
> * Сгенерированные коды пишутся в файл **`outbox/sms.jsonl`** в корне проекта (JSON Lines), до того как клиент получит HTTP 200.
> * IP клиента = адрес реального TCP-соединения. `X-Forwarded-For` / `X-Real-IP` игнорируются.
> * Всё время реальное: OTP 120 с, блокировка 900 с, IP-окно 60 с, окно отправок 600 с. Эндпоинта для перемотки времени нет.
> * Основной режим проверки — запуск FastAPI напрямую на Linux: `./scripts/run_jury.sh` (раздел 11).

---

## Содержание

1. [Что такое OTP Secure](#1-что-такое-otp-secure)
2. [Основные возможности](#2-основные-возможности)
3. [Технологии](#3-технологии)
4. [Архитектура](#4-архитектура)
5. [Структура папок](#5-структура-папок)
6. [Установка зависимостей](#6-установка-зависимостей)
7. [Настройка Redis](#7-настройка-redis)
8. [Создание .env](#8-создание-env)
9. [Запуск на Linux](#9-запуск-на-linux)
10. [Запуск через Docker Compose](#10-запуск-через-docker-compose)
11. [Запуск в режиме жюри](#11-запуск-в-режиме-жюри)
12. [Использование API](#12-использование-api)
13. [Как получить OTP из outbox/sms.jsonl](#13-как-получить-otp-из-outboxsmsjsonl)
14. [Полный цикл send → outbox → verify](#14-полный-цикл-send--outbox--verify)
15. [IP 127.0.0.1 и 127.0.0.2](#15-ip-127001-и-127002)
16. [Почему X-Forwarded-For игнорируется](#16-почему-x-forwarded-for-игнорируется)
17. [Что означает `advance: 120`](#17-что-означает-advance-120)
18. [TTL и блокировки](#18-ttl-и-блокировки)
19. [Запуск тестов](#19-запуск-тестов)
20. [Запуск attack.py](#20-запуск-attackpy)
21. [Конкурентность и Redis Lua](#21-конкурентность-и-redis-lua)
22. [Ограничения безопасности тестового режима](#22-ограничения-безопасности-тестового-режима)
23. [Семь обязательных критериев](#23-семь-обязательных-критериев)
24. [Три бонуса](#24-три-бонуса)
25. [Troubleshooting](#25-troubleshooting)

---

## 1. Что такое OTP Secure

Сервис подтверждения номера телефона одноразовым 6-значным кодом. Два обязательных эндпоинта — `POST /otp/send` и `POST /otp/verify` — плюс демо-интерфейс (`/demo`), защищённая панель событий безопасности (`/admin/dashboard`), Swagger (`/docs`) и скрипт атак `attack.py`.

## 2. Основные возможности

* OTP из 6 цифр через `secrets.randbelow`, ведущие нули сохраняются, срок жизни 120 с, одноразовый.
* Новая успешная выдача аннулирует предыдущий код.
* В Redis хранится только HMAC-SHA256 (номер + challenge id + код), сравнение — `hmac.compare_digest()`.
* Прогрессивные интервалы между отправками 30 → 60 → 120 с, не более 3 отправок за 10 минут.
* 5 неверных кодов → блокировка номера на 15 минут (HTTP 423).
* Не более 20 проверок в минуту с одного IP суммарно по всем номерам (HTTP 429).
* Ровно один успех при любом числе параллельных проверок правильного кода (атомарные Lua-скрипты), в том числе между несколькими процессами API.
* Журнал событий безопасности без OTP, без номеров и без IP (только HMAC-псевдонимы).
* Демо-доставка SMS в `outbox/sms.jsonl` с блокировкой файла и `fsync` до ответа 200.

## 3. Технологии

Python 3.12, FastAPI, Uvicorn, Pydantic v2, pydantic-settings, redis-py (asyncio), Redis 7 + Lua, `secrets`/`hmac`/`hashlib`, Vanilla JS + CSS, Pytest + pytest-asyncio + HTTPX, Docker / Docker Compose.

## 4. Архитектура

```
 client ──TCP──► Uvicorn (proxy headers OFF) ──► FastAPI routers (app/api)
                                                    │
                                   OtpService (app/services/otp_service.py)
              ┌───────────────┬──────────────┼───────────────┬──────────────────┐
     SecurityContext    IpRateLimiter   Redis Lua scripts   AuditService     SmsOutboxNotifier
     HMAC, псевдонимы   rate_limit.lua  issue_otp.lua       capped list +    outbox/sms.jsonl
                                        verify_otp.lua      счётчики         (flock + fsync)
                                              │
                                            Redis  ← единый источник истины (TTL, атомарность)
```

**Ключи Redis** (в именах только псевдонимы `HMAC(pseudonym-key, номер|IP)`, никогда сам номер или IP):

| Ключ | Содержимое | TTL |
|---|---|---|
| `otp:active:{phone_id}` | hash `{cid, digest}` текущего кода | 120 с |
| `otp:spent:{phone_id}` | дайджесты заменённых/использованных кодов (чтобы ответить 410, а не 401) | 120 с |
| `otp:send_count:{phone_id}` | число успешных отправок в окне | 600 с с первой отправки |
| `otp:send_cooldown:{phone_id}` | флаг паузы | 30 / 60 / 120 с |
| `otp:failures:{phone_id}` | число неверных кодов | 900 с с первой ошибки |
| `otp:block:{phone_id}` | флаг блокировки | 900 с |
| `otp:ip_limit:{ip_id}` | счётчик проверок с IP | 60 с с первой проверки |
| `otp:security_events` | последние 1000 событий | — |
| `otp:security_stats` | счётчики событий | — |

**Ключи HMAC** выводятся из `OTP_HMAC_KEY` с разными доменными метками (`otp-digest`, `pseudonym`, `admin-session`). Сообщения кодируются с префиксом длины (length-prefixed), поэтому разделители не могут дать неоднозначность.

## 5. Структура папок

```
.
├── app/
│   ├── main.py              # фабрика FastAPI, обработчики ошибок, заголовки безопасности
│   ├── __main__.py          # python -m app  (uvicorn без proxy headers)
│   ├── config.py            # настройки, проверка production-конфигурации
│   ├── dependencies.py      # контейнер сервисов
│   ├── api/                 # otp.py, admin.py, health.py
│   ├── schemas/             # pydantic-модели запросов/ответов/ошибок
│   ├── core/                # security.py (HMAC), otp_generator.py, client_ip.py, exceptions.py
│   ├── services/            # otp_service.py, rate_limiter.py, audit_service.py, sms_outbox.py
│   ├── storage/             # redis_client.py (ключи, загрузка Lua)
│   ├── lua/                 # issue_otp.lua, verify_otp.lua, rate_limit.lua
│   ├── templates/           # demo.html, login.html, dashboard.html
│   └── static/              # css/style.css, js/app.js, js/admin.js
├── outbox/                  # sms.jsonl (создаётся при старте; в .gitignore)
├── data/                    # автосгенерированные dev-секреты (в .gitignore)
├── scripts/                 # run_jury.sh, init_env.py
├── tests/                   # 57 тестов на реальном Redis
├── attack.py
├── Dockerfile, docker-compose.yml, docker-compose.jury.yml
├── requirements.txt, requirements-dev.txt, pytest.ini
└── .env.example, .gitignore
```

## 6. Установка зависимостей

```bash
python3.12 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt  # только для работы сервиса хватит requirements.txt
```

## 7. Настройка Redis

Любой из вариантов (Redis должен слушать `127.0.0.1:6379`):

```bash
sudo apt install redis-server && sudo systemctl start redis-server
# или
docker run -d --name otp-redis -p 127.0.0.1:6379:6379 redis:7-alpine
# или только Redis из compose-файла жюри (host network)
docker compose -f docker-compose.jury.yml up -d redis
```

Проверка: `redis-cli ping` → `PONG`.

## 8. Создание .env

```bash
python scripts/init_env.py      # создаёт .env из .env.example со случайными ключами (права 600)
```

или вручную: `cp .env.example .env` и заполните `OTP_HMAC_KEY`, `ADMIN_API_KEY` значениями из
`python -c "import secrets; print(secrets.token_urlsafe(48))"`.

Если ключи не заданы, в режиме `development` сервис сам сгенерирует их один раз и сохранит в `data/secrets.env` (права 600), чтобы лимиты и блокировки не сбрасывались при перезапуске. В `APP_ENV=production` запуск со слабыми/пустыми ключами, включённым outbox, `DEMO_MODE` или `DEBUG` запрещён.

## 9. Запуск на Linux

```bash
source .venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers
# эквивалентно:
python -m app
```

* Демо: http://127.0.0.1:8000/demo
* Swagger: http://127.0.0.1:8000/docs
* Dashboard: http://127.0.0.1:8000/admin/dashboard (ключ — `ADMIN_API_KEY` из `.env` или `data/secrets.env`)
* Health: http://127.0.0.1:8000/health

## 10. Запуск через Docker Compose

```bash
docker compose up --build
```

Поднимаются `redis` (с healthcheck и AOF) и `api` (ждёт healthy Redis). Порты опубликованы только на `127.0.0.1` (переменные `API_PORT`, `REDIS_PORT`).

* **Outbox на хосте:** `./outbox:/app/outbox` → файл доступен как **`./outbox/sms.jsonl`** в корне проекта.
* Контейнер работает от UID/GID `1000:1000`, чтобы файл с правами 600 был читаем пользователем хоста. Если ваш UID другой: `OTP_UID=$(id -u) OTP_GID=$(id -g) docker compose up --build`.
* ⚠️ **Важно про IP.** В этом (bridge) режиме Docker делает NAT, и приложение видит адрес шлюза (проверено: `172.22.0.1` для запросов и с 127.0.0.1, и с 127.0.0.2). Для проверки лимитов по IP используйте раздел 11.

## 11. Запуск в режиме жюри

**Вариант A (рекомендуемый) — FastAPI напрямую на Linux:**

```bash
./scripts/run_jury.sh
```

Скрипт: запускает Redis на `127.0.0.1:6379` (локальный `redis-server` или Docker), создаёт venv, ставит зависимости, создаёт `.env` с ключами, создаёт `outbox/` (права 700) и запускает

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers
```

То же вручную: 1) запустить Redis; 2) `source .venv/bin/activate`; 3) `python scripts/init_env.py`; 4) команда выше.

Проверка:

```bash
curl -s http://127.0.0.1:8000/health
curl -s -X POST http://127.0.0.1:8000/otp/verify -H "Content-Type: application/json" \
     -d '{"msisdn":"+996700123456","code":"111111"}'
curl -s --interface 127.0.0.2 -X POST http://127.0.0.1:8000/otp/verify -H "Content-Type: application/json" \
     -d '{"msisdn":"+996700123456","code":"111111"}'
ls -l outbox/sms.jsonl
```

**Вариант B — всё в Docker с host networking (только Linux):**

```bash
docker compose -f docker-compose.jury.yml up --build
```

API слушает `127.0.0.1:8000` прямо в сетевом пространстве хоста, NAT отсутствует, поэтому видны реальные `127.0.0.1` / `127.0.0.2`. Проверено экспериментально: Linux-клиент `curl --interface 127.0.0.2` → в логе API `127.0.0.2`, лимит 127.0.0.1 на него не распространяется, `X-Forwarded-For` игнорируется. (На Docker Desktop для Windows/macOS host networking относится к внутренней VM, поэтому там используйте вариант A.)

## 12. Использование API

### `POST /otp/send`

```json
{"msisdn": "+996700123456"}
```

| Код | Когда |
|---|---|
| 200 | код выдан и записан в outbox |
| 429 | пауза 30/60/120 с ещё идёт или исчерпан лимит 3 отправки / 10 мин (`reason`: `cooldown` / `window_limit`, заголовок `Retry-After`) |
| 423 | номер заблокирован (код не выдаётся, блокировка не снимается) |
| 422 | некорректный номер |
| 503 | Redis или запись outbox недоступны (ложного успеха нет) |

```json
{"success": true, "message": "OTP issued successfully", "expires_in": 120, "retry_after": 30, "sends_remaining": 2}
```

Код в ответе **не возвращается** никогда. Номер нормализуется в E.164 (`+996700123456`, `996700123456`, `00996700123456`, `+996 700 123 456` — один и тот же номер).

### `POST /otp/verify`

```json
{"msisdn": "+996700123456", "code": "482916"}
```

Порядок проверок: **1)** IP-лимит → 429; **2)** блокировка номера → 423; **3)** код.

| Код | Когда |
|---|---|
| 200 | `{"success": true, "verified": true, "message": "Phone successfully verified"}` |
| 401 | неверный код (`attempts_left`) |
| 410 | код истёк, уже использован (`reason: used`), заменён новым (`reason: replaced`) или не выдавался |
| 423 | номер заблокирован; 5-й неверный код сам возвращает 423 |
| 429 | > 20 проверок за 60 с с этого IP |
| 422 | код не из 6 цифр / некорректный номер |
| 503 | Redis недоступен |

Код, совпавший с заменённым или уже использованным кодом, получает 410 и **не** засчитывается как неверная попытка. Проверка номера без активного кода — 410 без увеличения счётчика ошибок.

## 13. Как получить OTP из `outbox/sms.jsonl`

Путь: **`<корень проекта>/outbox/sms.jsonl`** (и при прямом запуске, и в Docker — через bind mount). Относительный `OUTBOX_PATH` всегда отсчитывается от корня проекта, а не от текущей директории.

Формат — JSON Lines, одна строка = одно SMS:

```json
{"msisdn":"+996700123456","code":"482916","timestamp":"2026-11-20T12:00:00Z"}
```

* `msisdn` — номер в том виде, в каком он пришёл в `/otp/send`;
* `code` — 6 цифр строкой (ведущие нули сохраняются);
* `timestamp` — UTC, ISO 8601.

Правила: строка дописывается только при HTTP 200; при 429/423/503 записи нет; старые записи не перезаписываются; для номера действителен только **последний** код (если он не истёк). Если организаторы опубликуют иную официальную схему полей — её нужно привести в `SmsOutboxNotifier.build_record` (`app/services/sms_outbox.py`).

```bash
tail -n 1 outbox/sms.jsonl
grep '"+996700123456"' outbox/sms.jsonl | tail -n 1 | python3 -c 'import sys,json; print(json.load(sys.stdin)["code"])'
```

## 14. Полный цикл send → outbox → verify

```bash
# 1. отправка
curl -X POST http://127.0.0.1:8000/otp/send \
  -H "Content-Type: application/json" \
  -d '{"msisdn":"+996700123456"}'

# 2. получение OTP
tail -n 1 outbox/sms.jsonl
CODE=$(grep '"+996700123456"' outbox/sms.jsonl | tail -n 1 | python3 -c 'import sys,json; print(json.load(sys.stdin)["code"])')

# 3. подтверждение
curl -X POST http://127.0.0.1:8000/otp/verify \
  -H "Content-Type: application/json" \
  -d "{\"msisdn\":\"+996700123456\",\"code\":\"$CODE\"}"
```

`482916` в примерах — просто пример; используйте код из outbox.

## 15. IP 127.0.0.1 и 127.0.0.2

* IP = `request.client.host`, то есть peer-адрес TCP-соединения от Uvicorn.
* `127.0.0.1` и `127.0.0.2` — разные клиенты с независимыми счётчиками; ни один IP не захардкожен.
* Смена номера телефона не сбрасывает лимит IP (счётчик общий для всех номеров).
* В Linux вся подсеть `127.0.0.0/8` маршрутизируется на loopback, поэтому `curl --interface 127.0.0.2 http://127.0.0.1:8000/...` работает без настройки.

## 16. Почему X-Forwarded-For игнорируется

Заголовок задаёт клиент, и подделать его можно одной строкой — атакующий получил бы новый лимит на каждый запрос. Ловушка: Uvicorn **по умолчанию** включает `ProxyHeadersMiddleware` и доверяет `X-Forwarded-For` от `127.0.0.1` — то есть ровно от адреса жюри. Поэтому:

1. Документированная команда запуска содержит `--no-proxy-headers` (так же `python -m app` и Docker).
2. Дополнительная защита: при `TRUST_PROXY_HEADERS=false` приложение при старте отключает `ProxyHeadersMiddleware` Uvicorn (`app/core/client_ip.py`). Даже простой `uvicorn app.main:app` без флага не меняет IP по заголовкам — это проверяется тестом `test_19_20_ips_independent_and_xff_ignored[plain-uvicorn]`.

`X-Real-IP`, `Forwarded` и любые другие заголовки тоже не читаются.

## 17. Что означает `advance: 120`

По уточнению организаторов `advance: 120` — это **«проверить состояние системы после того, как прошло 120 секунд»**. Это не параметр HTTP и не запрос к API.

* Сервис всегда работает в **реальном времени**. Управляемых часов и эндпоинтов вроде `/advance`, `/time/advance`, `/test/time` нет.
* Срок жизни кода — TTL ключа в Redis (`PEXPIRE 120000`), а не таймер в Python или JS.

```text
00:00 — выдача OTP
01:59 — OTP ещё действителен (200)
02:00 — ключ удалён Redis
02:01 — проверка возвращает 410
```

Тест `tests/test_expiration.py::test_real_120_seconds` выполняет реальное ожидание (`RUN_SLOW=1`). Остальные тесты времени используют изолированную конфигурацию `APP_ENV=test` с уменьшенными интервалами — они проверяют ту же логику, но не являются проверкой точных production-интервалов (точные значения проверяются по `PTTL` в Redis).

## 18. TTL и блокировки

| Параметр | Значение | Как реализовано |
|---|---|---|
| Срок жизни OTP | 120 с | TTL `otp:active` |
| Паузы между отправками | 30 / 60 / 120 с | TTL `otp:send_cooldown`, длительность зависит от номера отправки |
| Окно отправок | 600 с, максимум 3 | окно стартует с первой успешной отправки; отказы (429) окно не продлевают |
| Неверные попытки | 5 | счётчик `otp:failures` (живёт 900 с с первой ошибки) |
| Блокировка | 900 с | TTL `otp:block` |
| IP-лимит | 20 проверок / 60 с | фиксированное окно с первого запроса, `otp:ip_limit` |

* 5-й неверный код: ставится блокировка, возвращается **423**, событие `PHONE_BLOCKED`. Атакованный код уничтожается, чтобы перебор нельзя было продолжить после разблокировки.
* Во время блокировки любые проверки → 423 (если раньше не сработал IP-лимит → 429), `/otp/send` → 423 и не выдаёт код. Смена IP и перезапуск API блокировку не снимают (всё в Redis).
* При постановке блокировки счётчик ошибок сбрасывается, поэтому первая ошибка после разблокировки не приводит к мгновенной повторной блокировке.
* Новая отправка **не** сбрасывает счётчик неверных попыток.
* Redis запущен с AOF (`--appendonly yes`), так что состояние переживает и перезапуск Redis.

## 19. Запуск тестов

Нужен работающий Redis. Тесты используют БД `15` и случайный префикс ключей, а outbox — во временной папке, поэтому реальные данные и `./outbox/sms.jsonl` не затрагиваются.

```bash
pip install -r requirements-dev.txt
TEST_REDIS_URL=redis://127.0.0.1:6379/15 pytest -q
RUN_SLOW=1 TEST_REDIS_URL=redis://127.0.0.1:6379/15 pytest -q     # + реальное ожидание 120 с
```

Соответствие обязательным сценариям:

| # | Сценарий | Тест |
|---|---|---|
| 1 | 6-значный OTP | `test_send.py::test_01_*` |
| 2 | ведущие нули | `test_send.py::test_02_leading_zeros_survive_end_to_end` |
| 3–4 | запись и структура JSONL | `test_outbox.py::test_03_*`, `test_04_*` |
| 5–6 | 200 / 401 | `test_verify.py::test_05_*`, `test_06_*` |
| 7 | истёкший → 410 | `test_expiration.py::test_07_*` |
| 8 | повторное использование | `test_verify.py::test_08_*` |
| 9 | новый код аннулирует старый | `test_verify.py::test_09_*` |
| 10–13 | паузы 30/60/120, 3 за 10 мин | `test_rate_limits.py::test_10_11_12_13_*`, `test_production_send_limits_values` |
| 14–15 | блокировка и разблокировка | `test_blocking.py::test_14_*`, `test_15_*` |
| 16 | 20 проверок/мин с IP | `test_rate_limits.py::test_16_*` |
| 17 | параллельное подтверждение (2/10/100) | `test_concurrency.py::test_17_*` |
| 18 | распределённый перебор 50 номеров | `test_rate_limits.py::test_18_*` |
| 19–20 | 127.0.0.1 vs 127.0.0.2, XFF | `test_real_ip.py` (реальный uvicorn и сокеты) |
| 21–23 | outbox при 429, история, конкурентная запись | `test_outbox.py::test_21_*`, `test_22_*`, `test_23_*` |
| 24 | истечение на границе 120 с | `test_expiration.py::test_24_*`, `test_real_120_seconds` |
| 25 | лимиты переживают перезапуск API | `test_blocking.py::test_25_*` |
| 26 | Redis недоступен → 503 | `test_verify.py::test_26_*` |
| 27 | в логах нет OTP | `test_verify.py::test_27_*` |
| 28 | outbox недоступен по HTTP | `test_outbox.py::test_28_*` |
| 29 | конкурентные неверные попытки | `test_blocking.py::test_29_*` |
| 30 | одноразовость между двумя процессами API | `test_concurrency.py::test_30_*` |

Полный список закрытых 18 сценариев жюри не опубликован, поэтому мы не утверждаем, что наши тесты им идентичны: они покрывают известную спецификацию и дополнительные негативные случаи.

## 20. Запуск attack.py

```bash
python attack.py                                      # все сценарии, цель http://127.0.0.1:8000
python attack.py --mode single|distributed|replay|dualip|stress
python attack.py --target http://127.0.0.1:8000 --outbox outbox/sms.jsonl --attempts 1000
```

* Принимаются только loopback-цели (внешние адреса отклоняются). Прокси и обход защит не используются.
* Тестовые номера генерируются случайно при каждом запуске.
* Для изоляции сценариев используются разные loopback-адреса источника (`127.x.y.z`); `dualip` использует ровно `127.0.0.1` и `127.0.0.2`.
* Вердикты считаются по реальным HTTP-ответам. Успех `replay` с известным кодом из outbox считается **авторизованным** и отделён от неавторизованных успехов перебора.

Пример фактического вывода (Linux, docker-compose.jury.yml):

```text
========================================================
OTP SECURE — ATTACK TEST REPORT
========================================================
Single Number Brute Force: PASS
    blocked on wrong attempt #5, all later attempts 423
Distributed Brute Force: PASS
    only 19 of 200 guesses reached the service, rest 429
Concurrent Replay: PASS
    1 success, 99 rejected
Dual IP Isolation: PASS
    127.0.0.1 limited after 20 checks; 127.0.0.2 unaffected (410)
X-Forwarded-For Spoofing: PASS
    X-Forwarded-For had no effect on rate limiting
Jury Stress Test (1000 attempts): PASS
    no successful guess, limits and block held

Authorized verifications (known test OTP): 1
Unauthorized OTP Successes: 0

OVERALL RESULT: PASS
========================================================
```

(«19 of 200»: одна проверка из 20 была потрачена на предварительный пробный запрос с этого IP.)

## 21. Конкурентность и Redis Lua

Никаких «GET → сравнить → DEL» отдельными командами:

1. Python читает `{cid, digest}` текущего кода и делает `hmac.compare_digest()` (constant-time сравнение в Python, а не в Lua).
2. Результат (`match` / `nomatch` / `spent` / `none`) и `cid` передаются в `verify_otp.lua`, который **атомарно**: проверяет блокировку → проверяет, что `cid` всё ещё текущий → при успехе удаляет код (одноразовость) → при ошибке увеличивает счётчик и при 5-й ошибке ставит блокировку.
3. Если код уже погашен параллельным запросом или заменён новым `/otp/send` между чтением и скриптом — ответ 410.

Redis выполняет Lua-скрипты последовательно, поэтому из 100 параллельных запросов с правильным кодом ровно один получает 200 — и в одном процессе, и между несколькими процессами API (`test_30_*`). Выдача кода (`issue_otp.lua`) атомарно проверяет блокировку, лимиты и паузу и заменяет код. IP-лимит — атомарный `INCR` + `PEXPIRE` в `rate_limit.lua`.

**Outbox и Redis не образуют одну транзакцию.** Порядок: код атомарно сохраняется в Redis → строка пишется в outbox (`flock` + один `write` + `fsync`) → HTTP 200. Если запись в файл не удалась: код отзывается скриптом, который удаляет его **только если он всё ещё тот же** (`cid` совпадает — более новый код не трогается), возвращается 503, пишется событие `OUTBOX_FAILURE`. Счётчик отправок и пауза при этом не откатываются (консервативно: сбой не даёт обойти лимиты).

## 22. Ограничения безопасности тестового режима

* `outbox/sms.jsonl` содержит **настоящие** коды — только для тестирования. Каталог 0700, файл 0600, файл в `.gitignore`, вне `/static`, HTTP-маршрута для него нет (`test_28_*`).
* В production: `APP_ENV=production`, `OUTBOX_ENABLED=false`, `DEMO_MODE=false` и реальный SMS-провайдер вместо `SmsOutboxNotifier`. Сервис откажется стартовать с небезопасной конфигурацией.
* Журнал безопасности хранит только псевдонимы (первые 12 hex-символов HMAC) и безопасные детали; OTP, дайджест, секрет, номер и IP туда не попадают (`test_27_*`). Отдельные повторяющиеся события (каждый следующий 429 по IP, попытки во время блокировки) только увеличивают счётчики, чтобы флуд не вытеснял важные события из списка из 1000 записей.
* Dashboard: ключ вводится один раз и обменивается на подписанную HMAC cookie (HttpOnly, SameSite=Strict, 1 час); вход ограничен 10 попытками/мин с IP; ключа нет в JS. На страницах действует строгий CSP.
* HMAC не заменяет rate limiting: шестизначных кодов всего 10⁶, поэтому защиту обеспечивают 5 попыток на номер и 20 проверок/мин на IP.

## 23. Семь обязательных критериев

| # | Требование | Реализация |
|---|---|---|
| 1 | 6 цифр, `secrets`, 120 с, одноразовый, новый send аннулирует старый | `core/otp_generator.py`, `lua/issue_otp.lua`, `lua/verify_otp.lua` |
| 2 | только HMAC-хеш, `hmac.compare_digest()` | `core/security.py` |
| 3 | паузы 30/60/120, максимум 3 за 10 мин | `lua/issue_otp.lua` |
| 4 | 5 ошибок → 15 мин блок; 20 проверок/мин с IP | `lua/verify_otp.lua`, `lua/rate_limit.lua` |
| 5 | ровно один успех при параллельных проверках | атомарный `verify_otp.lua`, тесты 2/10/100 + 2 процесса |
| 6 | журнал безопасности без OTP | `services/audit_service.py`, `/admin/dashboard` |
| 7 | `attack.py`: перебор одного номера и 50 номеров с одного IP | `attack.py` — обе атаки остановлены |

## 24. Три бонуса

* **Redis с TTL** — всё состояние в Redis с TTL, атомарные Lua-скрипты, AOF.
* **Dashboard событий** — `/admin/dashboard`: счётчики, таблица событий, фильтр, автообновление.
* **Docker Compose** — `docker compose up --build`; для проверки IP на Linux — `docker-compose.jury.yml`.

## 25. Troubleshooting

| Симптом | Решение |
|---|---|
| `503` на все запросы | Redis недоступен: `redis-cli ping`, проверьте `REDIS_URL` (на хосте `redis://127.0.0.1:6379/0`, в compose — `redis://redis:6379/0`) |
| Лимит IP общий для 127.0.0.1 и 127.0.0.2 | API запущен через Docker bridge (видит шлюз 172.x). Используйте `scripts/run_jury.sh` или `docker-compose.jury.yml` |
| `outbox/sms.jsonl` не читается на хосте | файл создан от другого UID: `OTP_UID=$(id -u) OTP_GID=$(id -g) docker compose up --build` |
| `Permission denied` при старте в Docker | папки `outbox/`, `data/` принадлежат root: `sudo chown -R $(id -u):$(id -g) outbox data` |
| порт 8000 занят | `PORT=8010 ./scripts/run_jury.sh`, `python -m app --port 8010`, `API_PORT=8010 docker compose up` |
| `curl --interface 127.0.0.2` не работает | на macOS нужен алиас: `sudo ifconfig lo0 alias 127.0.0.2`; в Linux работает сразу |
| забыли ключ администратора | `grep ADMIN_API_KEY .env data/secrets.env` |
| лимиты «сбросились» после смены `OTP_HMAC_KEY` | псевдонимы выводятся из ключа — не меняйте его между запусками |
