# OTP Secure — сервис одноразовых кодов (ТЗ № 6)

REST API выдаёт и проверяет 6-значные OTP. Сервис защищён:
* от перебора кода;
* от SMS-спама;
* от гонок при параллельных запросах.

Два обязательных эндпоинта: `POST /otp/send` и `POST /otp/verify`. Всё состояние хранится в Redis.

---

## 1. Запуск для жюри — только Docker

Нужны **Docker** и **Docker Compose v2** на Linux. Python, Redis и файл `.env` ставить и создавать **не нужно**: все настройки, включая демо-ключи, уже прописаны в `docker-compose.yml`.

```bash
git clone https://github.com/KadyrovErjan/inai-OTP-claude.git
cd inai-OTP-claude
docker compose up -d --build
```

Проверка, что всё поднялось (через 5–10 секунд после старта):

```bash
docker compose ps                    # api и redis в статусе (healthy)
curl -s http://127.0.0.1:8000/health
# {"status":"ok","redis":"up","env":"development","outbox_enabled":true}
```

Что запускается:

| Сервис | Адрес | Назначение |
|---|---|---|
| `api` | `http://127.0.0.1:8000` | FastAPI: `/otp/send`, `/otp/verify`, `/demo`, `/docs`, `/admin/dashboard` |
| `redis` | `127.0.0.1:6390` | хранилище состояния (порт 6390, чтобы не мешать вашему Redis на 6379) |

Оба контейнера работают в **host-сети** (`network_mode: host`). Поэтому API видит **настоящий адрес TCP-соединения**: `127.0.0.1` и `127.0.0.2` — разные клиенты, NAT нет.

Коды («SMS») пишутся в **`./outbox/sms.jsonl` в корне клонированного проекта**. Контейнер пишет файл от имени владельца папки `outbox/` (того, кто клонировал репозиторий), поэтому файл читается без `sudo`.

**Демо-ключи** (заданы в `docker-compose.yml`, `.env` не нужен):

| Переменная | Значение | Для чего |
|---|---|---|
| `ADMIN_API_KEY` | `inai2026-demo-admin-key-3e8b5d1f7a2c9064` | вход в панель http://127.0.0.1:8000/admin/dashboard и заголовок `X-Admin-Key` |
| `OTP_HMAC_KEY` | `inai2026-demo-hmac-key-9f4c2a7e1b8d6053c4a1e7f2b9d8c6a5` | HMAC кодов и псевдонимов в Redis |

> Это демо-значения только для стенда хакатона. Для реального развёртывания их нужно заменить своими.

Управление:

```bash
docker compose logs -f api           # логи API (IP клиентов и коды в лог не пишутся)
docker compose restart api           # перезапуск API — лимиты и блокировки сохраняются в Redis
docker compose down                  # остановить
docker compose down -v               # остановить и стереть состояние Redis (чистый старт для нового прогона)
```

Порты можно сменить без правки файлов: `API_PORT=8010 REDIS_PORT=6391 docker compose up -d --build`. Тогда во всех примерах ниже замените `8000` на `8010`.

---

## Ответы на три пункта уточнения жюри

| Пункт уточнения | Как сделано в сервисе |
|---|---|
| **1. IP берётся из подключения** | IP клиента — это адрес TCP-соединения (`request.client.host`). Заголовки `X-Forwarded-For`, `X-Real-IP` и `Forwarded` **не читаются**, даже если их прислать. IP-адреса и номера телефонов в коде не прописаны: у `127.0.0.1` и `127.0.0.2` просто разные счётчики. |
| **2. `advance: 120`** | Время **реальное**, нужно просто подождать. Срок жизни кода — TTL ключа в Redis. **Режима с подменой часов нет**, эндпоинтов вроде `/advance` тоже нет. |
| **3. Где взять OTP** | Файл **`outbox/sms.jsonl` в корне проекта** (JSON Lines, одна строка — одно SMS). Строка записывается на диск **до** ответа HTTP 200. Путь менять не нужно. |

---

## 2. Как получить OTP из `outbox/sms.jsonl`

Файл: **`<корень проекта>/outbox/sms.jsonl`**. Каждая строка — отдельный JSON:

```json
{"msisdn":"+996700123456","code":"048291","timestamp":"2026-11-20T12:00:00Z"}
```

| Поле | Тип | Значение |
|---|---|---|
| `msisdn` | строка | номер **в том виде, в каком он был передан** в `/otp/send` |
| `code` | строка | ровно 6 цифр, ведущие нули сохраняются (`"048291"`) |
| `timestamp` | строка | время выдачи, UTC, ISO 8601 с `Z` |

Строка появляется **только при HTTP 200** от `/otp/send`. При 429, 423, 422 и 503 новых строк нет. Старые строки не перезаписываются. Для номера действителен **только последний** выданный код, пока не прошло 120 секунд.

**Код для конкретного номера.** В файле записи разных номеров идут вперемешку, поэтому `tail -n 1` может показать чужой код. Берите последнюю запись нужного номера:

```bash
N="+996700123456"
CODE=$(python3 -c 'import json,sys; print([json.loads(l)["code"] for l in open("outbox/sms.jsonl") if json.loads(l)["msisdn"]==sys.argv[1]][-1])' "$N")
echo "$CODE"
```

Аналог через `grep`: `grep "\"$N\"" outbox/sms.jsonl | tail -n 1`.

Номер нужно указывать в той же записи, что и в запросе: `+996700123456` и `+996 700 123 456` для сервиса один номер, но в файле записан именно тот вариант, который вы отправили.

---

## 3. Полный цикл: send → outbox → verify

```bash
N="+996700123456"

# 1. выдать код → 200
curl -s -X POST http://127.0.0.1:8000/otp/send \
  -H "Content-Type: application/json" -d "{\"msisdn\":\"$N\"}"
# {"success":true,"message":"OTP issued successfully","expires_in":120,"retry_after":30,"sends_remaining":2}

# 2. взять код этого номера из файла
CODE=$(python3 -c 'import json,sys; print([json.loads(l)["code"] for l in open("outbox/sms.jsonl") if json.loads(l)["msisdn"]==sys.argv[1]][-1])' "$N")

# 3. подтвердить → 200
curl -s -X POST http://127.0.0.1:8000/otp/verify \
  -H "Content-Type: application/json" -d "{\"msisdn\":\"$N\",\"code\":\"$CODE\"}"
# {"success":true,"verified":true,"message":"Phone successfully verified"}

# 4. тот же код повторно → 410 (одноразовый)
curl -s -X POST http://127.0.0.1:8000/otp/verify \
  -H "Content-Type: application/json" -d "{\"msisdn\":\"$N\",\"code\":\"$CODE\"}"
# {"success":false,"error":"otp_used","message":"OTP has already been used","reason":"used"}
```

Сам код **никогда** не возвращается в HTTP-ответе.

---

## 4. Два IP: 127.0.0.1 и 127.0.0.2

В Linux вся сеть `127.0.0.0/8` относится к loopback, поэтому `127.0.0.2` работает без настройки. Лимит — 20 проверок за 60 секунд **на один IP**, суммарно по всем номерам.

```bash
# 21 проверка с 127.0.0.1 → первые 20 проходят лимит (410: кода нет), 21-я → 429
for i in $(seq 1 21); do
  curl -s -o /dev/null -w "%{http_code} " --interface 127.0.0.1 -X POST http://127.0.0.1:8000/otp/verify \
    -H "Content-Type: application/json" -d '{"msisdn":"+996555000111","code":"123456"}'
done; echo

# у 127.0.0.2 свой счётчик → 410, а не 429
curl -s -o /dev/null -w "%{http_code}\n" --interface 127.0.0.2 -X POST http://127.0.0.1:8000/otp/verify \
  -H "Content-Type: application/json" -d '{"msisdn":"+996555000111","code":"123456"}'

# подделка заголовка с ограниченного 127.0.0.1 не помогает → 429
curl -s -o /dev/null -w "%{http_code}\n" --interface 127.0.0.1 -H "X-Forwarded-For: 127.0.0.2" -X POST http://127.0.0.1:8000/otp/verify \
  -H "Content-Type: application/json" -d '{"msisdn":"+996555000111","code":"123456"}'
```

Ожидаемый вывод: `410 ×20, затем 429`, потом `410`, потом `429`. Через 60 секунд после первого запроса окно 127.0.0.1 сбрасывается.

Если за последнюю минуту с 127.0.0.1 уже были проверки, `429` наступит раньше. Например, сразу после раздела 3 вы увидите `410 ×18, затем 429`: два `verify` из раздела 3 уже учтены, потому что счётчик IP общий для всех номеров. Для «чистых» 20 подождите 60 секунд.

---

## 5. `advance: 120` и все интервалы

Сервис работает **только в реальном времени**. Все сроки — это TTL ключей Redis. Python- и JS-таймеры на решения не влияют. Чтобы проверить состояние «после 120 секунд», нужно подождать 120 секунд.

| Параметр | Значение | Отсчёт |
|---|---|---|
| Срок жизни OTP | **120 с** | с момента выдачи |
| Паузы между отправками на номер | **30 → 60 → 120 с** | после 1-й, 2-й и 3-й успешной отправки |
| Окно отправок | **не более 3 за 600 с** | с первой успешной отправки; отказы (429) окно **не продлевают** |
| Неверные коды | **5** → блокировка номера | 5-й неверный код сразу даёт 423 |
| Блокировка номера | **900 с** | смена IP, новый код и перезапуск API её не снимают |
| Проверки с одного IP | **20 за 60 с** | фиксированное окно с первого запроса, общее для всех номеров |

```text
00:00   POST /otp/send                → 200, код в outbox
01:59   POST /otp/verify (верный код) → 200
02:00   ключ удалён Redis
02:01   POST /otp/verify (тот же код) → 410
```

Режима с подменой часов **нет**, и эндпоинта для этого тоже нет. Для официальной проверки ничего настраивать не нужно.

Если для отладки нужно сократить ожидания, интервалы можно уменьшить переменными окружения в `docker-compose.yml` (`OTP_TTL`, `SEND_COOLDOWN_1…3`, `PHONE_BLOCK_SECONDS` и т. д.). Это меняет сами значения, а не часы, и **для проверки жюри не используется**.

---

## 6. API

### `POST /otp/send`

Запрос: `{"msisdn": "+996700123456"}`. Номер нормализуется в E.164: варианты `+996700123456`, `996700123456`, `00996700123456` и `+996 700 123 456` — это один номер.

| Код | Когда | Тело (пример) |
|---|---|---|
| 200 | код выдан и записан в outbox | `{"success":true,"expires_in":120,"retry_after":30,"sends_remaining":2}` |
| 429 | идёт пауза или исчерпан лимит 3 / 10 мин | `{"error":"send_rate_limited","reason":"cooldown"\|"window_limit","retry_after":28}` + заголовок `Retry-After` |
| 423 | номер заблокирован после 5 неверных кодов (код не выдаётся) | `{"error":"phone_blocked","retry_after":812}` |
| 422 | некорректный номер или тело | `{"error":"validation_error",…}` |
| 503 | Redis или запись outbox недоступны (ложного 200 не бывает) | `{"error":"service_unavailable",…}` |

Новая успешная выдача аннулирует предыдущий код номера: старый код после этого даёт 410 с `reason: replaced`.

### `POST /otp/verify`

Запрос: `{"msisdn": "+996700123456", "code": "048291"}`.

Порядок проверок: **1)** лимит IP → 429; **2)** блокировка номера → 423; **3)** код.

| Код | Когда | Тело (пример) |
|---|---|---|
| 200 | код верный (ровно один раз) | `{"success":true,"verified":true,"message":"Phone successfully verified"}` |
| 401 | неверный код | `{"error":"invalid_otp","attempts_left":3}` |
| 410 | код истёк, уже использован или заменён новым; либо кода для номера нет | `{"error":"otp_expired"\|"otp_used"\|"otp_replaced","reason":"expired"\|"used"\|"replaced"}` |
| 423 | номер заблокирован; 5-й неверный код сам возвращает 423 | `{"error":"phone_blocked","retry_after":900}` + `Retry-After` |
| 429 | больше 20 проверок за 60 с с этого IP | `{"error":"ip_rate_limited","retry_after":42}` + `Retry-After` |
| 422 | `code` не из 6 цифр, некорректный номер или тело | `{"error":"validation_error",…}` |
| 503 | Redis недоступен | `{"error":"service_unavailable",…}` |

Повтор уже использованного или заменённого кода даёт 410 и **не** считается неверной попыткой.

Swagger: http://127.0.0.1:8000/docs. Демо-страница: http://127.0.0.1:8000/demo.

---

## 7. Как устроена защита

* **Генерация:** `secrets.randbelow(10**6)` с форматом `06d`, поэтому ведущие нули сохраняются.
* **Хранение:** в Redis лежит только **HMAC-SHA256** от номера, уникального id запроса и кода; сравнение через `hmac.compare_digest()`. В Redis нет ни самого кода, ни номера, ни IP: в именах ключей только HMAC-псевдонимы.
* **Атомарность:** выдача, проверка, погашение и счётчики выполняются Lua-скриптами Redis. Из 100 параллельных проверок верного кода успешна ровно одна, в том числе если API запущен в нескольких процессах.
* **Устойчивость:** лимиты, паузы и блокировки переживают перезапуск API, потому что хранятся в Redis.
* **Журнал безопасности:** события выдачи, проверки, ошибок, блокировок и лимитов без OTP, номеров и IP (только псевдонимы). Панель: http://127.0.0.1:8000/admin/dashboard, ключ — `ADMIN_API_KEY` из таблицы выше. Для API можно передать заголовок `X-Admin-Key`.
* **Outbox:** файл не отдаётся по HTTP, исключён из Git и из Docker-образа.

---

## 8. Тесты и `attack.py`

`attack.py` уже лежит в образе и запускается внутри работающего контейнера API (он в той же host-сети, поэтому ходит с `127.0.0.1`, `127.0.0.2` и т. д.):

```bash
docker compose exec api python attack.py              # все атаки, итог PASS/FAIL и код выхода
docker compose exec api python attack.py --mode single|distributed|replay|dualip|stress
# при другом API_PORT добавьте: --target http://127.0.0.1:8010
```

Сценарии:
* перебор одного номера;
* 50 номеров с одного IP;
* 100 параллельных проверок одного кода;
* два IP и подделка `X-Forwarded-For`;
* 1000 попыток.

`attack.py` расходует лимиты, поэтому перед ручными проверками удобнее начать с чистого состояния: `docker compose down -v && docker compose up -d`.

Unit-тесты (pytest, 57 тестов на реальном Redis) запускаются без Docker и для проверки жюри не нужны:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
TEST_REDIS_URL=redis://127.0.0.1:6390/15 pytest -q   # Redis из docker compose, отдельная БД 15
```

---

## 9. Docker Desktop (Windows / macOS)

На Docker Desktop host-сеть относится к внутренней виртуальной машине, поэтому для Windows/macOS есть отдельный файл с обычной публикацией порта:

```bash
docker compose -f docker-compose.desktop.yml up -d --build
```

⚠️ В этом режиме Docker делает NAT, и API видит адрес шлюза (`172.x.x.x`) для всех клиентов. Отправка, проверка, outbox и панель работают, но **лимиты по IP (127.0.0.1 / 127.0.0.2) проверяйте на Linux** с основным `docker-compose.yml`.

---

## 10. Если что-то не работает

| Симптом | Решение |
|---|---|
| `docker compose ps` показывает `starting` | подождите 5–10 секунд: API ждёт, пока Redis станет `healthy` |
| `address already in use` | порт 8000 или 6390 занят: `API_PORT=8010 REDIS_PORT=6391 docker compose up -d --build` |
| `503` на все запросы, `/health` → `"redis":"down"` | `docker compose ps` и `docker compose logs redis` |
| `curl: (7) Failed to connect` к 127.0.0.1:8000 | запущен `docker-compose.desktop.yml` на Linux или контейнер ещё стартует: `docker compose logs api` |
| `Permission denied` при чтении `outbox/sms.jsonl` | репозиторий клонирован от `root`: читайте через `sudo` или клонируйте от своего пользователя |
| у 127.0.0.1 и 127.0.0.2 общий лимит | запущен вариант для Docker Desktop (NAT); используйте основной `docker-compose.yml` на Linux |
| в outbox «чужой» код | берите последнюю запись **своего** номера (раздел 2), а не `tail -n 1` |
| лимиты остались после прошлых прогонов | `docker compose down -v && docker compose up -d` |

<details>
<summary>Запуск без Docker (для разработки)</summary>

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
redis-cli ping || redis-server --bind 127.0.0.1 --port 6379 --daemonize yes
python scripts/init_env.py          # создаёт .env со случайными ключами
uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers --no-access-log
```

</details>

---

## Структура проекта

```
app/
  main.py            приложение FastAPI, обработчики ошибок, заголовки безопасности
  api/               otp.py (send/verify), admin.py (панель), health.py
  core/              security.py (HMAC), otp_generator.py (secrets), client_ip.py (IP из TCP)
  services/          otp_service.py, rate_limiter.py, audit_service.py, sms_outbox.py
  lua/               issue_otp.lua, verify_otp.lua, rate_limit.lua — атомарные операции Redis
  templates/, static/  демо-страница и панель
outbox/sms.jsonl     коды для жюри (создаётся при старте, в .gitignore)
scripts/             docker-entrypoint.sh, init_env.py, run_jury.sh
docker-compose.yml   запуск для жюри (Linux, host-сеть, все настройки внутри)
docker-compose.desktop.yml  вариант для Docker Desktop
tests/               pytest
attack.py            сценарии атак
```

Технологии: Python 3.12, FastAPI, Uvicorn, Redis 7 + Lua, Pydantic v2, pytest, Docker Compose.
