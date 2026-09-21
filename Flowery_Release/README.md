# 🌸 Flowery (Glue) — DPI Bypass & Tethering Mask для Windows

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078d7.svg)](https://microsoft.com)
[![Dependencies: None](https://img.shields.io/badge/dependencies-zero%20(stdlib)-brightgreen.svg)](https://docs.python.org/3/library/)

**Flowery (Glue)** — лёгкий автономный инструмент для обхода DPI-блокировок (ТСПУ / РКН) и операторских ограничений при раздаче интернета со смартфона на ПК (тетеринг).

Инструмент работает **полностью автономно**:
- 🚫 Не требует внешних VPS или платных серверов.
- 🚫 Не требует регистраций, ключей и создания аккаунтов.
- 🚫 **Ноль сторонних библиотек**: написан строго на стандартной библиотеке Python (`socket`, `select`, `threading`, `struct`, `ctypes`, `winreg`). Никаких `pip install`!

---

## ⚡ Ключевые возможности

### 1. Независимый обход Discord (даже без zapret)
- **TLS Record Fragmentation**: разделяет рукопожатие ClientHello на две валидные TLS-записи прямо посередине имени домена (SNI). DPI не видит заблокированный хост и пропускает трафик.
- **RFC 8305 (Happy Eyeballs)**: каскадно опрашивает все IP-адреса целевых серверов параллельно за 250 мс, мгновенно подключаясь к живому IP в обход заблокированных подсетей Cloudflare.
- **Голосовые каналы (Voice & WebRTC)**: поддерживает голосовые шлюзы `*.discord.media` и автоматический fallback на TCP/443 при блокировке UDP.

### 2. Скрытие раздачи интернета (Tethering Mask)
- **Фиксация TTL = 65**: автоматически прописывает `DefaultTTL = 65` в реестре Windows (`Tcpip\Parameters`). При прохождении смартфона значение уменьшается на 1, и оператор видит стандартный смартфонный TTL=64. Платная раздача не списывается.
- **RFC 1323 TCP Timestamps**: активирует временные метки TCP для предотвращения анализа пакетов оператором.

### 3. Автоматическая интеграция в систему (Zero Config)
- Автоматически настраивает системный прокси Windows через реестр и WinINet API. Браузеры (Chrome, Edge, Яндекс), Discord и другие приложения начинают работать через обход без ручной настройки сетевых параметров.
- При выходе (`Ctrl+C` или закрытие) **гарантированно возвращает все настройки системы в исходное состояние**.

### 4. Совместимость с Flowseal zapret
- Flowery работает на уровне локального HTTP/HTTPS прокси (`127.0.0.1:8118`) и **не использует WinDivert**.
- Полностью исключены конфликты драйверов — может работать как на 100% самостоятельно, так и в тандеме с Flowseal zapret (`winws.exe`).

---

## 🚀 Быстрый старт

1. Скачайте проект или клонируйте репозиторий:
   ```bash
   git clone https://github.com/KarlMerkel/Floweryguard.git
   cd Floweryguard
   ```
2. Запустите **`start.bat`** (правой кнопкой мыши -> *Запуск от имени администратора*).
3. Готово! В консоли появится цветной логотип цветка, активируется локальный прокси и применится профиль обхода.
4. Для проверки работы запустите **`test.bat`** — скрипт протестирует доступность всех 10 ключевых ресурсов (Discord Web, Gateway, CDN, Voice, YouTube, Rutracker, Twitter).

---

## 📂 Структура проекта

```text
Flowery/
├── Floweryguard/               # Ядро приложения
│   ├── __init__.py
│   ├── main.py                 # Главная точка входа и оркестратор
│   ├── proxy.py                # HTTP CONNECT прокси, TCP Split, TLS Record Frag, Happy Eyeballs
│   ├── detector.py             # Авто-детектор ограничений сети (тетеринг vs DPI)
│   ├── tls_parser.py           # Парсер TLS ClientHello и генератор сплита
│   ├── system_proxy.py         # Менеджер системного прокси Windows (WinINet)
│   ├── ttl_fix.py              # Управление DefaultTTL и RFC 1323 Timestamps в реестре
│   ├── quic_block.py           # Управление правилом UDP/443 в Windows Firewall
│   ├── dns_config.py           # Резервные защищённые DNS
│   ├── sni_spoofer.py          # Модуль десинхронизации SNI под белые списки
│   ├── tester.py               # Встроенный модуль экспресс-тестирования узлов
│   └── config.py               # Менеджер настроек (config.ini)
├── config.ini                  # Файл конфигурации
├── whitelist.txt               # Список целевых доменов
├── start.bat                   # Лаунчер полного комплекса с авто-повышением прав
├── test.bat                    # Экспресс-тест всех ресурсов в 1 клик
├── stop.bat                    # Экстренный сброс настроек сети и прокси
├── LICENSE                     # Лицензия MIT
└── README.md                   # Документация
```

---

## ⚙️ Тонкая настройка (`config.ini`)

Файл `config.ini` содержит подробные комментарии к каждой опции:

```ini
[proxy]
host = 127.0.0.1
port = 8118
auto_system_proxy = true

# true — Flowery сам полностью обходит блокировку Discord (TLS Record Frag + Happy Eyeballs)
# false — исключить Discord из прокси и передать его в zapret (WinDivert)
proxy_discord = true

# true — проксировать YouTube через Flowery; false — передать zapret
proxy_youtube = false

[bypass]
tcp_split = true
tls_record_frag = true
oob_data = true
http_host_obfuscation = true

[tethering]
fix_ttl = true
default_ttl = 65
enable_timestamps = true

[quic]
# Для Discord Voice рекомендуется false, чтобы не блокировать UDP-порты
block_quic = false
```

---

## 🛠 Управление через командную строку

```bash
# Запуск полного комплекса
python Floweryguard/main.py --all

# Только комплексная диагностика сети (тетеринг vs белый список)
python Floweryguard/main.py --detect

# Проверка текущего статуса параметров системы (TTL, прокси, фаервол)
python Floweryguard/main.py --status

# Проверка доступности заблокированных сайтов через прокси
python Floweryguard/main.py --test

# Только фиксация TTL=65
python Floweryguard/main.py --fix-ttl
```

---

## ❓ Часто задаваемые вопросы (FAQ)

<details>
<summary><b>Что делать, если Discord всё равно не подключается к войсу?</b></summary>
Убедитесь, что в <code>config.ini</code> параметр <code>block_quic = false</code> (чтобы не блокировались UDP пакеты WebRTC). Если ваш мобильный оператор полностью блокирует UDP, Discord автоматически переключится на WebRTC over TCP (порт 443), который фрагментируется Flowery.
</details>

<details>
<summary><b>Окно консоли случайно закрыли крестиком, прокси остался включён?</b></summary>
Просто запустите <b><code>stop.bat</code></b> — он мгновенно сбросит значение системного прокси в реестре Windows на 0 и восстановит прямое подключение.
</details>

<details>
<summary><b>Нужно ли держать zapret включённым?</b></summary>
Flowery может работать как полностью автономно, так и совместно с zapret. Если у вас zapret отлично работает на YouTube, но ломается на Discord — оставьте <code>proxy_discord = true</code> и <code>proxy_youtube = false</code> в <code>config.ini</code>, и они будут идеально дополнять друг друга.
</details>

---

## 📄 Лицензия

Проект распространяется под открытой лицензией [MIT](LICENSE).
