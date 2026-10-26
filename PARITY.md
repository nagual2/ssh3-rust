# PARITY — Go (`nagual2/ssh3-go`) vs Rust (`ssh3-rust`)

Сравнение функциональности двух реализаций протокола SSH3.

- **Эталон (Go):** `C:\Git\project\ssh3` — единственный поставляемый продукт (`ssh3`, `ssh3-server`), состояние — коммит `ce072f4` (`docs(compress): the cutoff of the frame layer`).
- **Догоняющая (Rust):** `C:\Git\project\ssh3-rust` — крейты `ssh3-client`, `ssh3-server`, `ssh3-core`, `ssh3-proto`, `ssh3-quinn`, `ssh3-auth`, `ssh3-h3`.

Метод: сплошной статический разбор обеих кодовых баз (Go: `cmd/`, `client/`, `server_auth/`, `message/`, `compress/`, `util/`, `auth/`, `packaging/`, `version.go`; Rust: все 7 крейтов). Каждое утверждение сопровождается ссылкой `путь:строка`. Если возможность не найдена — указано «не найдено». Wire-уровень (message types, framing) обеих реализаций совпадает — это подтверждено interop-матрицей из 22 сценариев (`ssh3-rust/README.md:152-183`); расхождения ниже относятся к **продуктовой поверхности** (CLI, политики, эксплуатация), а не к wire-формату.

Обновление 2026-10-22 (вторая волна): в Go после волны CLI-паритета (`a5bea1c`) пришли **сжатие тела канала** (`f1d0415`, `93594d3`, `e6994e3`, `ce072f4`), **начальный размер QUIC-пакета 1200** (`d12b25e`, `30ccdfe`, `1a4ee04`) и **бюджет датаграмм цепочки proxy-jump** (`897161f`). Все ссылки на Go пересчитаны по текущему `ce072f4` (ранее таблица опиралась на `a5bea1c` — строки `cmd/ssh3.go` сдвинулись на +12, `cmd/ssh3-server.go` на +1, `channel.go` на +6). Одновременно пересмотрены утверждения о Rust: крейты ушли вперёд (PTY-политика, escape-последовательности, `-L`/`-R`/`-D` в CLI, политики форвардинга, DoS-guard, lockout, секретный URL-путь, клампы размера кадра, `128+signum`, упаковка, SFTP-сервер) — соответствующие строки переведены из «пробел» в «да».

**Сноска †** — утверждение о Rust верно только для **незакоммиченного рабочего дерева** репозитория (`ssh3-server/src/sftp.rs`, `ssh3-server/src/sftp_child.rs`, `ssh3-server/src/sftp_stream.rs`, `packaging/build-deb.sh`, `packaging/ssh3-rust-server.control.in`, `packaging/ssh3-rust-server.postinst`, `packaging/ssh3-rust-server.prerm`, `ssh3-client/src/console.rs`, `ssh3-client/src/console/`); последний коммит — `108409b`.

Обозначения: **Сложность** — S (≤1 чел.-день), M (2-5), L (>5). **Go**/**Rust** — `да` / `нет` / `частично`.

---

## 1. Сводка

| № | Метрика | Значение |
|---|---------|----------|
| 1 | Всего строк возможностей в таблице паритета | **110** |
| 2 | Реализовано в Go | **109** |
| 3 | Реализовано в Rust | **65** (61 полностью + 1 с расхождением + 3 частично) |
| 4 | Полное совпадение (обе стороны, поведение эквивалентно) | **61** |
| 5 | Расхождение по семантике при наличии в обеих | **1** полное (I4) + **3** частичных (E3, G10, H8) |
| 6 | **Пробелов** (в Go есть, в Rust нет) | **44** |
| 7 | Пробелов по безопасности (High/Critical) | **4** (A10, I5, I8, I9) |
| 8 | Клиентских пробелов | **27** (+2 частичных: E3, H8) |
| 9 | Серверных пробелов | **11** (+1 частичный: M6) |
| 10 | Только в Rust (нет аналога в Go) | **1** (A7) |
| 11 | Протокольных пробелов (сжатие тела канала) | **0** (N1–N6 закрыты, `wave/t9-compression`) |
| 12 | Оценка закрытия разрыва | **≈ 25 человеко-дней** (эшелоны 0–2) или **≈ 80** (полный паритет, включая сжатие) |

Контроль суммы: 61 (совпадение) + 1 (расхождение) + 3 (частично) + 44 (пробел) + 1 (только Rust) = **110**.

Разбивка по подсистемам:

| № | Подсистема | Строк | Совпадает | Расхождение | Частично | Пробел | Только Rust |
|---|-----------|-------|-----------|-------------|----------|--------|-------------|
| 1 | Клиент: аутентификация | 11 | 8 | 0 | 0 | 2 | 1 |
| 2 | Клиент: сессия / PTY / сигналы | 15 | 13 | 0 | 0 | 2 | 0 |
| 3 | Клиент: форвардинг | 8 | 7 | 0 | 0 | 1 | 0 |
| 4 | Клиент: control master | 5 | 0 | 0 | 0 | 5 | 0 |
| 5 | Клиент: proxy jump | 4 | 0 | 0 | 1 | 3 | 0 |
| 6 | Клиент: передача файлов | 6 | 0 | 0 | 0 | 6 | 0 |
| 7 | Клиент: конфигурация / `-o` / ssh_config | 12 | 9 | 0 | 1 | 2 | 0 |
| 8 | Клиент: прочие флаги и сервисы | 9 | 2 | 0 | 1 | 6 | 0 |
| 9 | Сервер: аутентификация и политики | 9 | 5 | 1 | 0 | 3 | 0 |
| 10 | Сервер: политики форвардинга | 4 | 4 | 0 | 0 | 0 | 0 |
| 11 | Сервер: лимиты и таймауты | 6 | 3 | 0 | 0 | 3 | 0 |
| 12 | Сервер: функциональность | 9 | 6 | 0 | 0 | 3 | 0 |
| 13 | Эксплуатация: упаковка, логи, exit-коды | 6 | 4 | 0 | 0 | 2 | 0 |
| 14 | Протокол: сжатие тела канала (B8) | 0 | 6 | 0 | 0 | 0 | 0 |
| | **Итого** | **110** | **61** | **1** | **3** | **44** | **1** |

---

## 2. Таблица паритета

### 2.1. Клиент — аутентификация

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| A1 | Аутентификация | Pubkey по приватному ключу (ed25519 / P-256 / RSA) | да | да | Go `cmd/ssh3.go:701` (`-i`), `auth/plugins/pubkey_authentication/client/privkey_auth.go:47` (`-privkey`); Rust `ssh3-client/src/main.rs:47` (`--identity`) | — | — |
| A2 | Аутентификация | Pubkey через SSH-agent (выбор ключа агента) | да | да | Go `auth/plugins/pubkey_authentication/client/pubkey_auth.go:41` (`-pubkey-for-agent`); Rust `ssh3-client/src/main.rs:49-59` (`--agent`, `--agent-key`), `ssh3-client/src/agent.rs` | — | — |
| A3 | Аутентификация | Password (HTTP Basic) | да | да | Go `cmd/ssh3.go:677` (`-use-password`), `auth/plugins/pubkey_authentication/client/privkey_auth.go:118`; Rust `ssh3-client/src/main.rs:72-82` (`--password`, `--password-file`) | — | — |
| A4 | Аутентификация | OIDC: интерактивный браузерный flow | да | да | Go `cmd/ssh3.go:683` (`-use-oidc`), `auth/oidc/openid_connect.go`; Rust `ssh3-client/src/main.rs:103-128`, `ssh3-client/src/lib.rs:1250` (`authenticate_oidc_with_browser_opener`) | — | — |
| A5 | Аутентификация | OIDC: PKCE | да | да | Go `cmd/ssh3.go:705` (`-no-pkce`); Rust `ssh3-client/src/main.rs:129` (`--no-pkce`) | — | — |
| A6 | Аутентификация | OIDC: файл конфигурации IdP (`client_id`/`client_secret`) | да | нет | Go `cmd/ssh3.go:684` (`-oidc-config`); Rust — **не найдено** (есть только `--oidc-client-id`/`--oidc-issuer-url`/`--oidc-client-secret-file`, `ssh3-client/src/main.rs:103-128`) | S | A4 |
| A7 | Аутентификация | Bearer-токен из файла/argv (pre-computed) | нет | да | Go — CLI-флага нет, только внутренний `rawBearerTokenIdentity` (`client_auth.go:242`); Rust `ssh3-client/src/main.rs:92-101` (`--bearer-token`, `--bearer-token-file`) | — | — |
| A8 | Аутентификация | `known_hosts` (чтение/проверка/дописывание) | да | да | Go `known_hosts.go:18` (`Knows`), `known_hosts.go:91` (`ParseKnownHosts`), `known_hosts.go:128` (`AppendKnownHost`); Rust `ssh3-client/src/known_hosts.rs` (`KnownHosts::parse`, `append_known_host`, `certificate_fingerprint`), `ssh3-client/src/host_key.rs` (сверка presented-сертификата) | — | — |
| A9 | Аутентификация | `strict-host-key-checking` (yes / accept-new / no / ask) | да | да | Go `cmd/ssh3.go:679`, `strict_host_key.go:43` (`ParseStrictHostKeyChecking`), `strict_host_key.go:62` (`ResolveStrictHostKeyChecking`); Rust `ssh3-client/src/strict_host_key.rs` (`Ssh3StrictHostKeyChecking`, `resolve_strict_host_key_checking`, `decide_host_key`), `ssh3-client/src/main.rs` (`--strict-host-key-checking`, `-o StrictHostKeyChecking=`) | — | A8 |
| A10 | Аутентификация | SSHFP / `VerifyHostKeyDNS` | да | нет | Go `cmd/cli_flags.go:226` (`parseVerifyHostKeyDNSValue`), `sshfp.go:663` (`CheckSSHFP`), `sshfp.go:500` (`UDPSSHFPResolver.LookupSSHFP`); Rust — **не найдено** | L | A8, A9, DNS-резолвер |
| A11 | Аутентификация | Проброс SSH-agent на сервер (`-A` / `-forward-agent`) | да | да | Go `cmd/ssh3.go:691-692`; Rust `ssh3-client/src/main.rs:65` (`--forward-agent`), `ssh3-client/src/lib.rs:1745` (`send_forward_agent_request`) | — | — |

### 2.2. Клиент — сессия, PTY, сигналы

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| B1 | Сессия | Shell | да | да | Go `cmd/ssh3.go` (операнд без команды → shell), `client/client.go:561`; Rust `ssh3-client/src/main.rs:216-217` (операнд команды), `ssh3-client/src/lib.rs:1436` (`run_session_stdio`) | — | — |
| B2 | Сессия | Exec (удалённая команда) | да | да | Go `client/session.go:24` (`SessionSpec`); Rust `ssh3-client/src/lib.rs:264-270` (`Ssh3SessionRequest::Shell`/`Exec`) | — | — |
| B3 | PTY | Автовыделение PTY при интерактивном stdin | да | да | Go `client/client.go:556` (RequestTTY-политика), `cmd/cli_flags.go:291` (`parseRequestTTY`); Rust `ssh3-client/src/lib.rs:346-359` (`resolve_pty`: `auto` → shell + терминал, `yes`/`force` → всегда, `no` → никогда) | — | — |
| B4 | PTY | `-t` — принудительное выделение PTY без tty | да | да | Go `cmd/ssh3.go:725`, `cmd/forced_pty.go`; Rust `ssh3-client/src/main.rs:146` (`-t`), `ssh3-client/src/lib.rs:358` (`Ssh3PtyPolicy::Force`) | S | B3 |
| B5 | PTY | `-T` — запрет PTY | да | да | Go `cmd/ssh3.go:726`; Rust `ssh3-client/src/main.rs:150` (`-T`), `ssh3-client/src/lib.rs:357` (`Ssh3PtyPolicy::No`) | S | B3 |
| B6 | PTY | `-o RequestTTY=auto\|no\|yes\|force` + ssh_config `RequestTTY` | да | да | Go `cmd/cli_flags.go:291` (`parseRequestTTY`), `cmd/ssh3.go:844`; Rust `ssh3-client/src/main.rs:455` (`-o RequestTTY=`), `ssh3-client/src/lib.rs:248-259` (`Ssh3PtyPolicy::parse`) | S | B4, B5 |
| B7 | PTY | `-o Term=` / переменная `TERM` | да | да | Go `cmd/cli_flags.go:310` (`parseTermType`), `cmd/cli_flags.go:329` (`resolveTermType`), `cmd/ssh3.go:1748`; Rust `ssh3-client/src/main.rs:461` (`-o Term=`), `ssh3-client/src/lib.rs:1743` (`config.term_type` → `PtySpec::new`) | S | — |
| B8 | PTY | Изменение размера окна (`window-change`) | да | да | Go `cmd/window_change.go`; Rust `ssh3-client/src/lib.rs:824` (`send_window_change_request`), `ssh3-client/src/lib.rs:880` (вызов `spawn_resize_forwarder`), `ssh3-client/src/console/unix.rs` † | — | — |
| B9 | Сигналы | Пересылка сигналов на удалённый процесс | да | да | Go `cmd/ssh3-server.go:55-74` (карта имён), `client/signals_unix.go`; Rust `ssh3-client/src/lib.rs:842` (`send_signal_request`), `ssh3-client/src/lib.rs:883` (вызов `spawn_signal_forwarders`), `ssh3-client/src/console/unix.rs` † | — | — |
| B10 | Сессия | `-s` — запрос подсистемы (в т.ч. `sftp`) | да | нет | Go `cmd/ssh3.go:727`, `cmd/cli_flags.go:146` (`parseSubsystemName`), `cmd/sftp_client.go:131` (`sftpChannelType`); Rust — **не найдено** (`Ssh3SessionRequest` = только `Shell`/`Exec`, `ssh3-client/src/lib.rs:264-270`) | M | F1 |
| B11 | Escape | Escape-последовательности (`~.`, `~^Z`, `~~`) | да | да | Go `client/escape.go:28` (`EscapeConfig`), `client/escape.go:50` (`Feed`), `cmd/ssh3.go:1764-1773` (`client.EscapeConfig`); Rust `ssh3-client/src/escape.rs:28` (`Ssh3EscapeFilter`), `ssh3-client/src/escape.rs:57` (`feed`), `ssh3-client/src/lib.rs:1934-1986` (проводка в pump) | S | B3 |
| B12 | Escape | `-o EscapeChar=` / ssh_config `EscapeChar` | да | да | Go `cmd/cli_flags.go:346` (`parseEscapeChar`), `cmd/ssh3.go:835`, `cmd/ssh3.go:1370`; Rust `ssh3-client/src/main.rs:266` (`-o EscapeChar=`), `ssh3-client/src/main.rs:470` (ssh_config), `ssh3-client/src/escape.rs:123` (`parse_escape_char`) | S | B11 |
| B13 | Сессия | Код возврата удалённой команды (`exit-status`, `128+signum`) | да | да | Go `cmd/exit_status.go:17` (`safeExitStatus`), `cmd/exit_status.go:51` (`exitCodeForExitSignal`), `cmd/exit_status.go:28-63` (карта `128+signum`); Rust `ssh3-client/src/lib.rs:672` (`exit_code_for_exit_signal`), `ssh3-client/src/main.rs:737-740` | — | — |
| B14 | Сессия | `-f` — уход в фон | да | нет | Go `cmd/ssh3.go:715`, `cmd/background.go:38` (`validateBackgroundMode`), `cmd/background.go:17` (`backgroundEnv`); Rust — **не найдено** | M | B12, A9 |
| B15 | Сессия | `-N` — не открывать сессию (только форвардинг) | да | да | Go `cmd/ssh3.go:723`; Rust `ssh3-client/src/main.rs:162` (`-N`), `ssh3-client/src/lib.rs:1451` (`run_forwards_only`), `ssh3-client/src/lib.rs:1460` (`hold_forwards`) | S | C1 |

### 2.3. Клиент — форвардинг

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| C1 | Форвардинг | `-L` прямой TCP-форвардинг (CLI) | да | да | Go `cmd/ssh3.go:709`, `cmd/ssh2_parity.go:67` (`parseLocalForwardSpec`), `cmd/ssh3.go:1663-1665` (локальные слушатели `-L`); Rust `ssh3-client/src/main.rs:196` (`-L`), `ssh3-client/src/forward.rs:92` (`parse_local_forward_spec`), `ssh3-client/src/forward.rs:295` (слушатель) | S | — |
| C2 | Форвардинг | `-L udp://` прямой UDP-форвардинг (CLI) | да | да | Go `cmd/ssh3.go:709`, `cmd/ssh2_parity.go:208` (`localListenUDPAddr`); Rust `ssh3-client/src/forward.rs:95-96` (префикс `udp://`), `ssh3-client/src/forward.rs:384` (`forward_udp_socket`) | S | C1 |
| C3 | Форвардинг | `-D` — SOCKS5 / динамический форвардинг | да | да | Go `cmd/ssh3.go:711`, `cmd/cli_flags.go:85` (`parseDynamicForwardSpec`), `cmd/dynamic_forward.go`, `cmd/dynamic_forward_server.go`; Rust `ssh3-client/src/dynamic.rs` (`parse_dynamic_forward_spec`, `serve_socks5_connection`), `ssh3-client/src/forwarding_wire.rs` (кодеки `dynamic-forward`/`dynamic-forward-tcp`), `ssh3-client/src/lib.rs` (`start_dynamic_forwards`), `ssh3-server/src/dynamic_forward.rs` | — | C1 |
| C4 | Форвардинг | `-R` — обратный форвардинг | да | да | Go `cmd/ssh3.go:713`, `cmd/reverse_forward.go`, `cmd/reverse_forward_server.go`; Rust `ssh3-client/src/reverse.rs` (`parse_reverse_forward_spec`, `request_reverse_forward`, `bridge_forwarded_tcp`), `ssh3-client/src/incoming.rs` (диспетчер серверных каналов, авторизация цели), `ssh3-client/src/forwarding_wire.rs`, `ssh3-server/src/reverse_forward.rs` | — | J2, J3 |
| C5 | Форвардинг | `-forward-tcp` / `-forward-udp` (legacy-алиасы) | да | нет | Go `cmd/ssh3.go:721-722`; Rust — **не найдено** | S | C1, C2 |
| C6 | Форвардинг | `-o LocalForward=` / `-o RemoteForward=` / `-o DynamicForward=` | да | да | Go `cmd/ssh3.go:883`, `cmd/ssh3.go:889`, `cmd/ssh3.go:897`; Rust `ssh3-client/src/main.rs:279` (`localforward`), `ssh3-client/src/main.rs:285` (`remoteforward`), `ssh3-client/src/main.rs:291` (`dynamicforward`) | S | C1, C3, C4 |
| C7 | Форвардинг | Серверный приём форвардинга (TCP/UDP) | да | да | Go `cmd/ssh3-server.go:1386` (маршрутизация каналов), `message/dynamic_forward.go`; Rust `ssh3-server/src/forwarding.rs:84` (`handle_tcp_forwarding`), `ssh3-server/src/forwarding.rs:24` (`handle_udp_forwarding`) | — | — |
| C8 | Форвардинг | Безопасная семантика (политика целей `permit-open`) | да | да | Go `cmd/forward_policy.go:52` (`parsePermitOpen`), `cmd/ssh3-server.go:1039`; Rust `ssh3-server/src/forwarding.rs:81-121` (`ForwardPolicy::parse`: `*`, `!`, `host:port`), `ssh3-server/src/runtime.rs:367-368` (передача политики в обработчик) | S | J1 |

### 2.4. Клиент — control master

> Обновление (волна control master): D1–D5 закрыты в `wave/t4-control-master` — кодек кадров (`ssh3-client/src/cm.rs`, формат байт-в-байт по `client/cm` эталона), мастер с 0600-сокетом и stale-rebind (`ssh3-client/src/control.rs`), slave и `-O check|stop|exit` с JSON-статусом, CLI `-M/-S/-O` + `-control-master/-control-path/-control-persist`, daemon через detached re-exec. Формулировки строк ниже — из исходного разбора; столбец Rust обновлён.
| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| D1 | Control master | `-M` / `-control-master=no\|yes\|auto` | да | да | Go `cmd/ssh3.go:699`, `cmd/ssh3.go:696`, `cmd/controlmaster.go`; Rust: `ssh3-client/src/main.rs` (флаг `-M`, `ControlMaster` в `-o` и ssh_config, policy no/yes/auto), `ssh3-client/src/control.rs` (`serve_control_master`) | L | A9, C1 |
| D2 | Control master | `-S` / `-control-path` (unix-сокет) | да | да | Go `cmd/ssh3.go:700`, `cmd/ssh3.go:697`, `client/control.go:109`; Rust: `ssh3-client/src/main.rs` (`-S`, `ControlPath`), `ssh3-client/src/control.rs` (`default_control_path` `~/.ssh3/cm-<user>@<host>:<port>`, `listen_control_master` 0600 + stale-rebind) | M | D1 |
| D3 | Control master | `-control-persist=no\|yes\|N` | да | да | Go `cmd/ssh3.go:698`, `cmd/ssh3.go:926` (`-o ControlPersist`), `cmd/ssh3.go:978`; Rust: `ssh3-client/src/main.rs` (`ControlPersist` no/yes/N), `ssh3-client/src/control.rs` (idle-timeout мастера) | M | D1 |
| D4 | Control master | `-O check\|stop\|exit` | да | да | Go `cmd/ssh3.go:695`, `cmd/cli_flags.go:180` (`validateControlOperation`), `client/control.go:28-31` (`ControlOpCheck/Stop/Exit`), `client/control.go:68` (`RunControlOp`); Rust — **не найдено** | M; Rust: `ssh3-client/src/control.rs` (`run_control_op`, JSON `MasterStatus`, отказ «predates the extension» как в Go), `ssh3-client/src/main.rs` (`-O check|stop|exit`, вывод status line); | D2 |
| D5 | Control master | Протокол кадров control-сокета (`client/cm`) | да | да | Go `client/cm/messages.go`, `client/cm/protocol.go`, `client/cm/framing.go`; Rust: `ssh3-client/src/cm.rs` (S3CM-фрейминг `magic S3CM + version + type + u32 len`, типы 1–11 + `MSG_CONTROL_OP=12`, `hello`/`call`, 20 юнит-тестов формата) | M | D2 |

### 2.5. Клиент — proxy jump

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| E1 | Proxy jump | `-J host[,host...]` (цепочка хопов) | да | нет | Go `cmd/ssh3.go:707`, `cmd/ssh2_parity.go:120` (`parseProxyJumpChain`), `cmd/ssh3.go:1616-1625` (диалог цепочки); Rust — **не найдено** | L | C2 |
| E2 | Proxy jump | `-proxy-jump` (deprecated-алиас) | да | нет | Go `cmd/ssh3.go:706`, `cmd/ssh3.go:980`; Rust — **не найдено** | S | E1 |
| E3 | Proxy jump | ssh_config `ProxyJump` / `UDPProxyJump` | да | частично | Go `cmd/ssh3.go:1378-1380`, `cmd/ssh3.go:903`; Rust `ssh3-client/src/ssh_config.rs` (чтение ключа), `ssh3-client/src/main.rs:489` (`-o ProxyJump=`) — значение разбирается и проверяется, но сам туннель через jump-хост не реализован | M | E1, G4 |
| E4 | Proxy jump | Бюджет датаграмм туннеля (48 б/уровень, внешний пакет = база + 48·N, не ниже 1200) | да | нет | Go `cmd/ssh3.go:89` (`tunnelDatagramOverhead = 48`), `cmd/ssh3.go:99-112` (`tunnelOuterSize`), `cmd/ssh3.go:114-125` (`tunneledPacketSize`), `cmd/ssh3.go:1535`, `cmd/ssh3.go:1555`, `cmd/ssh3.go:1621`; Rust — **не найдено** (туннеля нет) | M | E1, H8 |

### 2.6. Клиент — передача файлов

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| F1 | Передача файлов | `-transfer SRC DST` (upload/download) | да | нет | Go `cmd/ssh3.go:714`, `cmd/sftp_client.go:135` (`runFileTransfer`), `cmd/sftp_client.go:41` (`isRemoteTransferSpec`); Rust — **не найдено** | L | B10, F5 |
| F2 | Передача файлов | `-r` — рекурсивная передача каталогов | да | нет | Go `cmd/ssh3.go:718`, `cmd/sftp_client.go:195` (`uploadDir`), `cmd/sftp_client.go:269` (`downloadDir`); Rust — **не найдено** | M | F1 |
| F3 | Передача файлов | `-continue` — докачка прерванного transfer | да | нет | Go `cmd/ssh3.go:719`, `cmd/sftp_client.go:513` (`hashResumePrefix`); Rust — **не найдено** | M | F1 |
| F4 | Передача файлов | `-checksum` — проверка SHA-256 | да | нет | Go `cmd/ssh3.go:720`, `cmd/sftp_client.go:425` (`verifyRemoteChecksum`); Rust — **не найдено** | M | F1 |
| F5 | Передача файлов | `-P` (порт) и `-U` (URL path) для операнда `user@host:path` | да | нет | Go `cmd/ssh3.go:716-717`, `cmd/sftp_client.go:67` (`parseRemoteTransferSpec`); Rust — **не найдено** | S | F1 |
| F6 | Передача файлов | Интерактивный SFTP-клиент (`-s sftp`) | да | нет | Go `cmd/ssh3.go:727`, `cmd/sftp_client.go:135`; Rust — **не найдено** (серверная подсистема SFTP есть — см. L7, но клиента нет) | M | F1, B10 |

### 2.7. Конфигурация, `-o`, ssh_config

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| G1 | Конфигурация | `-F path` — альтернативный ssh_config | да | да | Go `cmd/ssh3.go:724`, `cmd/cli_flags.go:169` (`resolveConfigPath`); Rust `ssh3-client/src/main.rs:188` (`-F`), `ssh3-client/src/main.rs` (`load_user_ssh_config`) — нечитаемый файл игнорируется с предупреждением в stderr, как в Go | S | G3 |
| G2 | Конфигурация | `-o Key=Value` (повторяемый) | да | да | Go `cmd/ssh3.go:682`, `cmd/ssh3.go:823-939` (диспетчер по 13 ключам); Rust `ssh3-client/src/main.rs` (`parse_options`) — ключи `RequestTTY`, `Term`, `EscapeChar`, `StrictHostKeyChecking`, `LocalForward`, `RemoteForward`, `DynamicForward`, `ProxyJump`, `ServerAliveInterval` | M | G3 |
| G3 | Конфигурация | ssh_config: секции `Host` | да | да | Go `client/config/matchcfg/matchcfg.go:294` (`parseSections`), `client/config/matchcfg/matchcfg.go:123`; Rust `ssh3-client/src/ssh_config.rs` (`SshConfig::parse_with_base`, `SshConfigSection`) | M | — |
| G4 | Конфигурация | ssh_config: секции `Match` (all/final/canonical/host/originalhost/user) | да | да | Go `client/config/matchcfg/matchcfg.go:257` (`matchSection`), `client/config/matchcfg/matchcfg.go:534` (`parseMatchCriteria`); Rust `ssh3-client/src/ssh_config.rs` (`parse_match_criteria`, `MatchCriterion`, `criteria_hold`) — критерии `all`, `final`, `host`, `originalhost`, `user`, `localuser`, `exec` и отрицание через `!` | L | G3 |
| G5 | Конфигурация | ssh_config: `Include` (рекурсия, glob, `~/.ssh`) | да | да | Go `client/config/matchcfg/matchcfg.go:342` (`expandIncludes`), `client/config/matchcfg/matchcfg.go:120` (`maxIncludeDepth = 16`), `client/config/matchcfg/matchcfg.go:447` (`globInclude`); Rust `ssh3-client/src/ssh_config.rs` (`expand_includes`, `resolve_include_target`, `glob_paths`, `MAX_INCLUDE_DEPTH = 16`) | M | G3 |
| G6 | Конфигурация | ssh_config: `ServerAliveInterval` | да | да | Go `cmd/ssh3.go:1345`; Rust `ssh3-client/src/main.rs:480` (`ssh_config_values`, `keep_alive_interval`) | S | G3 |
| G7 | Конфигурация | ssh_config: `ForwardAgent` | да | да | Go `cmd/ssh3.go:1351`; Rust `ssh3-client/src/main.rs:476` (`ssh_config_values`, `forward_agent`) | S | G3, A11 |
| G8 | Конфигурация | ssh_config: `EscapeChar` | да | да | Go `cmd/ssh3.go:1370`; Rust `ssh3-client/src/main.rs:470` (`ssh_config_values`, `escape_char`) | S | G3, B12 |
| G9 | Конфигурация | ssh_config: `StrictHostKeyChecking` | да | да | Go `strict_host_key.go:62` (`ResolveStrictHostKeyChecking`); Rust `ssh3-client/src/ssh_config.rs` (`SshConfig::get_for_user`), `ssh3-client/src/main.rs:452` (`ssh_config_values`) | — | G3, A9 |
| G10 | Конфигурация | ssh_config: `User`, `Port` | да | частично | Go `cmd/ssh3.go:868` (`Port`), `cmd/ssh3.go:876` (`User`); Rust `ssh3-client/src/ssh_config.rs:295` (`User` читается) — ключа `Port` **не найдено** | S | G3 |
| G11 | Конфигурация | ssh_config: `IdentityFile` | да | нет | Go `cmd/ssh3.go:943` (маршрутизация по ключу), `auth/plugins/pubkey_authentication/client/privkey_auth.go:57`; Rust — **не найдено** | S | G3, A1 |
| G12 | Конфигурация | Переменные окружения `SSH3_*` (серверная политика) | да | нет | Go `cmd/ssh3-server.go:993-1083` (`SSH3_ENABLE_PASSWORD_LOGIN`, `SSH3_GATEWAY_PORTS`, `SSH3_MAX_*`, `SSH3_PERMIT_OPEN`, `SSH3_PERMIT_LISTEN`, `SSH3_SHUTDOWN_DRAIN`), `packaging/ssh3-server.env`; Rust — **не найдено** | M | — |

### 2.8. Клиент — прочие флаги и сервисы

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| H1 | Прочее | `-v` / `-q` — уровни логирования | да | нет | Go `cmd/ssh3.go:685-686`, `cmd/ssh3.go:667` (`zerolog.SetGlobalLevel`), `cmd/ssh3.go:1080-1084` (`util.ConfigureLogger`); Rust — **не найдено** (только `eprintln!` в `ssh3-client/src/main.rs:729`) | S | — |
| H2 | Прочее | `-keylog` — файл ключей TLS | да | нет | Go `cmd/ssh3.go:676`; Rust — **не найдено** | S | — |
| H3 | Прочее | `-4` / `-6` — только IPv4 / IPv6 | да | нет | Go `cmd/ssh3.go:728-729`, `cmd/ssh3.go:772` (взаимная исключительность); Rust — **не найдено** | S | — |
| H4 | Прочее | `-p` — порт сервера | да | нет | Go `cmd/ssh3.go:702`; Rust — **не найдено** (порт только в URL) | S | — |
| H5 | Прочее | `-insecure` — не проверять сертификат | да | да | Go `cmd/ssh3.go:678`; Rust `ssh3-client/src/main.rs:139` | — | — |
| H6 | Прочее | `-version` / `-V` | да | да | Go `cmd/ssh3.go:688-689`; Rust `ssh3-client/src/main.rs:170` (`-V`/`--version`), `ssh3-client/src/lib.rs:95` (`SSH3_CLIENT_VERSION_STRING`) — печатается строка версии в формате Go (`SSH 3.0 ssh3-rust 0.1.0 experimental_spec_version=alpha-00`) | — | — |
| H7 | Прочее | X11 forwarding | да (серверная заглушка) | нет | Go `cmd/ssh3-server.go:564` (`newX11Req`), `cmd/ssh3-server.go:1497`, `client/session_pump.go:156` («not implemented» на клиенте); Rust — протокольный тип есть (`ssh3-proto/src/message.rs:330-331`), обработчика нет | M | — |
| H8 | Прочее | `-packet-size` / `-initial-packet-size` — начальный размер QUIC-пакета (дефолт 1200, минимум RFC 9000) | да | частично | Go `cmd/ssh3.go:703` (клиент), `cmd/ssh3-server.go:965` (сервер), `cmd/ssh3.go:210-212` (применение к `qconf.InitialPacketSize`); Rust — параметра **не найдено** (`ssh3-quinn/src/config.rs` не задаёт `TransportConfig`), но фактическое значение совпадает: дефолт `quinn` `initial_mtu` = 1200 | S | — |
| H9 | Прочее | Отключённый path-MTU discovery (сервер и туннелированные соединения) | да | нет | Go `cmd/ssh3-server.go:1316` (`DisablePathMTUDiscovery: true`), `cmd/ssh3.go:216-220` (туннель); Rust — **не найдено**: `quinn` оставляет PMTUD включённым по умолчанию, `ssh3-server/src/tls.rs:22-33` меняет только таймауты | S | H8, E4 |

### 2.9. Сервер — аутентификация и политики

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| I1 | Сервер: аутентификация | Pubkey по authorized-файлам | да | да | Go `server_auth/authorized_identities.go`, `server_auth/auth.go`; Rust `ssh3-server/src/auth.rs:447` (`authorize_request`), `ssh3-server/src/auth.rs:288` (`default_authorized_identity_paths`) | — | — |
| I2 | Сервер: аутентификация | Password (crypt/shadow) | да | да | Go `util/unix_util/linux_user.go:109` (`ComparePasswordWithHashedPassword`), `util/unix_util/user.go:123`; Rust `ssh3-server/src/auth.rs:358` (`default_password_verifier`) | — | — |
| I3 | Сервер: аутентификация | OIDC identity token | да | да | Go `server_auth/auth.go`; Rust `ssh3-server/src/auth.rs:524-527` (`verify_oidc_identity_token`), `ssh3-auth/src/lib.rs` | — | — |
| I4 | Сервер: аутентификация | Включение/выключение password-логина | да | да | Go `cmd/ssh3-server.go:993` (`-enable-password-login`); Rust `ssh3-server/src/main.rs:48` (`--enable-password-login`), `ssh3-server/src/auth.rs:314` (`should_authenticate`) | — | — |
| I5 | Сервер: аутентификация | Root-gate (root не входит по паролю) | да | нет | Go `server_auth/root_gate.go:13` (`PasswordLoginRefused`); Rust — **не найдено** | S | I2 |
| I6 | Сервер: DoS-guard | Кап неавторизованных диалогов (аналог MaxStartups) | да | да | Go `server_auth/dos_guard.go:26` (`MaxUnauthenticatedConversations = 100`), `server_auth/dos_guard.go:44` (`TryAcquireUnauthenticatedConversation`), `cmd/ssh3-server.go:1012`; Rust `ssh3-server/src/runtime.rs:181-186` (`try_acquire_unauthenticated`), `ssh3-server/src/config.rs:200`, `ssh3-server/src/config.rs:312` | S | — |
| I7 | Сервер: DoS-guard | Lockout после N неудачных паролей | да | да | Go `server_auth/dos_guard.go:30` (`MaxPasswordAuthFailures = 10`), `server_auth/dos_guard.go:33` (`PasswordLockoutDuration = 60s`), `cmd/ssh3-server.go:1017`, `cmd/ssh3-server.go:1022`; Rust `ssh3-server/src/auth.rs:164-186` (`password_failure`), `ssh3-server/src/config.rs:202-204`, `ssh3-server/src/config.rs:315-318` | M | I2 |
| I8 | Сервер: аутентификация | Константно-временное сравнение хэша пароля | да | нет | Go `util/unix_util/linux_user.go:109` — сравнение через `subtle`; Rust `ssh3-server/src/auth.rs:411` — `==` (неконстантно) | S | I2 |
| I9 | Сервер: аутентификация | Константно-временное сравнение SSHFP | да | нет | Go `sshfp.go:194` (`subtleEqual`); Rust — **не найдено** | S | A10 |

### 2.10. Сервер — политики форвардинга

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| J1 | Сервер: форвардинг | `-permit-open` (список допустимых целей, `*`, `!`) | да | да | Go `cmd/forward_policy.go:52` (`parsePermitOpen`), `cmd/ssh3-server.go:1039`; Rust `ssh3-server/src/main.rs:65` (`--permit-open`), `ssh3-server/src/forwarding.rs:81-121` (`ForwardPolicy::parse`) | M | — |
| J2 | Сервер: форвардинг | `-permit-listen` (допустимые bind-адреса для `-R`) | да | да | Go `cmd/forward_policy.go` (второй набор записей), `cmd/ssh3-server.go:1043`; Rust `ssh3-server/src/main.rs:72` (`--permit-listen`), `ssh3-server/src/reverse_forward.rs:313` (`check_listen_target`) | M | — |
| J3 | Сервер: форвардинг | `-gateway-ports` (no / clientspecified / yes) | да | да | Go `cmd/ssh3-server.go:1002`; Rust `ssh3-server/src/config.rs:190` (`GatewayPortsPolicy`), `ssh3-server/src/reverse_forward.rs:240` (`resolve_reverse_forward_bind`) | M | C4 |
| J4 | Сервер: форвардинг | `-max-reverse-forwards` (на пользователя) | да | да | Go `cmd/ssh3-server.go:1007`; Rust `ssh3-server/src/main.rs:84` (`--max-reverse-forwards`), `ssh3-server/src/reverse_forward.rs:251` (`acquire_reverse_forward_bind`) | S | C4 |

### 2.11. Сервер — лимиты и таймауты

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| K1 | Сервер: лимиты | `-max-channels-per-conversation` | да | нет | Go `cmd/ssh3-server.go:1048`, `cmd/ssh3-server.go:1341` (`newBudget`), `cmd/channel_budget.go`; Rust — **не найдено** | S | — |
| K2 | Сервер: лимиты | `-max-connections` | да | нет | Go `cmd/ssh3-server.go:1058`, `cmd/ssh3-server.go:1582`; Rust — **не найдено** (`ssh3-server/src/runtime.rs:42` — бесконечный цикл приёма) | S | — |
| K3 | Сервер: лимиты | `-max-incoming-streams` / `-max-incoming-uni-streams` | да | нет | Go `cmd/ssh3-server.go:1078`, `cmd/ssh3-server.go:1083`; Rust — **не найдено** | S | — |
| K4 | Сервер: таймауты | `-max-idle-timeout` (QUIC idle) | да | да | Go `cmd/ssh3-server.go:1068` (дефолт 24 ч — канон ssh2); Rust `ssh3-server/src/main.rs:101` (`--max-idle-timeout`), `ssh3-server/src/tls.rs:22-33` (`apply_transport_timeouts`), `ssh3-server/src/config.rs:321` (дефолт 24 ч) | S | — |
| K5 | Сервер: таймауты | `-handshake-idle-timeout` | да | да | Go `cmd/ssh3-server.go:1073` (дефолт 120 с — масштаб `LoginGraceTime`); Rust `ssh3-server/src/main.rs:93` (`--handshake-idle-timeout`), `ssh3-server/src/runtime.rs:46-52`, `ssh3-server/src/config.rs:324` (дефолт 120 с) | S | — |
| K6 | Сервер: лимиты | Клампы SSH-строки и `maxPacketSize` | да | да | Go `util/wire.go:212` (`MaxSSHStringLen = 1<<24`), `util/wire.go:219`, `channel.go:184` (`clampPeerMaxPacketSize`), `channel.go:199` (`clampLocalMaxPacketSize`); Rust `ssh3-proto/src/wire.rs:33` (`MAX_SSH_STRING_LEN = 1<<24`), `ssh3-proto/src/wire.rs:243-255` (`read_ssh_bytes`), `ssh3-core/src/channel.rs:49-65` (клампы), `ssh3-core/src/channel.rs:598-600` (`apply_peer_max_packet_size`) | — | — |

### 2.12. Сервер — функциональность

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| L1 | Сервер | Секретный URL-путь (`-url-path`) | да | да | Go `cmd/ssh3-server.go:962`, `cmd/ssh3-server.go:1544` (`mux.HandleFunc(*urlPath, handler)`); Rust `ssh3-server/src/runtime.rs:126` (`request_path_matches`), `ssh3-server/src/runtime.rs:165-167` (404 на чужой путь), `ssh3-server/src/config.rs:309` (дефолт `/ssh3-term`) | S | — |
| L2 | Сервер | Автогенерация self-signed сертификата | да | да | Go `cmd/ssh3-server.go:967` (`-generate-selfsigned-cert`), `generate_openssl_selfsigned_certificate.sh`; Rust `ssh3-server/src/tls.rs`, `ssh3-server/src/main.rs:439` (`run_with_self_signed`) | — | — |
| L3 | Сервер | Публичный сертификат (ACME / Let's Encrypt) | да | нет | Go `cmd/ssh3-server.go:977` (`-generate-public-cert`), `cmd/ssh3-server.go:1278` (`certmagic.TLS`); Rust — **не найдено** | L | — |
| L4 | Сервер | `-cert` / `-key` / `-c` / `-h` — свои сертификаты | да | нет | Go `cmd/ssh3-server.go:969-974`; Rust — **не найдено** (только self-signed) | M | L3 |
| L5 | Сервер | PTY-сессии | да | да | Go `cmd/ssh3-server.go` (`pty-req`), `cmd/ssh3.go` (клиент); Rust `ssh3-server/src/session.rs:420` (ветка `Pty`), `ssh3-server/src/pty.rs` | — | — |
| L6 | Сервер | Смена размера окна / сигналы на сервере | да | да | Go `cmd/ssh3-server.go:1497`; Rust `ssh3-server/src/session.rs:503` (`WindowChange`), `ssh3-server/src/session.rs:490` (`Signal`) | — | — |
| L7 | Сервер | Подсистема SFTP | да | да † | Go `cmd/ssh3-server.go:1386` (`serveSFTPSubsystem`), `cmd/ssh3-server.go:721` (`newSubsystemReq`), `cmd/sftp_subsystem.go`; Rust `ssh3-server/src/runtime.rs:348` (`handle_sftp_channel`), `ssh3-server/src/sftp.rs:50` (`CHANNEL_TYPE_SFTP`), `ssh3-server/src/sftp_stream.rs` | L | F1 |
| L8 | Сервер | Изоляция путей SFTP (`-sftp-jail`: chroot / lexical) | да | да † | Go `cmd/ssh3-server.go:1030`, `cmd/ssh3-server.go:1143`, `cmd/internal_sftp.go`; Rust `ssh3-server/src/config.rs:93` (`SftpJailMode`), `ssh3-server/src/sftp.rs:815-836` (chroot/lexical), `ssh3-server/src/sftp_child.rs` (дочерний процесс с chroot и сменой uid/gid) | M | L7 |
| L9 | Сервер | Graceful shutdown (SIGTERM → drain) | да | нет | Go `cmd/ssh3-server.go:1612-1633` (drain), `cmd/ssh3-server.go:1642` (`shutdownDrainPeriod`), `packaging/ssh3-server.env` (`SSH3_SHUTDOWN_DRAIN`); Rust — **не найдено**: `ssh3-server/src/runtime.rs:42-58` — остановки по сигналу нет | M | — |

### 2.13. Эксплуатация

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| M1 | Эксплуатация | systemd-юнит | да | да | Go `packaging/ssh3-server.service`; Rust `packaging/ssh3-rust-server.service` | S | — |
| M2 | Эксплуатация | systemd EnvironmentFile | да | да | Go `packaging/ssh3-server.env`; Rust `packaging/ssh3-rust-server.env` | S | G12 |
| M3 | Эксплуатация | Debian-упаковка (`.deb`) | да | да † | Go `packaging/debian/control`, `packaging/debian/rules`, `packaging/debian/ssh3.1`, `packaging/debian/ssh3-server.8`; Rust `packaging/build-deb.sh`, `packaging/ssh3-rust-server.control.in`, `packaging/ssh3-rust-server.postinst`, `packaging/ssh3-rust-server.prerm` | M | M1 |
| M4 | Эксплуатация | Man-страницы | да | нет | Go `packaging/debian/ssh3.1`, `packaging/debian/ssh3-server.8`; Rust — **не найдено** (в `packaging/` файлов `.1` нет) | M | — |
| M5 | Эксплуатация | Структурированное логирование (уровни, файл) | да | нет | Go `cmd/ssh3.go:667` (`zerolog.SetGlobalLevel`), `cmd/ssh3.go:1080-1084` (`util.ConfigureLogger`), `util/util.go` (`ConfigureLogger`), `packaging/ssh3-server.env` (`SSH3_LOG_LEVEL`, `SSH3_LOG_FILE`); Rust — **не найдено** (только `eprintln!`) | M | — |
| M6 | Эксплуатация | Коды возврата и баннер версии | да | да | Go `cmd/exit_status.go:17`, `cmd/exit_status.go:51`, `version.go:22-27` (`PROTOCOL_MAJOR`, `SOFTWARE_IMPLEMENTATION_NAME`); Rust `ssh3-client/src/lib.rs:672` (`exit_code_for_exit_signal`), `ssh3-client/src/main.rs:737-740`, `ssh3-h3/src/lib.rs:19` (`SSH3_VERSION_STRING`) | — | B13 |

### 2.14. Протокол — сжатие тела канала (B8)

> Обновление (волна сжатия): N1–N6 закрыты в `wave/t9-compression` — кадр 192 (`ssh3-proto`), кодеки и лимит бомбы (`ssh3-core/src/compress.rs`), запись с cutoff и negotiation по version string (`ssh3-core/src/channel.rs`, `ssh3-h3/src/lib.rs`), двусторонний interop против Go (17/18 сценариев с `compress=`) и golden-вектор кадра. Формулировки строк ниже — из исходного разбора; столбец Rust обновлён.

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| N1 | Сжатие | Capability `compress=<список>` в строке версии (объявление и разбор) | да | да | Go `version.go:244-246` (объявление в `GetVersionString`), `version.go:305-317` (разбор поля в `ParseVersionString`), `compress/compress.go:139-148` (`Available`), `compress/compress.go:167-179` (`ParseCapability`); Rust — **не найдено**: строка версии без поля (`ssh3-h3/src/lib.rs:19`, `ssh3-client/src/lib.rs:95`), разбора capability нет | S; Rust: `ssh3-h3/src/lib.rs` (`SSH3_VERSION_STRING` с `compress=zstd,deflate,lz4`), `ssh3-core/src/compress.rs` (`parse_version_capability`, `negotiate_with_version_string`); | N2, N3 |
| N2 | Сжатие | Сжатый кадр тела канала (тип сообщения 192: id алгоритма + сжатая полезная нагрузка) | да | да | Go `message/message.go:44` (`SSH_MSG_CHANNEL_DATA_COMPRESSED = 192`), `message/message.go:158-166` (`CompressedDataHeader`), `message/message.go:168-186` (`ParseCompressedDataMessage`), `message/message.go:280` (диспетчер), `channel.go:429-441` (запись сжатого кадра); Rust — **не найдено**: `ssh3-core/src/channel.rs:884-889` — незнакомый тип даёт `UnknownMessageType`, кадр 192 рвёт канал | M; Rust: `ssh3-proto/src/message.rs` (`SSH_MSG_CHANNEL_DATA_COMPRESSED`, `compressed_data_header`), `ssh3-core/src/channel.rs` (`parse_message` ветка 192, `write_data` сжатие чанка); golden `ssh3-proto/tests/data/wire_vectors.txt` (`channel_data_compressed_deflate`); | N1, N3 |
| N3 | Сжатие | Кодеки deflate / lz4 (block) / zstd (frame) и общий порядок выбора (zstd → deflate → lz4) | да | да | Go `compress/compress.go:64-69` (id 0–3), `compress/compress.go:122-131` (имена и порядок), `compress/compress.go:185-193` (`Choose`), `compress/compress.go:245-279` (`Compress`), `compress/compress.go:315-335` (`Decompress`); Rust — **не найдено** | L; Rust: `ssh3-core/src/compress.rs` (`compress`/`decompress`, порядок `CODECS`, lz4 block `lz4_flex`, zstd one-shot `zstd::bulk` с FCS); кросс-декомпрессия Go↔Rust проверена фикстурами `compress/interop_test.go` эталона; | — |
| N4 | Сжатие | Cutoff «fast levels» ZFS: кадр, не уменьшившийся, едет в открытом виде | да | да | Go `channel.go:430` (`len(packed) < len(chunk)`), `compress/compress.go:241-244` (контракт), `compress/compress.go:266-272` (отказ кодека lz4); Rust — **не найдено** | S; Rust: `ssh3-core/src/channel.rs` (`write_data`: кадр едет открытым, если `packed >= chunk`); | N3 |
| N5 | Сжатие | Лимит «бомбы» декодера — 16 MiB (предел пакета канала) | да | да | Go `compress/compress.go:81` (`MaxOutput = 16 << 20`), `compress/compress.go:315-335`, `compress/compress.go:367-389` (zstd: проверка FCS); Rust — **не найдено** | S; Rust: `ssh3-core/src/compress.rs` (`MAX_OUTPUT = 16 << 20`, `TooLarge`); | N3 |
| N6 | Сжатие | Сервер сжимает в ответ (кодек — из capability, объявленной клиентом) | да | да | Go `server.go:196-201` (`CompressAlgorithm` приёма канала), `server.go:225-233` (`newServerChannel`), `conversation.go:58-65` (`compressAlgorithm`), `conversation.go:353` (входящий канал); Rust — **не найдено** | M; Rust: `ssh3-core/src/conversation.rs` (`compression_algorithm` + `set_compression_algorithm` на conversation и каналах), `ssh3-h3/src/lib.rs` (negotiation из User-Agent клиента и Server-заголовка ответа), `ssh3-quinn/src/channel.rs` (входящие каналы наследуют кодек); | N1, N2, N3 |

---

## 3. Расхождения в поведении

### 3.1. Расхождения при наличии возможности в обеих реализациях

Возможность реализована и там, и там, но ведёт себя **по-разному** — 1 полное расхождение и 3 частичных.

| № | Строка | Подсистема | Расхождение | Go | Rust | Влияние |
|---|--------|-----------|-------------|----|------|---------|
| R1 | I4 | Сервер: аутентификация | **Password-login по умолчанию.** Go: парольный вход **включён** по умолчанию, выключается `-enable-password-login=false` / `SSH3_ENABLE_PASSWORD_LOGIN=0`. Rust: `enable_password_login: false` в дефолте конфигурации — парольный вход по умолчанию **выключен** и сервер его не запрашивает. | `cmd/ssh3-server.go:993` (дефолт `true`) | `ssh3-server/src/config.rs:285` (`enable_password_login: false`), `ssh3-server/src/config.rs:359` (валидация) | Расхождение в **безопасную** сторону: Rust-сервер из коробки не принимает пароли, но и не запрашивает их — поведение неэквивалентно и требует явного решения |
| R2 | E3, G10 | Proxy jump / конфигурация | **Частичное покрытие конфигурации.** Go: ssh_config даёт `ProxyJump`/`UDPProxyJump` (`cmd/ssh3.go:1378-1380`) и `User`/`Port` (`cmd/ssh3.go:868`, `cmd/ssh3.go:876`). Rust: `ProxyJump` читается и проверяется, но туннеля нет (E3); `User` читается (`ssh3-client/src/ssh_config.rs:295`), ключ `Port` не поддержан (G10). | `cmd/ssh3.go:1378-1380`, `cmd/ssh3.go:868`, `cmd/ssh3.go:876` | `ssh3-client/src/main.rs:489`, `ssh3-client/src/ssh_config.rs:295` | Rust-клиент не может взять порт из `~/.ssh/config` — соединение уйдёт на порт по умолчанию |
| R3 | H8 | Прочие флаги | **Начальный размер QUIC-пакета.** Go: `-packet-size` / `-initial-packet-size`, дефолт 1200, значение применяется к `quic.Config.InitialPacketSize`. Rust: параметра нет, но фактическое значение совпадает — дефолт `quinn` `initial_mtu` = 1200. | `cmd/ssh3.go:703`, `cmd/ssh3-server.go:965`, `cmd/ssh3.go:210-212` | `ssh3-quinn/src/config.rs` (параметра нет; дефолт `quinn` 1200) | Значения совпадают — расхождение только в управлении: у Rust нет способа поднять/опустить пакет (нужно для туннеля, E4) |

### 3.2. Поведенческие последствия пробелов

Здесь возможность **отсутствует** в Rust, поэтому поведение расходится более радикально — перечислено, чтобы при закрытии пробела не потерять нюанс Go-семантики.

| № | Пробел | Подсистема | Поведение Go | Поведение Rust | Последствие |
|---|--------|-----------|-------------|---------------|-------------|
| P1 | A8, A9, A10 | Аутентификация | **Доверие к серверу**: три независимых слоя — TLS-CA, `known_hosts`/`StrictHostKeyChecking` (политика `ask` по умолчанию) и SSHFP. | `known_hosts` и `StrictHostKeyChecking` есть (`ssh3-client/src/known_hosts.rs`, `ssh3-client/src/strict_host_key.rs`); SSHFP нет; доверие к CA — выбор между `WebPkiRoots`, `--ca-cert` и `--insecure` (`ssh3-client/src/lib.rs:1644-1660`, `ssh3-client/src/main.rs:139`). | Ветка SSHFP отсутствует — у Rust нет второй, независимой проверки хоста, кроме отпечатка в `known_hosts` |
| P2 | F1–F6 | Передача файлов | `-transfer`, `-r`, `-continue`, `-checksum`, `-P`/`-U`, интерактивный SFTP — `cmd/sftp_client.go`. | Не найдено ни клиента SFTP, ни режима передачи (в `ssh3-client/src/main.rs` нет таких флагов); серверная подсистема SFTP есть (L7 †) | Функциональность форвардинга и файловый сервис есть, а клиента передачи — нет: SFTP-клиент и `-transfer` — самые заметные пробелы продукта |
| P3 | I8, I9 | Сервер: аутентификация | Сравнение хэша пароля константно-временно (`util/unix_util/linux_user.go:109`) и SSHFP — константно-временно (`sshfp.go:194`). | Обычный `==` с ранним выходом (`ssh3-server/src/auth.rs:411`); SSHFP нет. | Timing-канал на подбор пароля остаётся (lockout в `ssh3-server/src/auth.rs:164-186` ограничивает частоту, но не устраняет канал) |
| P4 | K1, K2, K3 | Сервер: лимиты | Кап SSH-строки `util.MaxSSHStringLen = 1<<24` (`util/wire.go:212`) и кламп `maxPacketSize` — закрыты в Rust (`ssh3-proto/src/wire.rs:243-255`, `ssh3-core/src/channel.rs:49-65`); **не закрыты** лимиты соединений, каналов и входящих потоков. | `ssh3-server/src/runtime.rs:42` — бесконечный цикл приёма: ни `-max-connections`, ни `-max-channels-per-conversation`, ни `-max-incoming-streams` нет. | Сервер не ограничивает число соединений и каналов — вектор исчерпания памяти остаётся |
| P5 | L9 | Сервер | По SIGTERM/SIGINT сервер перестаёт принимать соединения и дренирует активные в течение `SSH3_SHUTDOWN_DRAIN` (по умолчанию 5 с) — `cmd/ssh3-server.go:1612`, `cmd/ssh3-server.go:1620-1633`. | Сигналы не ловятся: процесс умирает по умолчанию, активные сессии обрываются (`ssh3-server/src/runtime.rs:42-58`). | При обновлении сервера рвутся живые сессии; в systemd без `KillMode=process` — тем более |
| P6 | D1–D5, E1 | Control master / proxy jump | Control master (`-M`/`-S`/`-O`, протокол `client/cm`) и цепочка `-J` с UDP-туннелем. | Не найдено ни сокета control master, ни туннеля. | Каждое соединение — новое QUIC-рукопожатие; jump-хост недоступен |

Дополнительные расхождения **внутри wire-уровня** (не продуктовая поверхность, но влияют на совместимость) — уже зафиксированы в `ROADMAP.md:208-217` (M5): порядок `family`/`protocol` в `ForwardingRequest` (`ssh3-proto/src/message.rs:783` против `message/channel_request.go:609`), обработка `bool` (`ssh3-proto/src/wire.rs:185`), отсутствие клампа `maxPacketSize` (`ssh3-core/src/channel.rs:667`), отсутствие `forward-port` в карте Go.

### 3.3. Совместимость wire-уровня: сжатие и размер пакета

Оценка риска для связки Go ↔ Rust по двум новым возможностям Go.

| № | Возможность Go | Механизм | Совместимость с Rust | Риск |
|---|-----------------|----------|----------------------|------|
| W1 | Сжатие тела канала (`compress=`, тип 192) | Capability в строке версии; **пир сжимает только то, что другой объявил** (`compress.Choose(peerMask)`, `compress/compress.go:185-193`); пустое объявление = «без сжатия» (`version.go:310-311`, `compress/compress.go:167-179`) | **Совместимо сегодня.** Rust не объявляет `compress=` (`ssh3-h3/src/lib.rs:19`), поэтому Go-пир не пришлёт сжатых кадров: `Choose(0)` → `AlgorithmNone` → открытые кадры. Rust-декодер сжатых кадров не нужен для interop | **Средний, отложенный.** Если Rust объявит `compress=`, не реализовав декодер, Go-пир **немедленно** начнёт слать кадры 192, а диспетчер Rust отвергнет их как `UnknownMessageType` (`ssh3-core/src/channel.rs:884-889`) — канал упадёт. Правило: объявлять capability **только вместе с** полным декодером (кадр 192 + кодек + лимит бомбы) |
| W2 | Начальный размер пакета 1200 (`-packet-size`, `-initial-packet-size`) | Размер первого QUIC-пакета; влияет на MTU пути, а не на формат сообщений | **Совместимо.** Формат wire не меняется; у Rust фактическое значение уже 1200 (дефолт `quinn` `initial_mtu`), у Go — теперь тоже 1200. Значение `InitialPacketSize` не передаётся пиру в протоколе | **Низкий.** Расходится только управление: у Rust нет флагов (H8), а PMTUD у Rust оставлен включённым (H9) — для обычной сессии безопасно, для туннеля бюджет датаграмм (E4) считается от размера исходного пакета, поэтому при появлении `-J` в Rust PMTUD придётся выключать так же, как в Go (`cmd/ssh3.go:216-220`) |
| W3 | Пакет версии Go теперь длиннее | В `Server`/`User-Agent` добавлено поле `compress=zstd,deflate,lz4` (`version.go:244-246`) | **Совместимо.** Разбор строки в Go терпим к неизвестным полям (`version.go:305-317` — поле `compress` разбирается, остальные пропускаются с debug-логом); Rust строку версии не разбирает вовсе | **Низкий.** Единственное наблюдаемое отличие — текст заголовка; сравнение строк версий целиком в interop-тестах нужно обновить |

Вывод: **ни одна из новых возможностей Go не ломает wire-совместимость с текущим Rust.** Обе — расширения, включаемые через явное объявление, а Rust их не объявляет. Ограничение — «канал сжатия» в Rust придётся вводить атомарно (декодер + capability + лимиты), иначе peer начнёт сжимать раньше, чем Rust научится разжимать.

---

## 4. План закрытия разрыва

Упорядочено по (a) риск для безопасности, (b) стоимость, (c) зависимостям. Столбец «Блокер» — ссылки на шаги этого плана, которые должны быть выполнены раньше.

### 4.0. Статус шагов на 2026-10-22 (проверено по коду Rust)

Часть эшелона 0 и эшелона 1 закрыта в крейтах Rust — шаги ниже перечислены как справочные, не как работа:

| Закрытый шаг | Реализация в Rust |
|--------------|-------------------|
| S1 — лимит SSH-строки | `ssh3-proto/src/wire.rs:33` (`MAX_SSH_STRING_LEN = 1<<24`), `ssh3-proto/src/wire.rs:243-255` |
| S2 — кламп `maxPacketSize` | `ssh3-core/src/channel.rs:49-65`, `ssh3-core/src/channel.rs:598-600` |
| S3 — политика `permit-open` / `permit-listen` | `ssh3-server/src/forwarding.rs:81-121`, `ssh3-server/src/reverse_forward.rs:313` |
| S4 — кап неавторизованных диалогов | `ssh3-server/src/runtime.rs:181-186`, `ssh3-server/src/config.rs:312` |
| S5 (наполовину) — lockout паролей | `ssh3-server/src/auth.rs:164-186` (константно-временное сравнение — **не** сделано, `ssh3-server/src/auth.rs:411`) |
| S7 — секретный URL-путь | `ssh3-server/src/runtime.rs:126`, `ssh3-server/src/runtime.rs:165-167` |
| Q1–Q6 — `-L`/`-D`/`-R`, `-t`/`-T`, `-o`/`-F`, `Match`/`Include` | `ssh3-client/src/forward.rs`, `ssh3-client/src/dynamic.rs`, `ssh3-client/src/reverse.rs`, `ssh3-client/src/lib.rs:240-259`, `ssh3-client/src/ssh_config.rs` |
| Q4 — коды `128+signum` | `ssh3-client/src/lib.rs:672`, `ssh3-client/src/main.rs:737-740` |
| Q9 — systemd-юнит + EnvironmentFile | `packaging/ssh3-rust-server.service`, `packaging/ssh3-rust-server.env` |
| T1 — `known_hosts` + `StrictHostKeyChecking` | `ssh3-client/src/known_hosts.rs`, `ssh3-client/src/strict_host_key.rs` |
| T3 — `-R` обратный форвардинг | `ssh3-client/src/reverse.rs`, `ssh3-server/src/reverse_forward.rs` |
| T8 — escape-последовательности | `ssh3-client/src/escape.rs` |
| S9 (наполовину) — supply chain | `Cargo.lock`: `quinn-proto 0.11.19`, `rustls 0.23.46` |

### Эшелон 0 — безопасность (блокирует всё остальное)

| № | Шаг | Что делать | Файлы | Критерий готовности | Чел.-дней | Блокер |
|---|-----|-----------|-------|---------------------|---------|--------|
| S1 | Лимит SSH-строки | Ввести кап длины peer-строки ≤ 16 MiB (`util.MaxSSHStringLen = 1<<24`) в `read_ssh_bytes` и в асинхронный путь разбора | `ssh3-proto/src/wire.rs:243-255` | Негативный тест: peer шлёт varint `1<<62` → `Err`, без аллокации; `cargo test -p ssh3-core -p ssh3-proto` зелёный | ~~1.5~~ закрыт | — |
| S2 | Кламп `maxPacketSize` | Кламп peer-значения сверху локальным и снизу `minPeerMaxPacketSize` (≥4096) — как `channel.go:184`/`channel.go:199` | `ssh3-core/src/channel.rs:49-65` | Тест: peer шлёт `maxPacketSize = 1<<40` → локально применяется ≤ локального и ≥ 4096 | ~~1.5~~ закрыт | S1 |
| S3 | Политика форвардинга `permit-open` / `permit-listen` | Перенести семантику `cmd/forward_policy.go` (шаблоны `*`, `!`-отрицания, `host:port`) в серверный слой; по умолчанию — **ограничение** (в отличие от Go, где пусто = unrestricted, — расхождение нужно зафиксировать) | `ssh3-server/src/forwarding.rs:81-121`, `ssh3-server/src/reverse_forward.rs:313` | Тест: клиент просит `direct-tcp` на `10.0.0.1:22` → `OpenFailure`; разрешённая цель — ок. Interop-сценарий Go↔Rust с `-permit-open` зелёный | ~~3~~ закрыт | — |
| S4 | Кап неавторизованных диалогов (MaxStartups-аналог) | Счётчик незавторизованных разговоров + `503` при превышении; снятие слота на выходе | `ssh3-server/src/runtime.rs:181-186`, `ssh3-server/src/config.rs:312` | Тест: N+1 параллельных CONNECT без авторизации → `503`; слот возвращается после завершения | ~~1.5~~ закрыт | — |
| S5 | Lockout паролей + константно-временное сравнение | Заменить `==` на `subtle`-эквивалент; счётчик неудач + `PasswordLockoutDuration` | `ssh3-server/src/auth.rs:411`, `ssh3-server/src/auth.rs:164-186`, `ssh3-server/src/config.rs` | Тест: N+1 неверный пароль → отказ на `PasswordLockoutDuration`; успешный вход сбрасывает счётчик | 1 | S4 |
| S6 | Root-gate | Запретить password-аутентификацию для `root` | `ssh3-server/src/auth.rs:202-205`, `ssh3-server/src/auth.rs:463-468` | Тест: `root` + пароль → `401`; `root` + pubkey → `200` | 0.5 | — |
| S7 | Секретный URL-путь | Проверять путь CONNECT против сконфигурированного `url_path`; иначе `404` | `ssh3-server/src/runtime.rs:126`, `ssh3-server/src/config.rs:309` | Тест: CONNECT на `/wrong` → `404`; на `/ssh3-term` → `200`. Interop с Go-сервером (у него путь `/ssh3-term`) зелёный | ~~1~~ закрыт | — |
| S8 | Кап неограниченных структур | Ограничить `dangling_datagram_queues` (peer-id) и добавить бюджет каналов на разговор | `ssh3-core/src/conversation.rs:363-397` | Тест: 10 000 датаграмм на неизвестный channel-id → память под потолком, FIFO-вытеснение | 2 | — |
| S9 | Обновление supply-chain зависимостей | `quinn-proto` ≥ 0.11.19, `rustls` ≥ 0.23.46 — сделано; осталось `webpki-roots`, `rand` и чистый `cargo audit` | `Cargo.toml`, `Cargo.lock` | `cargo audit` чист по advisory из `ROADMAP.md:185-196` | 1 | — |

**Итого эшелон 0 (осталось): ≈ 4,5 человеко-дня.**

### Эшелон 1 — дешёвые быстрые выигрыши (дешёвые, дают наибольший эффект)

| № | Шаг | Что делать | Файлы | Критерий готовности | Чел.-дней | Блокер |
|---|-----|-----------|-------|---------------------|---------|--------|
| Q1 | **CLI `-L` (TCP и `udp://`)** | Вывести существующие примитивы в CLI: разбор `[bind:]port:host:port` и `udp://`, локальный listener, pump канала → целевой адрес | `ssh3-client/src/main.rs:196`, `ssh3-client/src/forward.rs` | `ssh3-rust-client --forward-tcp 8080:example.org:80 host` форвардит TCP; `--forward-udp` — UDP; interop-сценарии Rust→Go и Go→Rust зелёные | ~~2~~ закрыт | — |
| Q2 | **CLI `-D` (SOCKS5)** | Локальный SOCKS5-сервер, разбор `CONNECT`, открытие `direct-tcp` на цель | `ssh3-client/src/dynamic.rs` | SOCKS5-клиент (напр. `curl --socks5`) проходит через прокси к локальному echo-серверу | ~~3~~ закрыт | Q1 |
| Q3 | **Флаги `-t` / `-T` / `-o RequestTTY=`** | Флаг выбора PTY-политики + `RequestTTY` в конфиге | `ssh3-client/src/main.rs:146-155`, `ssh3-client/src/lib.rs:240-259` | `--no-pty` даёт сессию без PTY при tty-stdin; `--force-pty` — PTY без tty | ~~1~~ закрыт | — |
| Q4 | **Коды возврата `128+signum`** | Разобрать `exit-signal` и вернуть `128+signum` | `ssh3-client/src/lib.rs:672`, `ssh3-client/src/main.rs:737-740` | Тест: сервер убивает процесс по TERM → клиент возвращает 143 | ~~1~~ закрыт | — |
| Q5 | **`-F` + `-o Key=Value`** | Минимальный парсер ssh_config (`Host`, `User`, `Port`, `IdentityFile`, `StrictHostKeyChecking`, `ForwardAgent`, `ServerAliveInterval`) + `-o` с теми же ключами; позже — `Match`/`Include` (Q6) | `ssh3-client/src/ssh_config.rs`, `ssh3-client/src/main.rs` | `ssh3-rust-client -F ./cfg -o Port=4433 host` уважает файл и `-o`; приоритет `-o` > файл > дефолт | ~~3~~ закрыт (кроме `Port`/`IdentityFile` — см. G10, G11) | — |
| Q6 | **ssh_config `Match` и `Include`** | Перенести семантику из `client/config/matchcfg/matchcfg.go` | `ssh3-client/src/ssh_config.rs` | Вложенный `Include` + `Match host` работают; глубина Include ограничена 16 | ~~3~~ закрыт | Q5 |
| Q7 | **Версия/баннер и `-v`/`-q`** | Единый `SSH3_VERSION_STRING` — сделано; остались уровни логирования | `ssh3-h3/src/lib.rs:19`, `ssh3-client/src/main.rs` | `--version` печатает `SSH 3.0 alpha-00 ... 0.1.x`; `-v` включает подробный лог | 1.5 | — |
| Q8 | **Graceful shutdown сервера** | Ловить SIGTERM/SIGINT, переставать принимать, дренировать N секунд | `ssh3-server/src/runtime.rs:42-58`, `ssh3-server/src/main.rs` | SIGTERM → новые CONNECT отклоняются, активные сессии завершаются в течение окна; systemd-тест | 2 | — |
| Q9 | **Системд-юнит + EnvironmentFile** | Перенести `packaging/ssh3-server.service` и `packaging/ssh3-server.env` (с новыми именами бинарников) | `packaging/ssh3-rust-server.service`, `packaging/ssh3-rust-server.env` | `systemd-analyze verify` проходит; сервис стартует с `EnvironmentFile` | ~~1~~ закрыт | Q8 |

**Итого эшелон 1 (осталось): ≈ 3,5 человеко-дня.**

### Эшелон 2 — средние по стоимости

| № | Шаг | Что делать | Файлы | Критерий готовности | Чел.-дней | Блокер |
|---|-----|-----------|-------|---------------------|---------|--------|
| T1 | `known_hosts` + `StrictHostKeyChecking` | Порт `known_hosts.go` (парсинг, проверка сертификата, дописывание) и политику `yes/accept-new/no/ask` | `ssh3-client/src/known_hosts.rs`, `ssh3-client/src/strict_host_key.rs` | `ask` без терминала → отказ; `accept-new` → запись в known_hosts; `yes` → отказ при несовпадении | ~~5~~ закрыт | Q5 |
| T2 | SSHFP + `VerifyHostKeyDNS` | DNS-резолвер SSHFP (RFC 4255), сверка с хост-ключом, политика `yes/no/ask` + список алгоритмов | новый `ssh3-client/src/sshfp.rs`, `ssh3-client/src/main.rs` | Тест с фейковым DNS-ответом: совпадение/несовпадение/отсутствие записи | 4 | T1 |
| T3 | `-R` обратный форвардинг | Клиент: запрос `forward-port`; сервер: приём, биндинг, политика `permit-listen` и `gateway-ports` | `ssh3-client/src/reverse.rs`, `ssh3-server/src/reverse_forward.rs`, `ssh3-proto/src/message.rs:347` (`ForwardPort`) | Reverse-туннель: клиент слушает на сервере, трафик идёт клиенту; `permit-listen` блокирует недопустимые bind | ~~8~~ закрыт | S3, J2 |
| T4 | `-s` подсистема (клиент) | Клиент: запрос `subsystem` (серверная обработка есть — L7 †) | `ssh3-client/src/lib.rs:264-270`, `ssh3-proto/src/message.rs:337` | `subsystem` доходит до сервера и возвращает вывод | 2 | — |
| T5 | Передача файлов (клиент SFTP) | Серверная подсистема SFTP — сделана †; остался SFTP-клиент и режим `-transfer` | новый `ssh3-client/src/sftp.rs`, `ssh3-client/src/main.rs` | Загрузка/выгрузка файла; рекурсия по каталогу; докачка | 6 | T4, X7 (эшелон 3) |
| T6 | Лимиты и таймауты сервера | Таймауты — сделано (`ssh3-server/src/tls.rs:22-33`); осталось `-max-connections`, `-max-channels-per-conversation`, `-max-incoming-streams` | `ssh3-server/src/config.rs`, `ssh3-server/src/runtime.rs` | Каждый лимит имеет тест: превышение → отказ/закрытие | 2 | S8 |
| T7 | Серверные TLS-сертификаты | `-cert`/`-key`/`-c`/`-h` (собственный сертификат) | `ssh3-server/src/tls.rs`, `ssh3-server/src/main.rs`, `ssh3-server/src/config.rs` | Сервер с собственным PEM-сертификатом принимает клиента с `--ca-cert` | 3 | — |
| T8 | Escape-последовательности | Фильтр `~.`/`~^Z`/`~~` с настраиваемым `EscapeChar` | `ssh3-client/src/escape.rs` | `~.` закрывает сессию; `~^Z` suspend — на Unix | ~~4~~ закрыт | Q3 |

**Итого эшелон 2 (осталось): ≈ 17 человеко-дней.**

### Эшелон 3 — дорогие

| № | Шаг | Что делать | Файлы | Критерий готовности | Чел.-дней | Блокер |
|---|-----|-----------|-------|---------------------|---------|--------|
| X1 | ACME / публичные сертификаты | Интеграция certmagic-эквивалента (Let's Encrypt) для автопролнения сертификата | `ssh3-server/src/tls.rs`, `ssh3-server/src/config.rs`, новый `ssh3-server/src/acme.rs` | Сервер получает валидный публичный сертификат и обновляет его | 10 | T7 |
| X2 | Control master | Клиентский unix-сокет, фрейминг `client/cm`, режимы `yes/auto`, `-control-persist`, операции `-O check/stop/exit` | новый `ssh3-client/src/control.rs`, `ssh3-client/src/cm.rs` | Два вызова клиента переиспользуют одно QUIC-соединение; `-O check` отвечает статусом | 12 | Q5, Q1, T1 |
| X3 | Proxy jump | UDP/датаграммный туннель через jump-хост, цепочка хопов, `-J`/`-proxy-jump`/ssh_config + бюджет датаграмм (E4) | `ssh3-client/src/lib.rs`, `ssh3-client/src/main.rs` | `ssh3-rust-client -J jump target` работает через реальный jump-сервер | 10 | Q5, T1, H8, H9 |
| X4 | Изоляция путей SFTP (`-sftp-jail`) | chroot-модель (дочерний процесс + uid/gid) либо лексический jail | `ssh3-server/src/sftp.rs`, `ssh3-server/src/config.rs` | SFTP-клиент не может выйти за пределы jail; тест на `../../etc/passwd` | ~~5~~ закрыт † | T5 |
| X5 | Debian-упаковка и man-страницы | `.deb` — сделано † (`packaging/build-deb.sh`); остались man-страницы | `ssh3-rust/packaging/` | `dpkg-deb --build` собирает пакет; `lintian` без ошибок; `man` открывается | 2 | Q9, Q7 |
| X6 | X11 forwarding | Полная реализация X11-канала на клиенте и сервере | `ssh3-server/src/session.rs`, `ssh3-client/src/lib.rs`, `ssh3-proto/src/message.rs:330-331` | X11-приложение стартует через туннель | 6 | T4 |
| X7 | Полный аудит и wire- golden-векторы | Прогон `FROZEN.md`-процедуры; golden-векторы wire-формата из `wire_vectors_test.go` (механизм `scripts/refresh-go-vectors.sh` уже есть); fuzz-таргеты парсера | новый `ssh3-rust/tests/`, новый `ssh3-rust/fuzz/` | Все interop-сценарии зелёные на закреплённом теге Go; fuzz без падений | 3 | — |
| **X8** | **Сжатие тела канала (B8)** | Объявить `compress=` в строке версии (N1); принять кадр 192 в `ssh3-proto`/`ssh3-core` (N2); кодеки deflate/lz4/zstd с байт-в-байт совпадением с Go (N3); cutoff (N4), лимит бомбы 16 MiB (N5), сжатие на сервере (N6). **Порядок обязателен**: capability объявляется только вместе с готовым декодером | `ssh3-h3/src/lib.rs:19`, `ssh3-proto/src/message.rs`, `ssh3-core/src/channel.rs:856-890`, новый `ssh3-core/src/compress.rs` | Interop: Go-клиент ↔ Rust-сервер и Rust-клиент ↔ Go-сервер сжаты в обе стороны; golden-векторы кадра 192 совпадают с `message/compressed_data_test.go` Go; пир без `compress=` получает открытые кадры | 12 | X7, N3 |

**Итого эшелон 3 (осталось): ≈ 55 человеко-дней.**

### Сводка по плану

| № | Эшелон | Чел.-дней (осталось) | Что даёт |
|---|--------|----------------------|----------|
| 1 | Эшелон 0 — безопасность | 4,5 | Дожимает root-gate, константно-временное сравнение, кап структур и `cargo audit` |
| 2 | Эшелон 1 — дешёвые выигрыши | 3,5 | Уровни логирования, graceful shutdown |
| 3 | Эшелон 2 — средние | 17 | SSHFP, `-s` подсистема (клиент), SFTP-клиент, лимиты соединений, свои сертификаты |
| 4 | Эшелон 3 — дорогие | 55 | ACME, control master, proxy jump (+ бюджет датаграмм), man-страницы, аудит, **сжатие тела канала** |
| | **Итого** | **≈ 80** | Из них эшелоны 0–2 (до полезного «второго стека» без ACME/control master/proxy jump/сжатия) — **≈ 25** |

---

## 5. Блокирующие зависимости между шагами

### 5.1. Что можно делать параллельно (независимые группы)

| № | Группа | Шаги | Почему независимы |
|---|--------|------|-------------------|
| P1 | Wire-ядро | S8, X8 (сжатие) | Работают в `ssh3-proto`/`ssh3-core`; не трогают CLI и серверную политику. Сжатие требует готовых golden-векторов (X7) |
| P2 | Server-policy | S5, S6 | Работают в `ssh3-server`; каждый — свой участок `auth.rs` |
| P3 | CLI-мелочи | Q7, T2 | Независимы от форвардинга и конфигурации |
| P4 | Client-security | T4, T5, T7 | T5 зависит от T4 и T7; не зависит от control master |
| P5 | Supply chain | S9 | Изолирован: только `Cargo.toml`/`Cargo.lock` |
| P6 | Упаковка | Q9, X5 | Q9 → X5; зависит от Q7 (баннер) |
| P7 | Транспорт | H8, H9, E4 | Флаги размера пакета и отключение PMTUD; E4 зависит от H8/H9 и от X3 |

### 5.2. Жёсткие блокеры (пошаговая цепочка)

```
S4 (кап неавторизованных диалогов)  ── закрыт
  └─> S5 (lockout + const-time)      [lockout закрыт, осталось const-time]

S6 (root-gate)  ── независим, можно первым

S8 (кап неограниченных структур)
  └─> T6 (лимиты соединений/каналов/потоков)

S9 (supply chain)  ── независим, можно первым

Q7 (версия/баннер)
  └─> X5 (debian-упаковка + man)

Q8 (graceful shutdown) ──> Q9 (systemd) ──> X5 (debian)

T4 (-s подсистема, клиент)
  └─> T5 (SFTP-клиент / передача файлов)

T7 (свои сертификаты) ──> X1 (ACME)

X7 (аудит + golden-векторы) ──> X8 (сжатие)   [сжатие проверяется golden-векторами]
X3 (proxy jump) ──> E4 (бюджет датаграмм)
```

### 5.3. Критический путь (минимальная последовательность до «безопасно и полезно»)

```
S5 (const-time) → S6 (root-gate) → S8 (кап структур) → T6 (лимиты) → T2 (SSHFP) → Q7 → Q8 → Q9
```

≈ **9 человеко-дней** — даёт: константно-временное сравнение пароля, root-gate, кап структур и лимиты сервера, SSHFP, версию, graceful shutdown и systemd-юнит. Это и есть рекомендуемый «второй стек»-релиз (форвардинг, конфигурация, PTY, escape-последовательности, политики форвардинга и SFTP-сервер в Rust уже есть).

---

## 6. Что осталось непроверенным

1. **Динамика и нагрузка.** Все выводы — из статического чтения кода. Реальная производительность Rust-клиента/сервера (latency, throughput, поведение под нагрузкой) не измерялась; Go имеет готовый бенчмарк-стенд (`bench/`), Rust — нет.
2. **Состояние интеграционных тестов.** Interop-матрица из 22 сценариев заявлена в `ssh3-rust/README.md:152-183`, но фактический прогон в этой сессии не выполнялся (нет сборки Go-бинарников и toolchain-проверки). Утверждения «interop зелёный» в критериях готовности — это **целевые** критерии, а не наблюдённые результаты.
3. **Актуальность `ROADMAP.md`.** README/ROADMAP Rust ссылаются на строки `ssh3-server/src/lib.rs:344-393`, `:1718`, `ssh3-client/src/lib.rs:1406-1411` — после разбиения серверного монолита и выноса консоли в отдельный модуль эти номера **устарели**; реальные места — `ssh3-server/src/auth.rs:411` и `ssh3-client/src/lib.rs:1451`. Проверено по факту, в тексте документа использованы фактические строки.
4. **Полнота Go-поверхности.** Проверены `cmd/`, `client/`, `server_auth/`, `message/`, `compress/`, `util/`, `auth/`, `packaging/`, `version.go`. Не разбирались построчно `integration_tests/`, `bench/`, `internal/interop/`, `resources_manager.go`, `channel_rwc.go` — возможны редкие низкоуровневые возможности, не попавшие в таблицу.
5. **Плагинная подсистема Go.** `internal/plugins.go` и `auth/interface.go` задают точку расширения для внешних auth-плагинов; Rust эквивалента не имеет вовсе, и этот пробел в таблице не отражён отдельной строкой.
6. **Windows-специфика Rust.** Консоль клиента вынесена в платформенные модули (`ssh3-client/src/console.rs`, `ssh3-client/src/console/unix.rs`, `ssh3-client/src/console/windows.rs`, `ssh3-client/src/console/other.rs`) — на Windows PTY/resize/сигналы работают через слой Win32, но покрытие Windows в Rust не проверялось; Go имеет отдельные реализации (`client/escape_windows.go`, `client/signals_windows.go`, `client/winsize/winsize_windows.go`). Это расхождение не выделено строкой в таблице и требует отдельной оценки.
7. **Сжатие — побайтовая совместимость кодеков.** Совпадение байтов deflate/lz4/zstd с C-портом (`ssh3-c`, спецификация §15) и с Go проверено только по коду; golden-векторы Go (`message/compressed_data_test.go`) в этом прогоне не сверялись. Особое внимание — zstd-кадры < 256 байт (односегментная форма, всегда с размером) и lz4-блок (формат блока, не потока).
8. **Незакоммиченное состояние Rust.** Строки L7, L8, M3 и ссылки на `ssh3-client/src/console*` описывают рабочее дерево, а не коммит `108409b`; перед релизом их нужно зафиксировать и прогнать interop ещё раз.
9. **Замер трудозатрат.** Оценки в человеко-днях — экспертные, на основе прочитанного кода; они не проверены календарным прогоном и не учитывают время на CI/review/регрессии.

---

*Обновлено 2026-10-22. Источники: `C:\Git\project\ssh3` (Go, `ce072f4`) и `C:\Git\project\ssh3-rust` (Rust, `108409b` + рабочее дерево). Код не изменялся.*
