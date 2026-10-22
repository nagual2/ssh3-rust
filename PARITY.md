# PARITY — Go (`nagual2/ssh3-go`) vs Rust (`ssh3-rust`)

Сравнение функциональности двух реализаций протокола SSH3.

- **Эталон (Go):** `C:\Git\project\ssh3` — единственный поставляемый продукт (`ssh3`, `ssh3-server`).
- **Догоняющая (Rust):** `C:\Git\project\ssh3-rust` — крейты `ssh3-client`, `ssh3-server`, `ssh3-core`, `ssh3-proto`, `ssh3-quinn`, `ssh3-auth`, `ssh3-h3`.

Метод: сплошной статический разбор обеих кодовых баз (Go: `cmd/`, `client/`, `server_auth/`, `message/`, `util/`, `auth/`, `packaging/`, `version.go`; Rust: все 7 крейтов, 15 537 строк `src`). Каждое утверждение сопровождается ссылкой `путь:строка`. Если возможность не найдена — указано «не найдено». Wire-уровень (message types, framing) обеих реализаций совпадает — это подтверждено interop-матрицей из 22 сценариев (`ssh3-rust/README.md:152-183`); расхождения ниже относятся к **продуктовой поверхности** (CLI, политики, эксплуатация), а не к wire-формату.

Обозначения: **Сложность** — S (≤1 чел.-день), M (2-5), L (>5). **Go**/**Rust** — `да` / `нет` / `частично`.

---

## 1. Сводка

| № | Метрика | Значение |
|---|---------|----------|
| 1 | Всего строк возможностей в таблице паритета | **101** |
| 2 | Реализовано в Go | **100** |
| 3 | Реализовано в Rust | **25** (22 полностью + 3 частично) |
| 4 | Полное совпадение (обе стороны, поведение эквивалентно) | **18** |
| 5 | Расхождение по семантике при наличии в обеих | **6** (3 полных + 3 частичных) |
| 6 | **Пробелов** (в Go есть, в Rust нет) | **76** |
| 7 | Пробелов по безопасности (High/Critical) | **7** |
| 8 | Клиентских пробелов | **50** (+2 частичных) |
| 9 | Серверных пробелов | **26** (+1 частичный) |
| 10 | Только в Rust (нет аналога в Go) | **1** |
| 11 | Оценка закрытия разрыва | **≈ 73 человеко-дня** (эшелоны 0–2) или **≈ 124** (полный паритет) |

Контроль суммы: 18 (совпадение) + 3 (расхождение) + 3 (частично) + 76 (пробел) + 1 (только Rust) = **101**.

Разбивка по подсистемам:

| № | Подсистема | Строк | Совпадает | Расхождение | Частично | Пробел | Только Rust |
|---|-----------|-------|-----------|-------------|----------|--------|-------------|
| 1 | Клиент: аутентификация | 11 | 6 | 0 | 0 | 4 | 1 |
| 2 | Клиент: сессия / PTY / сигналы | 15 | 4 | 1 | 2 | 8 | 0 |
| 3 | Клиент: форвардинг | 8 | 0 | 1 | 0 | 7 | 0 |
| 4 | Клиент: control master | 5 | 0 | 0 | 0 | 5 | 0 |
| 5 | Клиент: proxy jump | 3 | 0 | 0 | 0 | 3 | 0 |
| 6 | Клиент: передача файлов | 6 | 0 | 0 | 0 | 6 | 0 |
| 7 | Клиент: конфигурация / `-o` / ssh_config | 12 | 0 | 0 | 0 | 12 | 0 |
| 8 | Клиент: прочие флаги и сервисы | 7 | 2 | 0 | 0 | 5 | 0 |
| 9 | Сервер: аутентификация и политики | 9 | 3 | 1 | 0 | 5 | 0 |
| 10 | Сервер: политики форвардинга | 4 | 0 | 0 | 0 | 4 | 0 |
| 11 | Сервер: лимиты и таймауты | 6 | 0 | 0 | 0 | 6 | 0 |
| 12 | Сервер: функциональность | 9 | 3 | 0 | 0 | 6 | 0 |
| 13 | Эксплуатация: упаковка, логи, exit-коды | 6 | 0 | 0 | 1 | 5 | 0 |
| | **Итого** | **101** | **18** | **3** | **3** | **76** | **1** |

---

## 2. Таблица паритета

### 2.1. Клиент — аутентификация

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| A1 | Аутентификация | Pubkey по приватному ключу (ed25519 / P-256 / RSA) | да | да | Go `cmd/ssh3.go:689` (`-i`), `auth/plugins/pubkey_authentication/client/privkey_auth.go:47` (`-privkey`); Rust `ssh3-client/src/main.rs:38` (`--identity`) | — | — |
| A2 | Аутентификация | Pubkey через SSH-agent (выбор ключа агента) | да | да | Go `auth/plugins/pubkey_authentication/client/pubkey_auth.go:41` (`-pubkey-for-agent`); Rust `ssh3-client/src/main.rs:41-51` (`--agent`, `--agent-key`), `ssh3-client/src/agent.rs` | — | — |
| A3 | Аутентификация | Password (HTTP Basic) | да | да | Go `cmd/ssh3.go:665` (`-use-password`), `auth/plugins/pubkey_authentication/client/privkey_auth.go:118`; Rust `ssh3-client/src/main.rs:59-76` (`--password`, `--password-file`) | — | — |
| A4 | Аутентификация | OIDC: интерактивный браузерный flow | да | да | Go `cmd/ssh3.go:671` (`-use-oidc`), `auth/oidc/openid_connect.go`; Rust `ssh3-client/src/main.rs:95-118`, `ssh3-client/src/lib.rs:918` | — | — |
| A5 | Аутентификация | OIDC: PKCE | да | да | Go `cmd/ssh3.go:692` (`-no-pkce`); Rust `ssh3-client/src/main.rs:120-121` (`--no-pkce`) | — | — |
| A6 | Аутентификация | OIDC: файл конфигурации IdP (`client_id`/`client_secret`) | да | нет | Go `cmd/ssh3.go:672` (`-oidc-config`); Rust — **не найдено** | S | A4 |
| A7 | Аутентификация | Bearer-токен из файла/argv (pre-computed) | нет | да | Go — CLI-флага нет, только внутренний `rawBearerTokenIdentity` (`client_auth.go:242`); Rust `ssh3-client/src/main.rs:78-92` (`--bearer-token`, `--bearer-token-file`) | — | — |
| A8 | Аутентификация | `known_hosts` (чтение/проверка/дописывание) | да | да | Go `known_hosts.go:18` (`Knows`), `known_hosts.go:91` (`ParseKnownHosts`), `known_hosts.go:128` (`AppendKnownHost`); Rust `ssh3-client/src/known_hosts.rs` (`KnownHosts::parse`, `append_known_host`, `certificate_fingerprint`), `ssh3-client/src/host_key.rs` (сверка presented-сертификата) | — | — |
| A9 | Аутентификация | `strict-host-key-checking` (yes / accept-new / no / ask) | да | да | Go `cmd/ssh3.go:667`, `strict_host_key.go:43` (`ParseStrictHostKeyChecking`), `strict_host_key.go:62` (`ResolveStrictHostKeyChecking`); Rust `ssh3-client/src/strict_host_key.rs` (`Ssh3StrictHostKeyChecking`, `resolve_strict_host_key_checking`, `decide_host_key`), `ssh3-client/src/main.rs` (`--strict-host-key-checking`, `-o StrictHostKeyChecking=`) | — | A8 |
| A10 | Аутентификация | SSHFP / `VerifyHostKeyDNS` | да | нет | Go `cmd/cli_flags.go:226` (`parseVerifyHostKeyDNSValue`), `sshfp.go:663` (`CheckSSHFP`), `sshfp.go:500` (`UDPSSHFPResolver.LookupSSHFP`); Rust — **не найдено** | L | A8, A9, DNS-резолвер |
| A11 | Аутентификация | Проброс SSH-agent на сервер (`-A` / `-forward-agent`) | да | да | Go `cmd/ssh3.go:679-680`; Rust `ssh3-client/src/main.rs:56-57` (`--forward-agent`), `ssh3-client/src/lib.rs:1420` (`spawn_agent_forwarder`) | — | — |

### 2.2. Клиент — сессия, PTY, сигналы

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| B1 | Сессия | Shell | да | да | Go `cmd/ssh3.go` (операнд без команды → shell), `client/client.go:556`; Rust `ssh3-client/src/main.rs:203-207`, `ssh3-client/src/lib.rs:485` | — | — |
| B2 | Сессия | Exec (удалённая команда) | да | да | Go `client/session.go:24` (`SessionSpec`); Rust `ssh3-client/src/lib.rs:489-494` | — | — |
| B3 | PTY | Автовыделение PTY при интерактивном stdin | да | да | Go `client/client.go:556` (RequestTTY-политика); Rust `ssh3-client/src/lib.rs:478-482`, `ssh3-client/src/lib.rs:564` (`detect_local_terminal`) | — | — |
| B4 | PTY | `-t` — принудительное выделение PTY без tty | да | нет | Go `cmd/ssh3.go:712`, `cmd/forced_pty.go`; Rust — **не найдено** | S | B3 |
| B5 | PTY | `-T` — запрет PTY | да | нет | Go `cmd/ssh3.go:713`; Rust — **не найдено** | S | B3 |
| B6 | PTY | `-o RequestTTY=auto\|no\|yes\|force` + ssh_config `RequestTTY` | да | нет | Go `cmd/cli_flags.go:291` (`parseRequestTTY`), `cmd/ssh3.go:831`; Rust — **не найдено** | S | B4, B5 |
| B7 | PTY | `-o Term=` / переменная `TERM` | да | частично | Go `cmd/cli_flags.go:310` (`parseTermType`), `cmd/ssh3.go:329-340` (`resolveTermType`); Rust `ssh3-client/src/lib.rs:574` — берёт только `TERM` из env, переопределения нет | S | — |
| B8 | PTY | Изменение размера окна (`window-change`) | да | да | Go `cmd/window_change.go`; Rust `ssh3-client/src/lib.rs:530` (`send_window_change_request`), `ssh3-client/src/lib.rs:617` (`spawn_resize_forwarder`) | — | — |
| B9 | Сигналы | Пересылка сигналов на удалённый процесс | да | да | Go `cmd/ssh3-server.go:55-74` (карта имён), `client/signals_unix.go`; Rust `ssh3-client/src/lib.rs:548` (`send_signal_request`), `ssh3-client/src/lib.rs:640` (`spawn_signal_forwarders`) | — | — |
| B10 | Сессия | `-s` — запрос подсистемы (в т.ч. `sftp`) | да | нет | Go `cmd/ssh3.go:714`, `cmd/cli_flags.go:146` (`parseSubsystemName`), `cmd/sftp_client.go:131` (`sftpChannelType`); Rust — **не найдено** (`Ssh3SessionRequest` = только `Shell`/`Exec`, `ssh3-client/src/lib.rs:113-117`) | M | F1 |
| B11 | Escape | Escape-последовательности (`~.`, `~^Z`, `~C`) | да | нет | Go `client/escape.go:28` (`EscapeConfig`), `client/escape.go:50` (`Feed`), `cmd/ssh3.go:1737-1754`; Rust — **не найдено** | M | B3 |
| B12 | Escape | `-o EscapeChar=` / ssh_config `EscapeChar` | да | нет | Go `cmd/cli_flags.go:346` (`parseEscapeChar`), `cmd/ssh3.go:822`, `cmd/ssh3.go:1362`; Rust — **не найдено** | S | B11 |
| B13 | Сессия | Код возврата удалённой команды (`exit-status`, `128+signum`) | да | частично | Go `cmd/exit_status.go:17` (`safeExitStatus`), `cmd/exit_status.go:51` (`exitCodeForExitSignal`), `cmd/exit_status.go:28-63` (карта `128+signum`); Rust `ssh3-client/src/main.rs:230` — возвращает код из `Ssh3CapturedSession.exit_status` (`ssh3-client/src/lib.rs:171`), но карты `128+signum` для `exit-signal` нет | S | — |
| B14 | Сессия | `-f` — уход в фон | да | нет | Go `cmd/ssh3.go:702`, `cmd/background.go:38` (`validateBackgroundMode`), `cmd/background.go:17` (`backgroundEnv`); Rust — **не найдено** | M | B12, A9 |
| B15 | Сессия | `-N` — не открывать сессию (только форвардинг) | да | нет | Go `cmd/ssh3.go:710`; Rust — **не найдено** | S | C1 |

### 2.3. Клиент — форвардинг

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| C1 | Форвардинг | `-L` прямой TCP-форвардинг (CLI) | да | нет | Go `cmd/ssh3.go:696`, `cmd/ssh2_parity.go:67` (`parseLocalForwardSpec`), `cmd/ssh3.go:1648`; Rust — **не найдено** в CLI (примитив есть: `ssh3-quinn/src/channel.rs:418` `open_tcp_forwarding_channel`, `ssh3-core/src/conversation.rs:237`) | S | — |
| C2 | Форвардинг | `-L udp://` прямой UDP-форвардинг (CLI) | да | нет | Go `cmd/ssh3.go:696`, `cmd/ssh2_parity.go:208` (`localListenUDPAddr`); Rust — **не найдено** в CLI (примитив: `ssh3-quinn/src/channel.rs:397` `open_udp_forwarding_channel`, `ssh3-core/src/conversation.rs:197`) | S | C1 |
| C3 | Форвардинг | `-D` — SOCKS5 / динамический форвардинг | да | да | Go `cmd/ssh3.go:698`, `cmd/cli_flags.go:85` (`parseDynamicForwardSpec`), `cmd/dynamic_forward.go`, `cmd/dynamic_forward_server.go`; Rust `ssh3-client/src/dynamic.rs` (`parse_dynamic_forward_spec`, `serve_socks5_connection`), `ssh3-client/src/forwarding_wire.rs` (кодеки `dynamic-forward`/`dynamic-forward-tcp`), `ssh3-client/src/lib.rs` (`start_dynamic_forwards`), `ssh3-server/src/dynamic_forward.rs` | — | C1 |
| C4 | Форвардинг | `-R` — обратный форвардинг | да | да | Go `cmd/ssh3.go:700`, `cmd/reverse_forward.go`, `cmd/reverse_forward_server.go`; Rust `ssh3-client/src/reverse.rs` (`parse_reverse_forward_spec`, `request_reverse_forward`, `bridge_forwarded_tcp`), `ssh3-client/src/incoming.rs` (диспетчер серверных каналов, авторизация цели), `ssh3-client/src/forwarding_wire.rs`, `ssh3-server/src/reverse_forward.rs` | — | J2, J3 |
| C5 | Форвардинг | `-forward-tcp` / `-forward-udp` (legacy-алиасы) | да | нет | Go `cmd/ssh3.go:708-709`; Rust — **не найдено** | S | C1, C2 |
| C6 | Форвардинг | `-o LocalForward=` / `-o RemoteForward=` / `-o DynamicForward=` | да | нет | Go `cmd/ssh3.go:870`, `cmd/ssh3.go:876`, `cmd/ssh3.go:884`; Rust — **не найдено** | S | C1, C3, C4 |
| C7 | Форвардинг | Серверный приём форвардинга (TCP/UDP) | да | да | Go `cmd/ssh3-server.go:1385` (маршрутизация каналов), `message/dynamic_forward.go`; Rust `ssh3-server/src/forwarding.rs:84` (`handle_tcp_forwarding`), `ssh3-server/src/forwarding.rs:24` (`handle_udp_forwarding`) | — | — |
| C8 | Форвардинг | Безопасная семантика (политика целей) | да | нет | Go `cmd/forward_policy.go:52` (`parsePermitOpen`), `cmd/ssh3-server.go:1038`; Rust `ssh3-server/src/forwarding.rs:89` — дизелит **любой** адрес, запрошенный пиром | M | J1 |

### 2.4. Клиент — control master

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| D1 | Control master | `-M` / `-control-master=no\|yes\|auto` | да | нет | Go `cmd/ssh3.go:684`, `cmd/ssh3.go:687`, `cmd/controlmaster.go`; Rust — **не найдено** | L | A9, C1 |
| D2 | Control master | `-S` / `-control-path` (unix-сокет) | да | нет | Go `cmd/ssh3.go:685`, `cmd/ssh3.go:688`, `client/control.go:109`; Rust — **не найдено** | M | D1 |
| D3 | Control master | `-control-persist=no\|yes\|N` | да | нет | Go `cmd/ssh3.go:686`, `cmd/ssh3.go:908`; Rust — **не найдено** | M | D1 |
| D4 | Control master | `-O check\|stop\|exit` | да | нет | Go `cmd/ssh3.go:683`, `cmd/cli_flags.go:180` (`validateControlOperation`), `client/control.go:28-31` (`ControlOpCheck/Stop/Exit`), `client/control.go:68` (`RunControlOp`); Rust — **не найдено** | M | D2 |
| D5 | Control master | Протокол кадров control-сокета (`client/cm`) | да | нет | Go `client/cm/messages.go`, `client/cm/protocol.go`, `client/cm/framing.go`; Rust — **не найдено** | M | D2 |

### 2.5. Клиент — proxy jump

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| E1 | Proxy jump | `-J host[,host...]` (цепочка хопов) | да | нет | Go `cmd/ssh3.go:694`, `cmd/ssh3.go:1515` (`parseProxyJumpChain`), `cmd/ssh3.go:1605`; Rust — **не найдено** | L | C2 |
| E2 | Proxy jump | `-proxy-jump` (deprecated-алиас) | да | нет | Go `cmd/ssh3.go:693`, `cmd/ssh3.go:968`; Rust — **не найдено** | S | E1 |
| E3 | Proxy jump | ssh_config `ProxyJump` / `UDPProxyJump` | да | нет | Go `cmd/ssh3.go:1365-1368`, `cmd/ssh3.go:890`; Rust — **не найдено** | M | E1, G4 |

### 2.6. Клиент — передача файлов

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| F1 | Передача файлов | `-transfer SRC DST` (upload/download) | да | нет | Go `cmd/ssh3.go:701`, `cmd/sftp_client.go:135` (`runFileTransfer`), `cmd/sftp_client.go:41` (`isRemoteTransferSpec`); Rust — **не найдено** | L | B10, F5 |
| F2 | Передача файлов | `-r` — рекурсивная передача каталогов | да | нет | Go `cmd/ssh3.go:705`, `cmd/sftp_client.go:195` (`uploadDir`), `cmd/sftp_client.go:269` (`downloadDir`); Rust — **не найдено** | M | F1 |
| F3 | Передача файлов | `-continue` — докачка прерванного transfer | да | нет | Go `cmd/ssh3.go:706`, `cmd/sftp_client.go:513` (`hashResumePrefix`); Rust — **не найдено** | M | F1 |
| F4 | Передача файлов | `-checksum` — проверка SHA-256 | да | нет | Go `cmd/ssh3.go:707`, `cmd/sftp_client.go:425` (`verifyRemoteChecksum`); Rust — **не найдено** | M | F1 |
| F5 | Передача файлов | `-P` (порт) и `-U` (URL path) для операнда `user@host:path` | да | нет | Go `cmd/ssh3.go:703-704`, `cmd/sftp_client.go:67` (`parseRemoteTransferSpec`); Rust — **не найдено** | S | F1 |
| F6 | Передача файлов | Интерактивный SFTP-клиент (`-s sftp`) | да | нет | Go `cmd/ssh3.go:714`, `cmd/sftp_client.go:135`; Rust — **не найдено** | M | F1, B10 |

### 2.7. Конфигурация, `-o`, ssh_config

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| G1 | Конфигурация | `-F path` — альтернативный ssh_config | да | нет | Go `cmd/ssh3.go:711`, `cmd/cli_flags.go:169` (`resolveConfigPath`); Rust — **не найдено** | S | G3 |
| G2 | Конфигурация | `-o Key=Value` (повторяемый) | да | нет | Go `cmd/ssh3.go:670`, `cmd/ssh3.go:811-927` (диспетчер по 13 ключам); Rust — **не найдено** | M | G3 |
| G3 | Конфигурация | ssh_config: секции `Host` | да | нет | Go `client/config/matchcfg/matchcfg.go:294` (`parseSections`), `client/config/matchcfg/matchcfg.go:123`; Rust — **не найдено** | M | — |
| G4 | Конфигурация | ssh_config: секции `Match` (all/final/canonical/host/originalhost/user) | да | нет | Go `client/config/matchcfg/matchcfg.go:257` (`matchSection`), `client/config/matchcfg/matchcfg.go:534` (`parseMatchCriteria`); Rust — **не найдено** | L | G3 |
| G5 | Конфигурация | ssh_config: `Include` (рекурсия, glob, `~/.ssh`) | да | нет | Go `client/config/matchcfg/matchcfg.go:342` (`expandIncludes`), `client/config/matchcfg/matchcfg.go:120` (`maxIncludeDepth = 16`), `client/config/matchcfg/matchcfg.go:447` (`globInclude`); Rust — **не найдено** | M | G3 |
| G6 | Конфигурация | ssh_config: `ServerAliveInterval` | да | нет | Go `cmd/ssh3.go:1332`; Rust — **не найдено** | S | G3 |
| G7 | Конфигурация | ssh_config: `ForwardAgent` | да | нет | Go `cmd/ssh3.go:1338`; Rust — **не найдено** | S | G3, A11 |
| G8 | Конфигурация | ssh_config: `EscapeChar` | да | нет | Go `cmd/ssh3.go:1362`; Rust — **не найдено** | S | G3, B12 |
| G9 | Конфигурация | ssh_config: `StrictHostKeyChecking` | да | да | Go `strict_host_key.go:62` (`ResolveStrictHostKeyChecking`); Rust `ssh3-client/src/ssh_config.rs` (`SshConfig::get`), `ssh3-client/src/main.rs` (`--ssh-config`) — читается только этот ключ | — | G3, A9 |
| G10 | Конфигурация | ssh_config: `User`, `Port` | да | нет | Go `cmd/ssh3.go:855` (`Port`), `cmd/ssh3.go:863` (`User`); Rust — **не найдено** (только `--user` CLI) | S | G3 |
| G11 | Конфигурация | ssh_config: `IdentityFile` | да | нет | Go `cmd/ssh3.go:931` (маршрутизация по ключу), `auth/plugins/pubkey_authentication/client/privkey_auth.go:57`; Rust — **не найдено** | S | G3, A1 |
| G12 | Конфигурация | Переменные окружения `SSH3_*` (серверная политика) | да | нет | Go `cmd/ssh3-server.go:992-1082` (`SSH3_ENABLE_PASSWORD_LOGIN`, `SSH3_GATEWAY_PORTS`, `SSH3_MAX_*`, `SSH3_PERMIT_OPEN`, `SSH3_PERMIT_LISTEN`, `SSH3_SHUTDOWN_DRAIN`), `packaging/ssh3-server.env`; Rust — **не найдено** | M | — |

### 2.8. Клиент — прочие флаги и сервисы

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| H1 | Прочее | `-v` / `-q` — уровни логирования | да | нет | Go `cmd/ssh3.go:673-674`, `cmd/ssh3.go:1064-1071` (zerolog); Rust — **не найдено** (только `eprintln!` в `ssh3-client/src/main.rs:232`) | S | — |
| H2 | Прочее | `-keylog` — файл ключей TLS | да | нет | Go `cmd/ssh3.go:664`; Rust — **не найдено** | S | — |
| H3 | Прочее | `-4` / `-6` — только IPv4 / IPv6 | да | нет | Go `cmd/ssh3.go:715-716`, `cmd/ssh3.go:759` (взаимная исключительность); Rust — **не найдено** | S | — |
| H4 | Прочее | `-p` — порт сервера | да | нет | Go `cmd/ssh3.go:690`; Rust — **не найдено** (порт только в URL) | S | — |
| H5 | Прочее | `-insecure` — не проверять сертификат | да | да | Go `cmd/ssh3.go:666`; Rust `ssh3-client/src/main.rs:131-132` | — | — |
| H6 | Прочее | `-version` / `-V` | да | да | Go `cmd/ssh3.go:676-677`; Rust `ssh3-client/src/main.rs:12` (`version` в clap) | — | — |
| H7 | Прочее | X11 forwarding | да (серверная заглушка) | нет | Go `cmd/ssh3-server.go:564` (`newX11Req`), `cmd/ssh3-server.go:1497`, `client/session_pump.go:156` («not implemented» на клиенте); Rust — протокольный тип есть (`ssh3-proto/src/message.rs:331`), обработчика нет | M | — |

### 2.9. Сервер — аутентификация и политики

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| I1 | Сервер: аутентификация | Pubkey по authorized-файлам | да | да | Go `server_auth/authorized_identities.go`, `server_auth/auth.go`; Rust `ssh3-server/src/auth.rs:280` (`authorize_request`), `ssh3-server/src/auth.rs:123` (пути по умолчанию) | — | — |
| I2 | Сервер: аутентификация | Password (crypt/shadow) | да | да | Go `util/unix_util/linux_user.go:109` (`ComparePasswordWithHashedPassword`), `util/unix_util/user.go:123`; Rust `ssh3-server/src/auth.rs:193` (`default_password_verifier`) | — | — |
| I3 | Сервер: аутентификация | OIDC identity token | да | да | Go `server_auth/auth.go`; Rust `ssh3-server/src/auth.rs:319-327` (`verify_oidc_identity_token`) | — | — |
| I4 | Сервер: аутентификация | Включение/выключение password-логина | да | да | Go `cmd/ssh3-server.go:992` (`-enable-password-login`); Rust `ssh3-server/src/main.rs:27-28`, `ssh3-server/src/auth.rs:149` (`should_authenticate`) | — | — |
| I5 | Сервер: аутентификация | Root-gate (root не входит по паролю) | да | нет | Go `server_auth/root_gate.go:13` (`PasswordLoginRefused`); Rust — **не найдено** | S | I2 |
| I6 | Сервер: DoS-guard | Кап неавторизованных диалогов (аналог MaxStartups) | да | нет | Go `server_auth/dos_guard.go:26` (`MaxUnauthenticatedConversations = 100`), `server_auth/dos_guard.go:44` (`TryAcquireUnauthenticatedConversation`), `cmd/ssh3-server.go:1011`; Rust — **не найдено** | S | — |
| I7 | Сервер: DoS-guard | Lockout после N неудачных паролей | да | нет | Go `server_auth/dos_guard.go:30` (`MaxPasswordAuthFailures = 10`), `server_auth/dos_guard.go:33` (`PasswordLockoutDuration = 60s`), `cmd/ssh3-server.go:1016`, `cmd/ssh3-server.go:1021`; Rust — **не найдено** | M | I2 |
| I8 | Сервер: аутентификация | Константно-временное сравнение хэша пароля | да | нет | Go `util/unix_util/linux_user.go:109` — сравнение через `subtle`; Rust `ssh3-server/src/auth.rs:246` — `==` (неконстантно) | S | I2 |
| I9 | Сервер: аутентификация | Константно-временное сравнение SSHFP | да | нет | Go `sshfp.go:194` (`subtleEqual`); Rust — **не найдено** | S | A10 |

### 2.10. Сервер — политики форвардинга

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| J1 | Сервер: форвардинг | `-permit-open` (список допустимых целей, `*`, `!`) | да | нет | Go `cmd/forward_policy.go:52` (`parsePermitOpen`), `cmd/ssh3-server.go:1038`; Rust — **не найдено** | M | — |
| J2 | Сервер: форвардинг | `-permit-listen` (допустимые bind-адреса для `-R`) | да | нет | Go `cmd/forward_policy.go` (второй набор записей), `cmd/ssh3-server.go:1042`; Rust — **не найдено** | M | — |
| J3 | Сервер: форвардинг | `-gateway-ports` (no / clientspecified / yes) | да | нет | Go `cmd/ssh3-server.go:1001`; Rust — **не найдено** | M | C4 |
| J4 | Сервер: форвардинг | `-max-reverse-forwards` (на пользователя) | да | нет | Go `cmd/ssh3-server.go:1006`; Rust — **не найдено** | S | C4 |

### 2.11. Сервер — лимиты и таймауты

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| K1 | Сервер: лимиты | `-max-channels-per-conversation` | да | нет | Go `cmd/ssh3-server.go:1047`, `cmd/ssh3-server.go:1340` (`newBudget`), `cmd/channel_budget.go`; Rust — **не найдено** | S | — |
| K2 | Сервер: лимиты | `-max-connections` | да | нет | Go `cmd/ssh3-server.go:1057`, `cmd/ssh3-server.go:1581`; Rust — **не найдено** (`ssh3-server/src/runtime.rs:38` — бесконечный цикл приёма) | S | — |
| K3 | Сервер: лимиты | `-max-incoming-streams` / `-max-incoming-uni-streams` | да | нет | Go `cmd/ssh3-server.go:1077`, `cmd/ssh3-server.go:1082`; Rust — **не найдено** | S | — |
| K4 | Сервер: таймауты | `-max-idle-timeout` (QUIC idle) | да | нет | Go `cmd/ssh3-server.go:1067`; Rust — **не найдено** (`ssh3-quinn/src/config.rs` — дефолты quinn) | S | — |
| K5 | Сервер: таймауты | `-handshake-idle-timeout` | да | нет | Go `cmd/ssh3-server.go:1072`; Rust — **не найдено** | S | — |
| K6 | Сервер: лимиты | Клампы SSH-строки и `maxPacketSize` | да | нет | Go `util/wire.go:212` (`MaxSSHStringLen = 1<<24`), `util/wire.go:219`, `channel.go:178` (`clampPeerMaxPacketSize`), `channel.go:193` (`clampLocalMaxPacketSize`); Rust `ssh3-proto/src/wire.rs:216-222` (`read_ssh_bytes` — без лимита), `ssh3-core/src/channel.rs:536` (`parse_message`), `ssh3-core/src/channel.rs:451` (`confirm_channel` — значение пира берётся как есть) | M | — |

### 2.12. Сервер — функциональность

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| L1 | Сервер | Секретный URL-путь (`-url-path`) | да | нет | Go `cmd/ssh3-server.go:962`, `cmd/ssh3-server.go:1543` (`mux.HandleFunc(*urlPath, handler)`); Rust `ssh3-server/src/runtime.rs:106` (`is_ssh3_connect`) — путь **не проверяется** | S | — |
| L2 | Сервер | Автогенерация self-signed сертификата | да | да | Go `cmd/ssh3-server.go:966` (`-generate-selfsigned-cert`), `generate_openssl_selfsigned_certificate.sh`; Rust `ssh3-server/src/tls.rs`, `ssh3-server/src/main.rs:85` (`run_with_self_signed`) | — | — |
| L3 | Сервер | Публичный сертификат (ACME / Let's Encrypt) | да | нет | Go `cmd/ssh3-server.go:976` (`-generate-public-cert`), `cmd/ssh3-server.go:1277` (`certmagic.TLS`); Rust — **не найдено** | L | — |
| L4 | Сервер | `-cert` / `-key` / `-c` / `-h` — свои сертификаты | да | нет | Go `cmd/ssh3-server.go:968-973`; Rust — **не найдено** (только self-signed) | M | L3 |
| L5 | Сервер | PTY-сессии | да | да | Go `cmd/ssh3-server.go` (`pty-req`), `cmd/ssh3.go` (клиент); Rust `ssh3-server/src/session.rs:372`, `ssh3-server/src/pty.rs` | — | — |
| L6 | Сервер | Смена размера окна / сигналы на сервере | да | да | Go `cmd/ssh3-server.go:1497`; Rust `ssh3-server/src/session.rs:453` (`WindowChange`), `ssh3-server/src/session.rs:440` (`Signal`) | — | — |
| L7 | Сервер | Подсистема SFTP | да | нет | Go `cmd/ssh3-server.go:1385` (`serveSFTPSubsystem`), `cmd/ssh3-server.go:721` (`newSubsystemReq`), `cmd/sftp_subsystem.go`; Rust — **не найдено** (`ssh3-server/src/session.rs:369-465` — нет ветки `Subsystem`) | L | F1 |
| L8 | Сервер | Изоляция путей SFTP (`-sftp-jail`: chroot / lexical) | да | нет | Go `cmd/ssh3-server.go:1029`, `cmd/ssh3-server.go:1143`, `cmd/internal_sftp.go`; Rust — **не найдено** | M | L7 |
| L9 | Сервер | Graceful shutdown (SIGTERM → drain) | да | нет | Go `cmd/ssh3-server.go:1559-1633`, `cmd/ssh3-server.go:1641` (`shutdownDrainPeriod`), `packaging/ssh3-server.env` (`SSH3_SHUTDOWN_DRAIN`); Rust `ssh3-server/src/runtime.rs:33-58` — остановки по сигналу нет | M | — |

### 2.13. Эксплуатация

| № | Подсистема | Возможность | Go | Rust | Файлы (путь:строка) | Сложность | Зависимости |
|---|-----------|-------------|----|------|----------------------|-----------|-------------|
| M1 | Эксплуатация | systemd-юнит | да | нет | Go `packaging/ssh3-server.service`; Rust — **не найдено** | S | — |
| M2 | Эксплуатация | systemd EnvironmentFile | да | нет | Go `packaging/ssh3-server.env`; Rust — **не найдено** | S | G12 |
| M3 | Эксплуатация | Debian-упаковка (`.deb`) | да | нет | Go `packaging/debian/control`, `packaging/debian/rules`, `packaging/debian/ssh3.1`, `packaging/debian/ssh3-server.8`; Rust — **не найдено** | M | M1 |
| M4 | Эксплуатация | Man-страницы | да | нет | Go `packaging/debian/ssh3.1`, `packaging/debian/ssh3-server.8`; Rust — **не найдено** | M | — |
| M5 | Эксплуатация | Структурированное логирование (уровни, файл) | да | нет | Go `cmd/ssh3.go:655`, `cmd/ssh3.go:1064-1071` (zerolog), `util/util.go` (`ConfigureLogger`), `packaging/ssh3-server.env` (`SSH3_LOG_LEVEL`, `SSH3_LOG_FILE`); Rust — **не найдено** (только `eprintln!`) | M | — |
| M6 | Эксплуатация | Коды возврата и баннер версии | да | частично | Go `cmd/exit_status.go:17`, `cmd/exit_status.go:51`, `version.go:22-27` (`PROTOCOL_MAJOR`, `SOFTWARE_IMPLEMENTATION_NAME`); Rust `ssh3-client/src/main.rs:230` (код из сессии), `ssh3-h3/src/lib.rs` (`SSH3_VERSION_STRING`) — семантика `128+signum` не воспроизведена | S | B13 |

---

## 3. Расхождения в поведении

### 3.1. Расхождения при наличии возможности в обеих реализациях

Возможность реализована и там, и там, но ведёт себя **по-разному** — 6 случаев (3 полных + 3 частичных).

| № | Строка | Подсистема | Расхождение | Go | Rust | Влияние |
|---|--------|-----------|-------------|----|------|---------|
| R1 | B3 | Сессия | **PTY-политика.** Go: `auto` по политике `RequestTTY` + `-t`/`-T`; при отсутствии tty PTY не берётся, но `-t` форсирует. Rust: PTY запрашивается **автоматически и безусловно**, если `stdin` — терминал; способа форсировать или запретить PTY нет. | `cmd/ssh3.go:712-713`, `cmd/cli_flags.go:291`, `cmd/forced_pty.go` | `ssh3-client/src/lib.rs:478-482`, `ssh3-client/src/lib.rs:564-579` | Rust-клиент не может выполнить `ssh -T host cmd` (пайплайны) и не может получить PTY без терминала |
| R2 | C7 | Форвардинг | **Политика целей на сервере.** Go ограничивает адреса, куда сервер дозвонится, политикой `permit-open`. Rust дозвонится в **любой** адрес, запрошенный аутентифицированным пиром. | `cmd/forward_policy.go:52`, `cmd/ssh3-server.go:1038` | `ssh3-server/src/forwarding.rs:89` (`TcpStream::connect(remote_addr)` без проверки) | Rust-сервер — SSRF-pivot: аутентифицированный клиент заставляет сервер сканировать внутреннюю сеть. Это **High**, не Medium |
| R3 | I4 | Сервер: аутентификация | **Password-login по умолчанию.** Go: парольный вход **включён** по умолчанию, выключается `-enable-password-login=false` / `SSH3_ENABLE_PASSWORD_LOGIN=0`. Rust: `enable_password_login: false` в дефолте конфигурации — парольный вход по умолчанию **выключен**. | `cmd/ssh3-server.go:992` (дефолт `true`) | `ssh3-server/src/config.rs:92` (`enable_password_login: false`), `ssh3-server/src/auth.rs:149` (`should_authenticate`) | Расхождение в **безопасную** сторону: Rust-сервер из коробки не принимает пароли. Но при этом и не запрашивает пароль при запуске — поведение неэквивалентно и требует явного решения |
| R4 | B7 | PTY | **Переопределение `TERM`.** Go: `-o Term=` → ssh_config `Term` → переменная `TERM` → дефолт. Rust: берёт **только** `TERM` из окружения, переопределения нет. | `cmd/cli_flags.go:310` (`parseTermType`), `cmd/ssh3.go:329-340` (`resolveTermType`) | `ssh3-client/src/lib.rs:574` | Терминальный тип нельзя задать явно — не совпадает с ожиданиями пользователей и с поведением Go |
| R5 | B13, M6 | Сессия / эксплуатация | **Exit-код по сигналу.** Go маппит `exit-signal` в `128+signum` (HUP→129, TERM→143, …) и в 255 при аномальном завершении. Rust пробрасывает код как есть, карты `128+signum` нет. | `cmd/exit_status.go:28-63` (карта `signalExitCodes`), `cmd/exit_status.go:51` (`exitCodeForExitSignal`), `cmd/exit_status.go:17` (`safeExitStatus`) | `ssh3-client/src/lib.rs:171`, `ssh3-client/src/main.rs:230` | Скрипты, различающие `exit 143` (TERM) и `exit 1`, получат разные коды |
| R6 | — | Клиент: прочее | **Баннер версии.** Go печатает полную строку версии протокола и ПО (`SSH 3.0 alpha-00 francoismichel/ssh3 0.1.37`, `version.go:22-27`). Rust печатает только версию крейта из `Cargo.toml` (`clap` `version`). | `version.go:22-27`, `cmd/ssh3.go:676-677` | `ssh3-client/src/main.rs:12` | Невозможно отличить сборку по версии; мелочь, но видна пользователю |

### 3.2. Поведенческие последствия пробелов

Здесь возможность **отсутствует** в Rust, поэтому поведение расходится более радикально — перечислено, чтобы при закрытии пробела не потерять нюанс Go-семантики.

| № | Пробел | Подсистема | Поведение Go | Поведение Rust | Последствие |
|---|--------|-----------|-------------|---------------|-------------|
| P1 | A8, A9, A10 | Аутентификация | **Доверие к серверу**: три независимых слоя — TLS-CA, `known_hosts`/`StrictHostKeyChecking` (политика `ask` по умолчанию) и SSHFP. | Только выбор между `WebPkiRoots`, `--ca-cert` и `--insecure` (`ssh3-client/src/main.rs:123-132`, `ssh3-client/src/lib.rs:60-63`). | У Rust нет «окна подтверждения» хоста: TOFU-подобного поведения нет, доверие решается только на уровне CA. Rust-клиент **безопасен**, но неудобен и не имеет SSHFP-гарантий |
| P2 | C1, C2 | Форвардинг | `-L` и `-L udp://` доступны пользователю; разбор спецификации — `cmd/ssh2_parity.go:67`. | Примитивы `open_tcp_forwarding_channel` / `open_udp_forwarding_channel` есть (`ssh3-quinn/src/channel.rs:418`, `ssh3-quinn/src/channel.rs:397`; `ssh3-core/src/conversation.rs:237`, `ssh3-core/src/conversation.rs:197`), но используются **только в тестах** (`ssh3-client/src/lib.rs:2810-2867`); CLI их не экспонирует. | Функциональность формально «есть в рантайме, нет в продукте» — самый дешёвый пробел в списке |
| P3 | L1 | Сервер | Секретный URL-путь: обработчик монтируется **только** на `/ssh3-term` (`cmd/ssh3-server.go:1543`), всё прочее — 404. | Проверяется только метод CONNECT и `:protocol=ssh3` (`ssh3-server/src/runtime.rs:106`, `ssh3-h3/src/lib.rs:440`); путь игнорируется. | Rust-сервер доступен на **любом** пути: секретность endpoint'а не обеспечена, сканеры видят сервис |
| P4 | I8 | Сервер: аутентификация | Сравнение хэша пароля константно-временно (`util/unix_util/linux_user.go:109`) + lockout (`server_auth/dos_guard.go:30`). | Обычный `==` с ранним выходом (`ssh3-server/src/auth.rs:246`), lockout отсутствует. | Timing-канал на подбор пароля + отсутствие lockout = кратно более простой подбор |
| P5 | L9 | Сервер | По SIGTERM/SIGINT сервер перестаёт принимать соединения и дренирует активные в течение `SSH3_SHUTDOWN_DRAIN` (по умолчанию 5 с) — `cmd/ssh3-server.go:1562`, `cmd/ssh3-server.go:1611-1633`. | Сигналы не ловятся: процесс умирает по умолчанию, активные сессии обрываются (`ssh3-server/src/runtime.rs:33-58`). | При обновлении сервера рвутся живые сессии; в systemd без `KillMode=process` — тем более |
| P6 | K6 | Сервер: лимиты | Кап SSH-строки `util.MaxSSHStringLen = 1<<24` (`util/wire.go:212`, `util/wire.go:219`) и кламп `maxPacketSize` сверху/снизу (`channel.go:178`, `channel.go:193`). | `read_ssh_bytes` выделяет буфер по peer-varint без предела (`ssh3-proto/src/wire.rs:216-222`, боевой путь — `ssh3-core/src/channel.rs:536`); peer-`maxPacketSize` берётся как есть (`ssh3-core/src/channel.rs:451`). | Remote memory exhaustion: peer объявляет длину 2^62 и заставляет сервер выделить память |

Дополнительные расхождения **внутри wire-уровня** (не продуктовая поверхность, но влияют на совместимость) — уже зафиксированы в `ROADMAP.md:208-217` (M5): порядок `family`/`protocol` в `ForwardingRequest` (`ssh3-proto/src/message.rs:625` против `message/channel_request.go:609`), обработка `bool` (`ssh3-proto/src/wire.rs:185`), отсутствие клампа `maxPacketSize` (`ssh3-core/src/channel.rs:447`), отсутствие `forward-port` в карте Go.

---

## 4. План закрытия разрыва

Упорядочено по (a) риск для безопасности, (b) стоимость, (c) зависимостям. Столбец «Блокер» — ссылки на шаги этого плана, которые должны быть выполнены раньше.

### Эшелон 0 — безопасность (блокирует всё остальное)

| № | Шаг | Что делать | Файлы | Критерий готовности | Чел.-дней | Блокер |
|---|-----|-----------|-------|---------------------|---------|--------|
| S1 | Лимит SSH-строки | Ввести кап длины peer-строки ≤ 16 MiB (`util.MaxSSHStringLen = 1<<24`) в `read_ssh_bytes` и в асинхронный путь разбора | `ssh3-proto/src/wire.rs:216-222`, `ssh3-core/src/channel.rs:536` (`parse_message`) | Негативный тест: peer шлёт varint `1<<62` → `Err`, без аллокации; `cargo test -p ssh3-core -p ssh3-proto` зелёный | 1.5 | — |
| S2 | Кламп `maxPacketSize` | Кламп peer-значения сверху локальным и снизу `minPeerMaxPacketSize` (≥4096) — как `channel.go:178`/`channel.go:193` | `ssh3-core/src/channel.rs:451`, `ssh3-quinn/src/channel.rs:364`, `ssh3-core/src/channel.rs:447` | Тест: peer шлёт `maxPacketSize = 1<<40` → локально применяется ≤ локального и ≥ 4096 | 1.5 | S1 |
| S3 | Политика форвардинга `permit-open` / `permit-listen` | Перенести семантику `cmd/forward_policy.go` (шаблоны `*`, `!`-отрицания, `host:port`) в серверный слой; по умолчанию — **ограничение** (в отличие от Go, где пусто = unrestricted, — расхождение нужно зафиксировать) | `ssh3-server/src/forwarding.rs:84-141`, `ssh3-server/src/forwarding.rs:24-78`, новый `ssh3-server/src/forward_policy.rs` | Тест: клиент просит `direct-tcp` на `10.0.0.1:22` → `OpenFailure`; разрешённая цель — ок. Interop-сценарий Go↔Rust с `-permit-open` зелёный | 3 | — |
| S4 | Кап неавторизованных диалогов (MaxStartups-аналог) | Счётчик незавторизованных разговоров + `503` при превышении; снятие слота на выходе | `ssh3-server/src/runtime.rs:98-140`, `ssh3-server/src/config.rs:31-57` | Тест: N+1 параллельных CONNECT без авторизации → `503`; слот возвращается после завершения | 1.5 | — |
| S5 | Lockout паролей + константно-временное сравнение | Заменить `==` на `subtle`-эквивалент; счётчик неудач + `PasswordLockoutDuration` | `ssh3-server/src/auth.rs:246`, `ssh3-server/src/auth.rs:267-273`, `ssh3-server/src/config.rs` | Тест: N+1 неверный пароль → отказ на `PasswordLockoutDuration`; успешный вход сбрасывает счётчик | 2 | S4 |
| S6 | Root-gate | Запретить password-аутентификацию для `root` | `ssh3-server/src/auth.rs:291-296` | Тест: `root` + пароль → `401`; `root` + pubkey → `200` | 0.5 | — |
| S7 | Секретный URL-путь | Проверять путь CONNECT против сконфигурированного `url_path`; иначе `404` | `ssh3-server/src/runtime.rs:106`, `ssh3-server/src/config.rs:31`, `ssh3-server/src/main.rs:14-16` | Тест: CONNECT на `/wrong` → `404`; на `/ssh3-term` → `200`. Interop с Go-сервером (у него путь `/ssh3-term`) зелёный | 1 | — |
| S8 | Кап неограниченных структур | Ограничить `dangling_datagram_queues` (peer-id) и добавить бюджет каналов на разговор | `ssh3-core/src/conversation.rs:308-325`, `ssh3-core/src/conversation.rs:292` | Тест: 10 000 датаграмм на неизвестный channel-id → память под потолком, FIFO-вытеснение | 2 | — |
| S9 | Обновление supply-chain зависимостей | `quinn-proto` ≥ 0.11.19 (RUSTSEC-2026-0185, обход DATAGRAM-лимита), `rustls` ≥ 0.23.46, `webpki-roots`, `rand` | `Cargo.toml`, `Cargo.lock` | `cargo audit` чист по advisory из `ROADMAP.md:185-196` | 1.5 | — |

**Итого эшелон 0: ≈ 15 человеко-дней.**

### Эшелон 1 — дешёвые быстрые выигрыши (дешёвые, дают наибольший эффект)

| № | Шаг | Что делать | Файлы | Критерий готовности | Чел.-дней | Блокер |
|---|-----|-----------|-------|---------------------|---------|--------|
| Q1 | **CLI `-L` (TCP и `udp://`)** | Вывести существующие примитивы в CLI: разбор `[bind:]port:host:port` и `udp://`, локальный listener, pump канала → целевой адрес | `ssh3-client/src/main.rs:31-139`, `ssh3-client/src/lib.rs` (новый модуль `forwarding.rs`), `ssh3-quinn/src/channel.rs:397,418` | `ssh3-rust-client --forward-tcp 8080:example.org:80 host` форвардит TCP; `--forward-udp` — UDP; тест round-trip через локальный echo-сервер; interop-сценарий Rust→Go и Go→Rust зелёные | 2 | — |
| Q2 | **CLI `-D` (SOCKS5)** | Локальный SOCKS5-сервер, разбор `CONNECT`, открытие `direct-tcp` на цель | `ssh3-client/src/lib.rs` (новый `socks.rs`), `ssh3-quinn/src/channel.rs:418` | SOCKS5-клиент (напр. `curl --socks5`) проходит через прокси к локальному echo-серверу | 3 | Q1 |
| Q3 | **Флаги `-t` / `-T` / `-o RequestTTY=`** | Флаг выбора PTY-политики + `RequestTTY` в конфиге | `ssh3-client/src/main.rs:31-139`, `ssh3-client/src/lib.rs:473-500`, `ssh3-client/src/lib.rs:60-63` (`Ssh3ClientConfig`) | `--no-pty` даёт сессию без PTY при tty-stdin; `--force-pty` — PTY без tty | 1 | — |
| Q4 | **Коды возврата `128+signum`** | Разобрать `exit-signal` и вернуть `128+signum` | `ssh3-client/src/lib.rs:169-175`, `ssh3-client/src/lib.rs:1067` (`run_session_stdio`), `ssh3-client/src/main.rs:229-235` | Тест: сервер убивает процесс по TERM → клиент возвращает 143 | 1 | — |
| Q5 | **`-F` + `-o Key=Value`** | Минимальный парсер ssh_config (`Host`, `User`, `Port`, `IdentityFile`, `StrictHostKeyChecking`, `ForwardAgent`, `ServerAliveInterval`) + `-o` с теми же ключами; позже — `Match`/`Include` (Q6) | новый `ssh3-client/src/config.rs` | `ssh3-rust-client -F ./cfg -o Port=4433 host` уважает файл и `-o`; приоритет `-o` > файл > дефолт | 3 | — |
| Q6 | **ssh_config `Match` и `Include`** | Перенести семантику из `client/config/matchcfg/matchcfg.go` | новый `ssh3-client/src/config.rs` | Вложенный `Include` + `Match host` работают; глубина Include ограничена 16 | 3 | Q5 |
| Q7 | **Версия/баннер и `-v`/`-q`** | Единый `SSH3_VERSION_STRING`, уровни логирования, `--version` с версией протокола и ПО | `ssh3-h3/src/lib.rs` (`SSH3_VERSION_STRING`), `ssh3-client/src/main.rs`, `ssh3-server/src/main.rs` | `--version` печатает `SSH 3.0 alpha-00 ... 0.1.x`; `-v` включает подробный лог | 1.5 | — |
| Q8 | **Graceful shutdown сервера** | Ловить SIGTERM/SIGINT, переставать принимать, дренировать N секунд | `ssh3-server/src/runtime.rs:33-58`, `ssh3-server/src/main.rs:71-91` | SIGTERM → новые CONNECT отклоняются, активные сессии завершаются в течение окна; systemd-тест | 2 | — |
| Q9 | **Системd-юнит + EnvironmentFile** | Перенести `packaging/ssh3-server.service` и `packaging/ssh3-server.env` (с новыми именами бинарников) | `ssh3-rust/packaging/` (новый каталог) | `systemd-analyze verify` проходит; сервис стартует с `EnvironmentFile` | 1 | Q8 |

**Итого эшелон 1: ≈ 18 человеко-дней.**

### Эшелон 2 — средние по стоимости

| № | Шаг | Что делать | Файлы | Критерий готовности | Чел.-дней | Блокер |
|---|-----|-----------|-------|---------------------|---------|--------|
| T1 | `known_hosts` + `StrictHostKeyChecking` | Порт `known_hosts.go` (парсинг, проверка сертификата, дописывание) и политику `yes/accept-new/no/ask` | новый `ssh3-client/src/known_hosts.rs`, `ssh3-client/src/main.rs`, `ssh3-client/src/lib.rs` | `ask` без терминала → отказ; `accept-new` → запись в known_hosts; `yes` → отказ при несовпадении | 5 | Q5 |
| T2 | SSHFP + `VerifyHostKeyDNS` | DNS-резолвер SSHFP (RFC 4255), сверка с хост-ключом, политика `yes/no/ask` + список алгоритмов | новый `ssh3-client/src/sshfp.rs`, `ssh3-client/src/main.rs` | Тест с фейковым DNS-ответом: совпадение/несовпадение/отсутствие записи | 4 | T1 |
| T3 | `-R` обратный форвардинг | Клиент: запрос `forward-port`; сервер: приём, биндинг, политика `permit-listen` и `gateway-ports` | `ssh3-client/src/lib.rs`, `ssh3-server/src/forwarding.rs`, `ssh3-proto/src/message.rs:347` (`ForwardPort`) | Reverse-туннель: клиент слушает на сервере, трафик идёт клиенту; `permit-listen` блокирует недопустимые bind | 8 | S3, J2 |
| T4 | `-s` подсистема | Клиент: запрос `subsystem`; сервер: обработчик подсистемы | `ssh3-client/src/lib.rs:113-117`, `ssh3-server/src/session.rs:369-465`, `ssh3-proto/src/message.rs:337` | `subsystem` доходит до сервера и возвращает вывод | 2 | — |
| T5 | Передача файлов (SFTP) | Клиент: SFTP-клиент поверх канала `sftp`; сервер: подсистема SFTP | новый `ssh3-client/src/sftp.rs`, `ssh3-server/src/sftp.rs`, `ssh3-server/src/session.rs` | Загрузка/выгрузка файла; рекурсия по каталогу; докачка | 10 | T4, X7 (эшелон 3) |
| T6 | Лимиты и таймауты сервера | `-max-connections`, `-max-channels-per-conversation`, `-max-idle-timeout`, `-handshake-idle-timeout`, `-max-incoming-streams` | `ssh3-server/src/config.rs`, `ssh3-server/src/runtime.rs`, `ssh3-quinn/src/config.rs` | Каждый лимит имеет тест: превышение → отказ/закрытие | 4 | S8 |
| T7 | Серверные TLS-сертификаты | `-cert`/`-key`/`-c`/`-h` (собственный сертификат) | `ssh3-server/src/tls.rs`, `ssh3-server/src/main.rs:14-43`, `ssh3-server/src/config.rs` | Сервер с собственным PEM-сертификатом принимает клиента с `--ca-cert` | 3 | — |
| T8 | Escape-последовательности | Фильтр `~.`/`~^Z`/`~C` с настраиваемым `EscapeChar` | новый `ssh3-client/src/escape.rs`, `ssh3-client/src/lib.rs:1267-1350` | `~.` закрывает сессию; `~^Z` suspend — на Unix | 4 | Q3 |

**Итого эшелон 2: ≈ 40 человеко-дней.**

### Эшелон 3 — дорогие

| № | Шаг | Что делать | Файлы | Критерий готовности | Чел.-дней | Блокер |
|---|-----|-----------|-------|---------------------|---------|--------|
| X1 | ACME / публичные сертификаты | Интеграция certmagic-эквивалента (Let's Encrypt) для автопродления сертификата | `ssh3-server/src/tls.rs`, `ssh3-server/src/config.rs`, новый `ssh3-server/src/acme.rs` | Сервер получает валидный публичный сертификат и обновляет его | 10 | T7 |
| X2 | Control master | Клиентский unix-сокет, фрейминг `client/cm`, режимы `yes/auto`, `-control-persist`, операции `-O check/stop/exit` | новый `ssh3-client/src/control.rs`, `ssh3-client/src/cm.rs` | Два вызова клиента переиспользуют одно QUIC-соединение; `-O check` отвечает статусом | 12 | Q5, Q1, T1 |
| X3 | Proxy jump | UDP/датаграммный туннель через jump-хост, цепочка хопов, `-J`/`-proxy-jump`/ssh_config | `ssh3-client/src/lib.rs`, `ssh3-client/src/main.rs` | `ssh3-rust-client -J jump target` работает через реальный jump-сервер | 8 | Q5, T1 |
| X4 | Изоляция путей SFTP (`-sftp-jail`) | chroot-модель (дочерний процесс + uid/gid) либо лексический jail | `ssh3-server/src/sftp.rs`, `ssh3-server/src/config.rs` | SFTP-клиент не может выйти за пределы jail; тест на `../../etc/passwd` | 5 | T5 |
| X5 | Debian-упаковка и man-страницы | `.deb` с control/rules/postinst + `ssh3-rust-client.1` / `ssh3-rust-server.1` | `ssh3-rust/packaging/debian/` | `dpkg-deb --build` собирает пакет; `lintian` без ошибок | 5 | Q9, Q7 |
| X6 | X11 forwarding | Полная реализация X11-канала на клиенте и сервере | `ssh3-server/src/session.rs`, `ssh3-client/src/lib.rs`, `ssh3-proto/src/message.rs:331` | X11-приложение стартует через туннель | 6 | T4 |
| X7 | Полный аудит и wire- golden-векторы | Прогон `FROZEN.md`-процедуры; golden-векторы wire-формата из `wire_vectors_test.go`; fuzz-таргеты парсера | новый `ssh3-rust/tests/`, новый `ssh3-rust/fuzz/` | Все 22 interop-сценария зелёные на закреплённом теге Go; fuzz без падений | 5 | — |

**Итого эшелон 3: ≈ 51 человеко-день.**

### Сводка по плану

| № | Эшелон | Чел.-дней | Что даёт |
|---|--------|-----------|----------|
| 1 | Эшелон 0 — безопасность | 15 | Снимает 7 High/Critical-пробелов; без него публичный релиз невозможен |
| 2 | Эшелон 1 — дешёвые выигрыши | 18 | Закрывает 12 пробелов, включая `-L`/`-D` (дешёвый быстрый выигрыш) |
| 3 | Эшелон 2 — средние | 40 | Закрывает ещё ~14 пробелов: known_hosts, SSHFP, `-R`, SFTP, лимиты |
| 4 | Эшелон 3 — дорогие | 51 | Закрывает оставшиеся: ACME, control master, proxy jump, упаковка, аудит |
| | **Итого** | **≈ 124** | Из них эшелоны 0–2 (до полезного «второго стека» без ACME/control master/proxy jump) — **≈ 73** |

---

## 5. Блокирующие зависимости между шагами

### 5.1. Что можно делать параллельно (независимые группы)

| № | Группа | Шаги | Почему независимы |
|---|--------|------|-------------------|
| P1 | Wire-ядро | S1, S2, S8 | Работают в `ssh3-proto`/`ssh3-core`; не трогают CLI и серверную политику |
| P2 | Server-policy | S3, S4, S5, S6, S7 | Работают в `ssh3-server`; каждый — свой файл (`forwarding.rs`, `runtime.rs`, `auth.rs`, `config.rs`) |
| P3 | CLI-форвардинг | Q1, Q2 | Только `ssh3-client`; Q2 зависит лишь от Q1 |
| P4 | CLI-конфигурация | Q5, Q6, Q7 | Только `ssh3-client`; Q6 зависит от Q5 |
| P5 | CLI-мелочи | Q3, Q4 | Независимы от Q1/Q2/Q5 |
| P6 | Client-security | T1, T2 | T2 зависит от T1; не зависит от Q1/Q2 |
| P7 | Supply chain | S9 | Изолирован: только `Cargo.toml`/`Cargo.lock` |
| P8 | Упаковка | Q9, X5 | Q9 → X5; не зависит от функциональных шагов, кроме Q7 (баннер) |

### 5.2. Жёсткие блокеры (пошаговая цепочка)

```
S1 (лимит SSH-строки)
  └─> S2 (кламп maxPacketSize)            [S2 без S1 оставит частично открытую поверхность]

S9 (supply chain)  ── независим, можно первым

S4 (кап неавторизованных диалогов)
  └─> S5 (lockout паролей + const-time)

S3 (permit-open / permit-listen)
  └─> T3 (-R обратный форвардинг)         [без политики нельзя открывать -R безопасно]

Q1 (-L TCP/UDP CLI)
  ├─> Q2 (-D SOCKS5)
  └─> T3 (-R обратный форвардинг)         [общий код локального слушателя]

Q5 (-F / -o)
  ├─> Q6 (Match / Include)
  ├─> T1 (known_hosts)                    [политика хоста читается из конфига]
  │     └─> T2 (SSHFP)
  └─> X2 (control master)                 [control-path из конфига]
        └─> X3 (proxy jump)               [цепочка хостов из конфига]

T4 (-s подсистема)
  └─> T5 (передача файлов / SFTP)
        └─> X4 (sftp-jail)

Q7 (версия/баннер)
  └─> X5 (debian-упаковка)

Q3 (-t/-T)  ──> T8 (escape-последовательности)   [escape требует явного PTY-режима]
Q8 (graceful shutdown) ──> Q9 (systemd) ──> X5 (debian)

X7 (аудит + golden-векторы) — блокирующий для ЛЮБОГО релиза,
    выполняется последним, но требует зелёного interop-набора
```

### 5.3. Критический путь (минимальная последовательность до «безопасно и полезно»)

```
S1 → S2 → S3 → S7 → Q1 → Q5 → Q3 → Q7 → Q8 → Q9
                                    ↘ T1 → T2
```

≈ **18 человеко-дней** без ветки `known_hosts`/`SSHFP`, ≈ **27** с ней — даёт: безопасный сервер (лимиты, политика форвардинга, секретный путь), работающие `-L`, конфигурацию, управление PTY, версию, graceful shutdown и systemd-юнит. Это и есть рекомендуемый «второй стек»-релиз.

---

## 6. Что осталось непроверенным

1. **Динамика и нагрузка.** Все выводы — из статического чтения кода. Реальная производительность Rust-клиента/сервера (latency, throughput, поведение под нагрузкой) не измерялась; Go имеет готовый бенчмарк-стенд (`bench/`), Rust — нет.
2. **Состояние интеграционных тестов.** Interop-матрица из 22 сценариев заявлена в `ssh3-rust/README.md:152-183`, но фактический прогон в этой сессии не выполнялся (нет сборки Go-бинарников и toolchain-проверки). Утверждения «interop зелёный» в критериях готовности — это **целевые** критерии, а не наблюдённые результаты.
3. **Актуальность `ROADMAP.md`.** README/ROADMAP Rust ссылаются на строки `ssh3-server/src/lib.rs:344-393`, `:1718`, `ssh3-client/src/lib.rs:1406-1411` — после разбиения серверного монолита эти номера **устарели**; реальные места — `ssh3-server/src/auth.rs:246` и `ssh3-client/src/lib.rs:1412`. Проверено по факту, в тексте документа использованы фактические строки.
4. **Полнота Go-поверхности.** Проверены `cmd/`, `client/`, `server_auth/`, `message/`, `util/`, `auth/`, `packaging/`, `version.go`. Не разбирались построчно `integration_tests/`, `bench/`, `internal/interop/`, `resources_manager.go`, `channel_rwc.go` — возможны редкие низкоуровневые возможности, не попавшие в таблицу.
5. **Плагинная подсистема Go.** `internal/plugins.go` и `auth/interface.go` задают точку расширения для внешних auth-плагинов; Rust эквивалента не имеет вовсе, и этот пробел в таблице не отражён отдельной строкой.
6. **Windows-специфика Rust.** Часть клиентского кода помечена `#[cfg(unix)]` (`ssh3-client/src/lib.rs:563-584` — терминал, `ssh3-client/src/lib.rs:666` — сигналы), поэтому PTY/resize/сигналы на Windows в Rust не работают, тогда как Go имеет отдельные реализации (`client/escape_windows.go`, `client/signals_windows.go`, `client/winsize/winsize_windows.go`). Это расхождение не выделено строкой в таблице и требует отдельной оценки.
7. **Замер трудозатрат.** Оценки в человеко-днях — экспертные, на основе прочитанного кода; они не проверены календарным прогоном и не учитывают время на CI/review/регрессии.

---

*Сгенерировано 2026-10-22. Источники: `C:\Git\project\ssh3` (Go) и `C:\Git\project\ssh3-rust` (Rust). Код не изменялся.*
