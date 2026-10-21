# SSH3 über HTTP/3 — Rust-Implementierung

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![Status: dormant](https://img.shields.io/badge/status-dormant%20since%202026--10--13-lightgrey.svg)](FROZEN.md)

[English](README.md) | [Русский](README.ru.md) | **Deutsch**

SSH3 bildet RFC-4254-artige Sitzungssemantik auf QUIC, TLS 1.3 und HTTP/3
Extended CONNECT ab. Das Protokoll behält den vertrauten SSH-Workflow — Shell-Sitzungen,
exec, PTY-Zuweisung, Fenstergrößenänderung, Signalweiterleitung, direkte
TCP/UDP-Portweiterleitung, SSH-Agent-Weiterleitung — und trägt ihn über einen
HTTP-nativen Transport mit QUIC-nativen Datagrammen.

Dieses Repository enthält **nur die Rust-Implementierung**: eine unabhängige
Referenzimplementierung des SSH3-Protokolls.

> [!NOTE]
> SSH3 ist weiterhin experimentell, und der Protokollname kann sich noch ändern.
> Das Protokoll bleibt SSH-typische Sitzungs- und Kanalsemantik über QUIC und
> HTTP/3 Extended CONNECT.

> [!WARNING]
> **Dieser Workspace ist seit 2026-10-13 eingefroren (dormant).** Er wird in der
> CI gebaut (Build, Tests, Clippy, Advisory-Scan), aber in keinem
> Release-Artefakt ausgeliefert, und die unten aufgeführten Audit-Fundstellen
> sind mit dem Code eingefroren — es sind keine
> Fixes geplant. Das einzige ausgelieferte Produkt bleibt die Go-Implementierung
> ([nagual2/ssh3-go](https://github.com/nagual2/ssh3-go)). Die Bedingungen für
> das Auftauen stehen in [`FROZEN.md`](FROZEN.md) und
> [`ROADMAP.md`](ROADMAP.md).

## Positionierung

> Unabhängige Referenzimplementierung des SSH3-Protokolls in Rust.
> Wire-kompatibel zu [francoismichel/ssh3](https://github.com/francoismichel/ssh3)
> und zu [nagual2/ssh3-go](https://github.com/nagual2/ssh3-go), aber **kein Fork
> davon und kein Ersatz dafür**.

Dieses Repository ist der **zweite Stack** und die **Protokoll-Referenz** der
SSH3-Implementierungsfamilie. Zweck ist es, eine zweite, unabhängige Lesart des
Wire-Formats lebendig zu halten, die Basis für den C-Port
([nagual2/ssh3-c](https://github.com/nagual2/ssh3-c) zu bilden und dem Protokoll
eine überprüfbare, auditierbare Implementierung zu geben, die nicht an der
Go-Produktoberfläche hängt.

## Voraussetzungen

| Voraussetzung | Hinweise |
| --- | --- |
| Rust 1.85 oder neuer | Die Crates nutzen Edition 2024; die minimal unterstützte Version ist 1.85. |
| Netzwerkzugriff auf crates.io | Nur für den ersten Build nötig; `Cargo.lock` ist eingecheckt. |
| Go-Toolchain (1.21+) | **Nur** für die Cross-Implementierungs-Interop-Tests. Zum Bauen, Starten und Testen des Rust-Codes allein nicht erforderlich. |
| Unix-ähnlicher Host | Die Interop-Szenarien werden nur unter Unix kompiliert (`#[cfg(unix)]`); der übrige Workspace baut auch unter Windows. |

## Bauen und starten

```bash
git clone https://github.com/nagual2/ssh3-rust.git
cd ssh3-rust
cargo build --workspace
```

Der Workspace erzeugt zwei Binaries:

| Binary | Paket | Zweck |
| --- | --- | --- |
| `ssh3-rust-client` | `ssh3-client` | SSH3-Client: Shell, exec, PTY, Authentifizierung, Forwarding. |
| `ssh3-rust-server` | `ssh3-server` | SSH3-Server: Sitzungen, PTY, Authentifizierung, Forwarding. |

Die Paketnamen bleiben `ssh3-client` / `ssh3-server` — sie beschreiben das
Protokoll, nicht das Produkt; die Binaries tragen den Produktnamen, damit sie
nie mit der Go-Implementierung im `PATH` kollidieren.

Hilfe zu beiden Binaries direkt aus dem Workspace:

```bash
cargo run -p ssh3-client -- --help
cargo run -p ssh3-server -- --help
```

Für Geheimnisse sind dateibasierte Flags (`--password-file`,
`--bearer-token-file`, `--oidc-client-secret-file`) vorzuziehen: Werte in
`argv` landen in der Shell-History, in der Prozessliste und in CI-Logs.

## Schnellstart

Der Rust-Server startet mit einem selbstsignierten Zertifikat, deshalb nutzen
die Beispiele unten `--insecure` (stattdessen das Zertifikat mit `--ca-cert`
festnageln, wenn die Gegenstelle nicht auf demselben Host läuft).

Lokalen Server starten:

```bash
cargo run -p ssh3-server -- \
  --bind 127.0.0.1:4433 \
  --user "$USER" \
  --require-auth \
  --authorized-identity ~/.ssh/authorized_keys
```

Mit privatem Schlüssel verbinden und eine Shell öffnen:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --identity ~/.ssh/id_ed25519 \
  https://127.0.0.1:4433/ssh3-term
```

Statt einer Shell einen entfernten Befehl ausführen:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --identity ~/.ssh/id_ed25519 \
  https://127.0.0.1:4433/ssh3-term \
  -- "printf 'hello from ssh3\n'"
```

Der Server akzeptiert derzeit jeden URL-Pfad — Unterstützung für geheime Pfade
gibt es noch nicht (siehe die Einschränkungen unten).

## Crates im Workspace

| Crate | Beschreibung |
| --- | --- |
| `ssh3-proto` | Wire-Format: Nachrichtentypen, SSH-Strings und Varints, Kodierung und Dekodierung des SSH3-Framings. |
| `ssh3-core` | Konversations- und Kanal-Runtime: Kanal-Lebenszyklus, Daten- und Extended-Data-Streams, Datagramm-Warteschlangen. |
| `ssh3-quinn` | QUIC-Transport-Anbindungen auf Basis von `quinn`, TLS-Konfiguration und Erzeugung selbstsignierter Zertifikate. |
| `ssh3-h3` | HTTP/3-Bootstrap und Extended-CONNECT-Behandlung (`:protocol=ssh3`), einschließlich des Datagramm-Dispatch-Pfads. |
| `ssh3-auth` | Authentifizierungshelfer: Public Key (ed25519, P-256, RSA), Password-Verifier-Unterstützung und OIDC-Token-Prüfung. |
| `ssh3-client` | Client-Runtime und CLI-Binary: Sitzungsaufbau, PTY, Resize, Signale, Agent- und Port-Forwarding. |
| `ssh3-server` | Server-Runtime und CLI-Binary: Authentifizierung, Sitzungsverwaltung, PTY, Forwarding. |

`vendor/h3` ist ein bewusster `[patch.crates-io]`-Shim über dem crates.io-Crate
`h3` 0.0.8. Er ergänzt die Unterstützung des Pseudo-Headers `:protocol`, die
Extended CONNECT benötigt und die im Upstream-`h3` fehlt. Nicht gegen das
Upstream-Crate tauschen — siehe [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Tests

```bash
cargo test --workspace          # gesamte Suite: 89 Tests
cargo test -p ssh3-client       # zusätzlich die Cross-Implementierungs-Matrix
```

`cargo check --workspace --locked` läuft ohne Netzwerkzugriff durch, sobald die
Abhängigkeiten zwischengespeichert sind.

### Cross-Implementierungs- (Interop-) Matrix

22 Szenarien fahren **echte Go-Binaries**, gebaut aus dem Repository
[nagual2/ssh3-go](https://github.com/nagual2/ssh3-go), gegen die
Rust-Implementierung — in beide Richtungen:

| Szenario | Rust → Go | Go → Rust |
| --- | --- | --- |
| exec (entfernter Befehl) | ja | ja |
| Public-Key-Authentifizierung (ed25519, P-256, RSA, Aushandlung zusätzlicher Algorithmen) | ja | ja |
| Passwort-Authentifizierung | ja | ja |
| OIDC-Authentifizierung (Token und interaktive Anmeldung) | ja | ja |
| Shell mit PTY | ja | ja |
| Fenstergrößenänderung (SIGWINCH) | — | ja |
| Signalweiterleitung | — | ja |
| Direkte TCP-Weiterleitung | ja | ja |
| Direkte UDP-Weiterleitung (Datagramme) | ja | ja |
| SSH-Agent-Authentifizierung und Agent-Weiterleitung | ja | ja |

> [!WARNING]
> Die Interop-Tests benötigen einen **Checkout des Go-Repositories** und eine
> **Go-Toolchain**. Die Umgebungsvariable `SSH3_GO_REPO` zeigt auf diesen
> Checkout: die Testumgebung baut daraus die Go-Gegenstücke und führt die
> Szenarien dagegen aus. Ohne sie (oder ohne Go-Toolchain) wird jedes
> Interop-Szenario **übersprungen** — im Testlog erscheint eine Zeile
> `skipping:` — statt fehlschlagen. Pin den Checkout auf ein Release-Tag der
> Go-Implementierung: die Interop-Matrix wird gegen ein konkretes Go-Release
> geprüft, nicht gegen `main` (siehe `M0.C.2` in [`ROADMAP.md`](ROADMAP.md)).
> Der eingefrorene `h3`-0.0.8-Shim ist mit der Go-Implementierung bis zur
> `quic-go`-v0.40.x-Linie interoperabel; ein Checkout mit neuerem `quic-go`
> (v0.49+) ist auf Drahtebene nicht kompatibel zu diesem Workspace — die
> Szenarien scheitern mit einem HTTP/3-Fehler `0x104`.
> Die Szenarien werden nur auf Unix-ähnlichen Hosts kompiliert.

## Kompatibilität mit der Go-Implementierung

Die Rust-Implementierung spricht dasselbe Wire-Protokoll wie die
Go-Implementierung: dieselbe Nachrichtennummerierung, dieselbe Framing, dieselben
Authentifizierungsabläufe und dieselben Forwarding-Header. Die obige
Interop-Matrix ist der Regressionsschutz für diese Aussage — eine Änderung in
einer Implementierung, die die andere bricht, lässt die Rust-Testsuite
fehlschlagen.

Die Go-Implementierung ist bei der Produktoberfläche weiter voraus. Sie ist das
ausgelieferte Produkt, und der Rust-Workspace versucht nicht, sie nachzubauen:

| Fähigkeit | Go-Implementierung | Rust-Workspace |
| --- | --- | --- |
| Shell-Sitzung und exec | ja | ja |
| PTY, Resize, Signalweiterleitung | ja | ja |
| Public-Key-, Passwort-, OIDC- und Agent-Authentifizierung | ja | ja |
| Direkte TCP/UDP-Weiterleitung | ja | ja (Runtime und CLI) |
| Reverse-Forwarding (`-R`), dynamisches SOCKS (`-D`), Proxy-Jump | ja | nein |
| Control Master / Verbindungs-Multiplexing | ja | nein |
| Dateiübertragung (`-transfer`) | ja | nein |
| Geheimer URL-Pfad | ja | nein |
| Automatisierung öffentlicher Zertifikate (Let's Encrypt) | ja | nein (nur selbstsigniert) |
| Release-Verpackung (`.deb`, systemd-Unit, goreleaser) | ja | nein |

## Bekannte Einschränkungen und Audit-Fundstellen

Der Workspace wurde mit den folgenden offenen Punkten eingefroren. Sie stehen
hier, damit niemand diesen Code für production-hardened hält.

| Fundstelle | Severity | Ort | Beschreibung |
| --- | --- | --- | --- |
| F-16 | Low (pre-auth) | `ssh3-server/src/lib.rs:344-393` | Die Passwort-Authentifizierung vergleicht den berechneten Hash mit dem kurzschließenden Operator `==` statt mit einem constant-time-Vergleich; eine Sperre nach wiederholten Fehlversuchen fehlt. |
| F-19 (Rust-Client-Rest) | Medium | `ssh3-client/src/lib.rs:1406-1411` | Ein fehlerhaftes Datagramm beendet den Datagramm-Empfang im Rust-Client weiterhin. Die Go-Seite von F-19 wurde im Go-Repository behoben, der Rust-Rest nicht. |
| F-20 | Medium | `ssh3-core/src/conversation.rs:292` | Kein Kanal-Budget: `dangling_datagram_queues` ist eine unbeschränkte `HashMap` über eine vom Peer gelieferte Kennung. |
| Keine Längenbegrenzung für SSH-Strings | High | `ssh3-proto/src/wire.rs:167` | `read_ssh_bytes` allokiert einen Puffer, dessen Größe aus der vom Peer gelieferten Varint-Länge stammt. Die Go-Implementierung begrenzt die Länge (`util.MaxSSHStringLen = 1<<24`), die Rust-Implementierung nicht. |
| `max_packet_size` wird nicht geklemmt | High | `ssh3-quinn/src/channel.rs:364`, `ssh3-core/src/channel.rs:447` | Der vom Peer angegebene Wert wird unverändert übernommen: weder auf ein lokales Maximum geklemmt noch auf ein sinnvolles Minimum gehoben. |
| Kein `permit-open` / `permit-listen` | High | `ssh3-server/src/lib.rs:1718` | Der Server leitet an jede vom Peer verlangte Adresse weiter; es gibt keine Forwarding-Policy, die das einschränkt. |
| Veraltete QUIC-Abhängigkeit | Medium | `Cargo.lock` (`quinn-proto` 0.11.14) | RUSTSEC-2026-0185 (entfernte Speichererschöpfung) und eine Umgehung des DATAGRAM-Limits. Behoben in `quinn-proto` 0.11.19+. Der DATAGRAM-Pfad ist Kern von SSH3, die Advisory betrifft also das Protokoll selbst. |
| Minimaler Server | — | `ssh3-server` | Nur selbstsignierte Zertifikate, keine Automatisierung öffentlicher Zertifikate, kein geheimer URL-Pfad. |

Der Workspace wird von `.github/workflows/ci.yml` gebaut: `cargo fmt --check`,
Clippy mit `-D warnings`, die Testsuite und die Interop-Matrix gegen das
festgehaltene Go-Release `v0.1.12`. Die Toolchain ist in `rust-toolchain.toml`
festgelegt, Formatter und Linter sind in `rustfmt.toml` und `clippy.toml`
konfiguriert.

Zusätzlich existiert eine zweite, asynchrone Kopie des Wire-Parsers in
`ssh3-core/src/channel.rs:439-615`; die Round-Trip-Tests prüfen
`ssh3_proto::Ssh3Message::parse`, das nicht im Produktionspfad verwendet wird.

## Wire-Spezifikation

Das hier gesprochene Protokoll ist der experimentelle IETF-Entwurf
`draft-michel-remote-terminal-http3-00` (pre-standard). Die konkrete
Kodierung, die die Implementierungen verwenden — Nachrichtenlayout,
String-Kodierung, Forwarding-Header — ist im C-Port-Repository spezifiziert:
[SSH3 wire protocol, rev nagual2/1](https://github.com/nagual2/ssh3-c/blob/main/docs/SPEC-wire.md).

## Projektdokumente

| Dokument | Zweck |
| --- | --- |
| [`ROADMAP.md`](ROADMAP.md) | Entwicklungsplan: Rebranding, Sicherheits-Backlog, Wiederherstellung der Infrastruktur, Bedingungen zum Auftauen. |
| [`FROZEN.md`](FROZEN.md) | Der Einfrierungsbeschluss vom 2026-10-13 und seine Folgen für Audits und Releases. |
| [`CHANGELOG.md`](CHANGELOG.md) | Historie nur der Rust-Linie. |
| [`NOTICE`](NOTICE) | Zuordnung und Herkunft des importierten Codes. |
| [`SECURITY.md`](SECURITY.md) | Bedrohungsmodell, bekannte Einschränkungen und Meldeweg für Schwachstellen. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Regeln für Build, Tests und Beiträge. |

## Lizenz und Zuordnung

Lizenziert unter der Apache License, Version 2.0
(<https://www.apache.org/licenses/LICENSE-2.0>).

Der Rust-Code wurde am 2026-04-02 aus
[MatiasHiltunen/ssh3](https://github.com/MatiasHiltunen/ssh3) — einem Fork von
[francoismichel/ssh3](https://github.com/francoismichel/ssh3) — **importiert**
und danach von den `nagual2`-Maintainern erweitert. Es ist kein Rewrite von
Grund auf. Die vollständige Zuordnung steht in [`NOTICE`](NOTICE).

## Go-Implementierung

Die ausgelieferte Go-Implementierung liegt in einem eigenen Repository:
[nagual2/ssh3-go](https://github.com/nagual2/ssh3-go) — ein Fork von
[francoismichel/ssh3](https://github.com/francoismichel/ssh3).
