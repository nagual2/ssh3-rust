# T10 — Windows live acceptance protocol (2026-11-20)

> The protocol of the live acceptance of the Windows client: the agent (T10.1)
> and the interactive console (T10.2). The report of the T10.1 run and the
> transcript of the T10.2 session ride the ROADMAP rows; this file is the
> protocol the ROADMAP rows reference.

## 10.1 — the agent on the named pipe (VM SSH3VPN-W11)

| № | Item | Result |
|---|------|--------|
| 1 | Stand: everything inside the guest — Rust server (windows-gnu, `--bind 127.0.0.1:8443 --url-path /ssh3-term --shell powershell.exe`), OpenSSH ssh-agent, throwaway ed25519 via `ssh-add`, `~/.ssh3/authorized_identities` | ✅ |
| 2 | Client `-v --insecure --user vpnlab --agent https://127.0.0.1:8443/ssh3-term whoami` | ✅ auth rides `\\.\pipe\openssh-ssh-agent`, exec returned `ssh3vpn-w11\vpnlab`, exit 0 |
| 3 | Notes | the Windows server needs `--shell powershell.exe` (the `/bin/sh` default is outside the parity — the reference has no Windows server); the `/var/log/ssh3.log` default is the M5 parity hard-fail — rides `SSH3_LOG_FILE` on Windows; the client hangs silently on a post-auth server channel error — follow-up 10.5 |
| 4 | Rollback | the agent service restored to Disabled, the stand directory deleted, VM Off, the startup memory restored to 2048 MB |

## 10.2 — the interactive console (host console, real Go server igal.lan)

The client `C:\Program Files\ssh3-rust\ssh3.exe` built from main `17efc3a`,
the session `ssh3.exe -i %USERPROFILE%\.ssh\igel_ed25519 --insecure "max@igal.lan:443/ssh3-term"`
against the live Go reference server (Debian 12, igal.lan).

| № | Checklist item | Result |
|---|----------------|--------|
| 1 | Interactive session: raw mode, instant echo, per-keystroke input | ✅ `max@IGAL:~$` |
| 2 | VT rendering of the prompt and the output | ✅ |
| 3 | UTF-8: «привет мир» typed and echoed | ✅ |
| 4 | Ctrl-C during the session | ✅ `^C`, the session survives |
| 5 | Ctrl-Break in a long command | ✅ |
| 6 | Resize of the window | ✅ |
| 7 | Clean `exit` (the client ends with the session — the stdin pump fix) | ✅ twice |

## The findings of the session (beyond the checklist)

| № | Finding | Disposition |
|---|---------|-------------|
| 1 | The Windows exe carries no icon (the reference client does) | release polish — the T7 tail row of the ROADMAP |
| 2 | An operand without the URL path (`max@igal.lan`, `:443`, `:443/`) gets `400 Bad Request` from the server | the server behaviour, not the client; UX polish candidate (hint about the missing `/ssh3-term`) |
| 3 | `-4` on a DNS name that publishes AAAA only refuses honestly | correct |
| 4 | Without `-insecure` the certificate of igal.lan refuses as «unknown, insecure, not self-signed» | the canon 2.3 verdict: a private CA is not a TOFU candidate; the anchors are `--ca-cert` or a pin |
