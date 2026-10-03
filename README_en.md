# ghacc

English | [简体中文](README.md)

ghacc (GitHub / Steam Accelerator) is a network accelerator written in **C++23 modules**. It
extracts and rewrites the "network acceleration" feature of SteamTools (Watt Toolkit / Steam++)
into a CLI + TUI program for **Linux / macOS / Windows**:

- Intercept target traffic via **Hosts + a local MITM reverse proxy**, or the **system proxy /
  PAC forward proxy**;
- Pick faster upstream IPs with **DoH resolution + TCP latency ranking**;
- Ship built-in **GitHub** and **Steam** rules, extendable from configuration;
- Mint a local CA on demand to decrypt and forward TLS (MITM), with one-command trust/untrust.

> This repository is a standalone rewrite of SteamTools' network acceleration. It does not include
> Steam client JS injection, commercial acceleration SDKs, or the Windows WinDivert mode, but the
> script-injection extension point is reserved.

## Features

| Area | Description |
|---|---|
| Proxy modes | `hosts` (Hosts + MITM reverse proxy), `system`, `pac`, `forward` |
| Targets | Built-in `github`, `steam`; data-driven `[[provider.custom]]` |
| DNS | Custom DoH (A/AAAA/CNAME) + TTL cache + latency ranking, system fallback |
| TLS | Self-signed local CA, per-host leaf certificates, SNI selection, ALPN fixed to `http/1.1` |
| Takeover | Marked hosts block (reversible, backed up); GNOME/KDE/macOS/Windows system proxy |
| Observability | 5-second sliding-window rates, request log, log rotation, config hot reload |
| Interface | FTXUI dashboard + a complete command line |

## Platform support

| Capability | Linux | macOS | Windows |
|---|---|---|---|
| hosts path | `/etc/hosts` | `/etc/hosts` | `%SystemRoot%\System32\drivers\etc\hosts` |
| Bind 80/443 | root or `setcap cap_net_bind_service=+eip <bin>` | root | Administrator |
| CA trust | Debian: `update-ca-certificates`; RHEL: `update-ca-trust` | `security add-trusted-cert` | `certutil -addstore` |
| System proxy | GNOME `gsettings` / KDE `kwriteconfig` | `networksetup` | `reg` (WinINET) |
| Daemon | `fork`+`setsid` | `fork`+`setsid` | unsupported; use a service |

> Only Linux is covered by automated verification. The macOS/Windows branches are implemented and
> return clear privilege hints, but were not exercised end-to-end on those systems.

## Build

Requires [mcpp](https://github.com/mcpp-community/mcpp) and the cached third-party packages
(asio / OpenSSL / FTXUI / tomlplusplus / cmdline / boost.ut).

```sh
mcpp build            # build the workspace (libs/accel + apps/ghacc)
mcpp test             # run unit tests (under libs/accel and apps/ghacc)
mcpp run ghacc -- --help
```

The first build downloads and statically builds `compat.openssl`, which takes a while; afterwards it
lives in mcpp's global cache.

## Quick start

```sh
# 1. Dashboard (no arguments opens the TUI)
ghacc

# 2. Hosts + MITM: rewrite hosts and point 80/443 at the local reverse proxy
sudo ghacc hosts apply --provider github,steam
sudo ghacc run --mode hosts
sudo ghacc hosts revert

# 3. System proxy
ghacc run --mode system
ghacc proxy set

# 4. PAC
ghacc run --mode pac
ghacc proxy set --pac

# 5. Plain forward proxy: point clients at http://127.0.0.1:26501
ghacc run --mode forward
curl -x http://127.0.0.1:26501 http://github.com

# Stop a background instance
ghacc stop
```

## Command reference

```
ghacc [tui]                               dashboard (also the no-argument default)
ghacc run   [--mode hosts|system|pac|forward]
            [--provider a,b] [--address IP]
            [--http-port N] [--https-port N] [--proxy-port N]
            [-d|--daemon] [--force]
ghacc stop
ghacc status [--json]
ghacc provider list
ghacc provider enable|disable <id>
ghacc ca path|show|export|install|uninstall [--path FILE]
ghacc hosts show|apply|revert [--ip IP] [--provider a,b]
            [--path FILE] [--backup FILE]
ghacc proxy set|clear [--pac] [--host HOST] [--port N]
ghacc test <domain> [--dns URL]...
ghacc config path|get|set|edit [key] [value]
ghacc completion bash|zsh|fish
ghacc version | help
```

The shared options `--config FILE` and `--dir DIR` are accepted before or after the subcommand.

`status --json` emits stable fields for scripts:

```json
{
  "version": "0.1.0",
  "running": false,
  "mode": "hosts",
  "address": "127.0.0.1",
  "proxy_port": 26501,
  "http_port": 80,
  "https_port": 443,
  "providers": ["github", "steam"],
  "available_providers": ["github", "steam"],
  "ca_present": true,
  "ca_trusted": false,
  "hosts": {"path": "/etc/hosts", "block_present": false, "writable": false, "entries": 0}
}
```

## TUI dashboard

Run `ghacc` with no arguments or `ghacc tui` for a full-screen dashboard: status bar on top,
provider toggles on the left, live traffic in the centre, request log on the right and key hints at
the bottom.

| Key | Action |
|---|---|
| `s` | Start / stop the engine |
| `p` | Pause / resume refresh |
| `r` | Clear the request log |
| `m` | Cycle mode and persist it (listeners need a restart) |
| `c` | Install and trust the local CA |
| `h` | Apply the hosts block |
| `q` | Quit |

## Configuration

Default paths (override with `--config`):

- Linux: `$XDG_CONFIG_HOME/ghacc/config.toml` (defaults to `~/.config/ghacc/config.toml`)
- macOS: `~/Library/Application Support/ghacc/config.toml`
- Windows: `%APPDATA%\ghacc\config.toml`

```toml
[general]
mode = "hosts"          # hosts | system | pac | forward
log_level = "info"      # debug | info | warn | error

[listen]
address = "127.0.0.1"
proxy_port = 26501
http_port = 80
https_port = 443
pac_path = "/pac"

[dns]
doh = ["https://doh.pub/dns-query", "https://1.1.1.1/dns-query"]
prefer_ipv6 = false
cache_ttl = 600

[providers]
enabled = ["github", "steam"]

# Data-driven extension: no rebuild needed
[[provider.custom]]
id = "example"
name = "Example"
[[provider.custom.rules]]
pattern = "*.example.com"
```

`ghacc config get|set` understands: `mode`, `log_level`, `listen.address`, `listen.proxy_port`,
`listen.http_port`, `listen.https_port`, `listen.pac_path`, `dns.prefer_ipv6`, `dns.cache_ttl`,
`dns.doh`, `providers.enabled`.

While running, the config file's mtime is watched and **provider rules** and **log level** hot
reload; changes to listen address/ports/mode require a restart.

## Data and log paths

| Purpose | Linux | macOS | Windows |
|---|---|---|---|
| CA cert/key | `~/.config/ghacc/ca/` | `~/Library/Application Support/ghacc/ca/` | `%APPDATA%\ghacc\ca\` |
| Leaf cache | `~/.local/share/ghacc/certs/` | `~/Library/Application Support/ghacc/certs/` | `%LOCALAPPDATA%\ghacc\certs\` |
| PID / hosts backup | `~/.local/state/ghacc/` | `~/Library/Application Support/ghacc/` | `%LOCALAPPDATA%\ghacc\` |
| Rotating log | `~/.local/state/ghacc/ghacc.log` | `~/Library/Logs/ghacc/ghacc.log` | `%LOCALAPPDATA%\ghacc\logs\ghacc.log` |

Logs rotate by size (4 MiB default, keeping three `.1`/`.2`/`.3` generations).

## Trusting the CA

```sh
ghacc ca path          # print the ca.crt path
ghacc ca show          # print the PEM
ghacc ca export --path ./ghacc-ca.crt
sudo ghacc ca install  # install into the system trust store
sudo ghacc ca uninstall
```

Without privileges the command fails with a `sudo` / Administrator hint.

## Tests

```sh
# Unit tests (boost.ut)
cd libs/accel && mcpp test
cd apps/ghacc && mcpp test

# End-to-end (Python + pytest, driving a real process)
cd tests/e2e && uv run pytest
```

The end-to-end suite never touches ports 80/443, the real `/etc/hosts`, or the system proxy; see
[`tests/e2e/README_en.md`](tests/e2e/README_en.md).

## Packaging

```sh
mcpp pack                        # default vendored bundle
mcpp pack --mode self-contained  # bundle the runtime libraries for redistribution
```

Artifacts land in `apps/ghacc/target/dist/`.

## Extending providers

Acceleration targets beyond the built-ins can be added either data-driven from the config file or as
a C++ module that registers itself. See [`docs/provider-api_en.md`](docs/provider-api_en.md).

## Known limitations

- HTTP/1.1 only: the local ALPN advertises `http/1.1` and upstream uses 1.1 as well.
- hosts has no wildcard support: `*.github.com` collapses to `github.com`; subdomains rely on
  MITM / forward-proxy modes.
- Steam JS injection is not implemented (the `IScriptInjector` interface is reserved).
- Windows WinDivert DNS interception and commercial acceleration SDKs are out of scope.
- macOS/Windows takeover flows are not automatically verified on those platforms.

## License

MIT
