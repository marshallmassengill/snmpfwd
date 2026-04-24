# CLAUDE.md

Notes for future Claude Code sessions working in this repo. This is
intentionally terse — full detail is in the commits, the
`docs/PORTING-NOTES.md` design journal, and `CHANGES.txt`. Read this
first so you don't re-learn the same gotchas.


## Working environment

- Dev venv lives at **`/tmp/snmpfwd-port/`**. Its Python is
  `/tmp/snmpfwd-port/bin/python3` (3.11), pytest is
  `/tmp/snmpfwd-port/bin/pytest`. snmpfwd is installed editable into
  that venv; `snmpfwd-server` / `snmpfwd-client` are in
  `/tmp/snmpfwd-port/bin/`.
- Git default branch is **`rebuild`**, not `master`. `master` is stale
  0.4.5 upstream baseline kept for history. Tags in use: `v0.5.0`,
  `v0.5.1`. See `CHANGES.txt` for what's in each.
- GitHub remote is `git@github.com:marshallmassengill/snmpfwd.git`.
- This is a **personal fork of lextudio/snmpfwd** — not published to
  PyPI, not contributed back upstream.


## Running the tests

Full suite (unit + integration, runs in ~90 s):

    /tmp/snmpfwd-port/bin/pytest tests/

Current state: **195 passed, 6 skipped** (the 6 are the
transparent-proxy parametrizations; see below).

Skip counts can be misleading: the transparent-proxy tests auto-skip
when `os.geteuid() != 0`. Running them requires root + iptables + netns
and the path below; the suite is green without them.

    cd /home/marshall/Development/snmpfwd
    sudo env "PATH=/tmp/snmpfwd-port/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        /tmp/snmpfwd-port/bin/pytest -v tests/integration/test_transparent_proxy.py

`sudo env PATH=...` is required because Ubuntu's sudo applies
`secure_path` which overrides `sudo -E`'s preserved $PATH.


## Real bugs surfaced by this repo — don't let them bite you again

1. **Silent rc=0 on config error**: the installed console-script entry
   runs `sys.exit(main())`, and bare `return` in `main()` on error
   paths yields `sys.exit(None)` which exits 0. Fixed by renaming the
   body to `_run()` and adding a wrapper `main()` that turns normal
   return into rc=1 and KeyboardInterrupt into rc=0. Any new error
   path should still flow through this wrapper.

2. **`cryptography` missing-runtime-dep**: pysnmp 7's DES/AES USM priv
   implementations import from `cryptography.hazmat.decrepit.ciphers`
   unconditionally but declare `cryptography` only as a `[dev]` extra.
   Without it, every SNMPv3 authPriv request fails with
   `decryptionError`. We added `cryptography >= 44.0.1` as a runtime
   dep in `pyproject.toml` — don't remove it.

3. **pysnmp 7 dropped `enablePktInfo` / `enableTransparent`**: the
   asyncio carrier has no helpers for `IP_TRANSPARENT` / `IP_PKTINFO`
   socket options. We create the socket ourselves via
   `endpoint.make_transport_socket()` and pass it via
   `open_server_mode(sock=...)`. New call sites needing these options
   should use the same helper.

4. **pysnmp 7 asyncio carrier drops `IP_PKTINFO` ancillary data**:
   `datagram_received(data, addr)` has no hook for recvmsg-style
   ancillary data. This means `transparent-proxy` mode works for
   ingress but snmpfwd can't see the per-packet original destination
   IP. Noted in `docs/source/configuration/examples/command-forwarding-transparent-proxy.rst`.

5. **pyasn1 `OctetString` str() on binary bytes**: pysnmp 7 generates
   engine-ids as random 8-byte strings. `str(OctetString)` returns the
   raw bytes, which often contain 0x0a or 0x0d, and these break
   `.`-based regex matching. Always use `prettyPrint()` on
   `OctetString` values destined for regex match (see
   `requestObserver` in `snmpfwdserver.py` and the mirror in
   `snmpfwdclient.py`).

6. **`rocommunity` is IPv4-only in net-snmp**. The IPv6 counterpart is
   `rocommunity6`. Passing `rocommunity public ::1` in snmpd.conf
   LOOKS like it works but snmpd silently drops every v6 request.
   Documented at the top of `test_ipv6.py`'s snmpd fixture.

7. **`snmpsim-lextudio` pins `pysnmp-lextudio<7`** which installs into
   the same `pysnmp/` namespace and overwrites our pysnmp 7.x. Use
   **`snmpsim`** (canonical lextudio package, depends on pysnmp>=7.1).
   Already fixed in `.github/workflows/test.yml`.

8. **Ubuntu 24.04 split `snmptrapd` out of the `snmpd` apt package**
   into its own `snmptrapd` package. CI and local setup need both.


## Repo layout landmarks

- `snmpfwd/scripts/snmpfwd{server,client}.py` — the two daemon entry
  points. Each has `def main():` (the wrapper) and `def _run():` (the
  body). Don't collapse them back.
- `snmpfwd/bootstrap.py` — shared startup. Called from both scripts.
  Contains config loading, plugin manager init, dispatcher build,
  trunk wiring, signal handling, metrics timer, SNMP metrics agent,
  and SIGHUP reload plumbing.
- `snmpfwd/log.py` — logging facade. `setLogger(progId, method, *args,
  force=...)` is repeatable; `force=True` clears existing handlers,
  `force=False` appends. `--logging-method` is a CLI flag that
  accepts multiple occurrences.
- `snmpfwd/metrics.py` — in-process counter registry. 12 named
  counters. `metrics.log_deltas()` is the periodic log-dump.
- `snmpfwd/metrics_mib.py` — pysnmp MIB exposure of the above.
  Activated by `SNMPFWD_METRICS_SNMP_BIND=host:port` env var.
- `snmpfwd/target_override.py` — the `lcd.get_target_address` monkey
  patch that backs `transparent-proxy` / `virtual-interface` modes.
  Unit-tested; integration-tested at the snmpfwd-client level.
- `snmpfwd/endpoint.py` — transport-address parser used by both
  scripts. `parse_optional_port`, `make_transport_socket`,
  `transport_af_for_domain`. IPv6 supported.
- `snmpfwd/trunking/` — the server/client trunking protocol +
  encryption.
- `snmpfwd/plugins/manager.py` — exec()-based plugin loader with
  atomic `reload_from_config()` (drives the SIGHUP plugin-reload
  path).
- `snmpfwd/plugins/path_format.py` — macro expansion for the logger
  plugin's destination template.
- `plugins/{logger,oidfilter,rewrite}.py` — bundled user plugins.
- `tests/unit/` — pure Python tests (no subprocess). 50-ish cases.
- `tests/integration/` — spawn real snmpd / snmpfwd-server /
  snmpfwd-client processes, drive net-snmp CLI tools, assert
  end-to-end behaviour. ~145 cases across ~12 test files.
- `conf/` — example configurations for each forwarding scenario.
- `conf/systemd/` — systemd unit files.


## Test fixture patterns

Most integration tests use one of these fixtures from
`tests/integration/conftest.py`:

- `snmpfwd_proxy` — snmpd backend + snmpfwd pair, plain v2c.
- `snmpfwd_trap_proxy` — snmptrapd backend + trap-shaped snmpfwd pair.
- `snmpfwd_proxy_oidfilter` / `snmpfwd_proxy_rewrite` /
  `snmpfwd_proxy_logger_templated` — plain proxy with a single
  bundled plugin attached to the server side.
- `snmpfwd_proxy_with_metrics_agent` — adds the SNMP metrics-MIB
  agent via env var on the server side only.

Each spawns real processes into `tmp_path`. Teardown sends SIGTERM.

If you're writing a test that needs a specific config shape the stock
fixtures don't provide, follow the pattern in
`tests/integration/test_snmpv3.py` or `test_trunk_encryption.py`: write
inline templates + a local fixture that calls `spawn_supervised`
directly. Don't add one-off params to the shared templates.

For anything that needs root (transparent-proxy, netns), gate with:

    pytestmark = [pytest.mark.skipif(os.geteuid() != 0, reason=...)]

and auto-skip in CI.


## Conventions I've been following

- **Comments explain *why*, not *what***. No line comments narrating
  obvious code. Multi-line comments only for surprising bugs or
  pysnmp-specific gotchas — the kind of things this file lists.
- **Commit messages have bodies**: one-line subject, blank line, then
  paragraphs. Wrap at ~72 columns. Don't summarize the diff — explain
  the motivation and any non-obvious choices. Tests and related code
  ship together in the same commit when they're part of the same
  logical change.
- **CHANGES.txt**: top entry is the unreleased / current-release
  section. Everything released has a date. Don't retroactively edit
  released sections.
- **TODO.txt**: short, current. Strike items as you ship them
  (remove the line entirely rather than marking done).


## When the user says "keep going" / "let's do that"

They've been iterating on integration-test coverage and small
feature additions. The pattern is: I propose 1–3 options with brief
scopes, they pick, I execute. They're OK with `sudo`-gated tests
running locally. They've explicitly declared the project "done for
now" after each substantial push, so don't assume there's more to do
until they say so.


## When in doubt

- Don't guess at pysnmp API shapes — probe them via a quick
  `/tmp/snmpfwd-port/bin/python -c "..."` first. The deprecation
  warnings surface renamed symbols (camelCase → snake_case).
- Don't add features that aren't in TODO.txt or explicitly requested.
- Don't mix test-infra changes with feature commits unless the test
  change is strictly in service of the feature.
- Every test you add should be runnable locally today against the
  `/tmp/snmpfwd-port/` venv. If it needs root or a network setup,
  gate it.
