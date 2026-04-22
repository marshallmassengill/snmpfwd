# Porting notes: pysnmp-lextudio / pyasn1 API drift spike

**Step 0.1 output — investigation only, no code changes applied.**

Scratch venv: `/tmp/snmpfwd-spike` (Python 3.12.3)

| Package          | Version   | Notes                                                 |
|------------------|-----------|-------------------------------------------------------|
| `pysnmp`         | 7.1.24    | lextudio fork; publishes under the plain `pysnmp` name on PyPI |
| `pyasn1`         | 0.6.3     | `pyasn1.compat.octets` removed (only `compat/integer.py` remains) |
| `pycryptodomex`  | 3.23.0    | unchanged API surface; AES-CBC still works identically |
| `snmpsim`        | 1.2.1     | lextudio fork; installs cleanly on pysnmp 7.x; CLI is `snmpsim-command-responder` |

## Summary of required changes

Three classes of change: (A) import-path swaps, (B) camelCase → snake_case renames with no backward-compat shim, (C) removed features with no replacement. Everything else is either unchanged or has a working camelCase alias.

### A. Import-path swaps

| Old path                                          | New path                                              |
|---------------------------------------------------|-------------------------------------------------------|
| `pysnmp.carrier.asynsock.dispatch.AsynsockDispatcher` | `pysnmp.carrier.asyncio.dispatch.AsyncioDispatcher`   |
| `pysnmp.carrier.asynsock.dgram.udp`                | `pysnmp.carrier.asyncio.dgram.udp`                    |
| `pysnmp.carrier.asynsock.dgram.udp6`               | `pysnmp.carrier.asyncio.dgram.udp6`                   |
| `pysnmp.carrier.asynsock.dgram.unix`               | **no replacement — see (C)**                          |

Used in: `snmpfwd/endpoint.py`, `snmpfwd/scripts/snmpfwdserver.py`, `snmpfwd/scripts/snmpfwdclient.py`.

### B. camelCase → snake_case renames (no compat shim)

These are **override-surface or method-call** breakages in modern pysnmp. The old names raise `AttributeError`.

**`AsyncioDispatcher` (old `AsynsockDispatcher`)**
- `registerTimerCbFun(fn, interval)` → `register_timer_callback(fn, interval)`
- `registerRoutingCbFun(fn)` → `register_routing_callback(fn)`
- `sendMessage(...)` → `send_message(...)`
- Still camelCase (compat aliased): `jobStarted`, `runDispatcher`, `closeDispatcher`, `registerTransport`

**`SnmpEngine`**
- `registerTransportDispatcher(td, domain)` → `register_transport_dispatcher(td, domain)`
- `unregisterTransportDispatcher(...)` → `unregister_transport_dispatcher(...)`
- Attribute `snmpEngineID` is still camelCase ✓

**`CommandResponderBase`** (subclassed in `snmpfwdserver.py`)
- Override: `handleMgmtOperation(...)` → `handle_management_operation(...)`
- Class attr: `pduTypes = (...)` → `SUPPORTED_PDU_TYPES = (...)`
- Method: `releaseStateInformation(ref)` → `release_state_information(ref)`
- Method: `sendPdu(engine, ref, pdu)` → `send_pdu(engine, ref, pdu)`

**`NotificationReceiver`** (subclassed in `snmpfwdserver.py` for traps)
- Override: `processPdu(...)` → `process_pdu(...)` *(verify arg signature against pysnmp source before rewriting)*
- Class attr: `pduTypes` → `SUPPORTED_PDU_TYPES`

**`CommandGenerator` / `NotificationOriginator`** (instantiated in `snmpfwdclient.py`)
- `sendPdu(...)` → `send_pdu(...)`

**`v2c.apiPDU` / `v1.apiPDU`** (used in plugins + lazylog)
- `getVarBinds(pdu)` → `get_varbinds(pdu)`
- `setVarBinds(pdu, list)` → `set_varbinds(pdu, list)`

**`rfc2576`** (v1↔v2 PDU proxy translation, used in `snmpfwdserver.py`)
- `v1ToV2(pdu)` → `v1_to_v2(pdu)`
- `v2ToV1(pdu)` → `v2_to_v1(pdu)` (used if we need it)

**`pysnmp.debug`** (used in CLI `--debug-snmp` wiring)
- `pysnmp_debug.setLogger(...)` → `pysnmp_debug.set_logger(...)`
- `pysnmp_debug.flagMap` and `FLAG_MAP` both still work (aliased)

**`pyasn1.debug`** (used in CLI `--debug-asn1` wiring)
- `pyasn1_debug.flagMap` → `pyasn1_debug.FLAG_MAP` (only the uppercase form exists)
- `pyasn1_debug.setLogger` still works
- `pyasn1_debug.Debug` still works

### C. Removed with no replacement

- **`pyasn1.compat.octets`** — entire module gone. Used in `trunking/client.py`, `trunking/server.py`, `trunking/crypto.py`. Mechanical swaps:
  - `null` → `b''`
  - `int2oct(n)` → `bytes((n,))`
  - `oct2int(b)` → `b[0]` (bytes indexing returns int in py3)
  - `str2octs(s)` → `s.encode()` *(verify callsite: in `crypto.py:str2octs(key)` this is the AES key, must remain bytes)*

- **UNIX-domain SNMP transport** — `pysnmp.carrier.asyncio.dgram.unix` does not exist. The existing `try: from ... import unix; except ImportError: unix = None` pattern in `endpoint.py` and both scripts will degrade naturally (conditional use keyed on `unix is not None`). No `conf/*` example uses unix-domain transport. Acceptable loss for the port.

### Preserved — no changes needed

- All **USM auth/priv constants** in `pysnmp.entity.config` (`usmHMACMD5AuthProtocol`, `usmHMAC128SHA224AuthProtocol`, `usmDESPrivProtocol`, `usmAesCfb128Protocol`, `usmAesBlumenthalCfb192Protocol`, `usmNoAuthProtocol`, etc.) still exist as backward-compat shims. The `authProtocols` and `privProtocols` dicts in both scripts are **unchanged**. (New UPPER_SNAKE names like `USM_AUTH_HMAC96_MD5` coexist but we don't need to switch.)
- **`pysnmp.entity.config`** functions: `addV1System`, `addV3User`, `addTargetAddr`, `addTargetParams`, `addVacmUser`, `addTransport`, `addSocketTransport` — all still camelCase.
- All **PDU class imports** from `rfc1157`, `rfc1902`, `rfc1905`, `rfc3411` — unchanged (`TrapPDU`, `GetRequestPDU`, `GetBulkRequestPDU`, `ResponsePDU`, `SNMPv2TrapPDU`, `notificationClassPDUs`, `unconfirmedClassPDUs`, etc.).
- All `v2c` / `v1` type classes (`ObjectIdentifier`, `Integer`, `Integer32`, `OctetString`, `IpAddress`, `Counter32`, `Gauge32`, `Unsigned32`, `TimeTicks`, `Opaque`, `Counter64`, `Null`) — unchanged.
- `pyasn1` encoder/decoder, `SubstrateUnderrunError`, `type.univ`/`namedtype`/`namedval` — unchanged.
- `SnmpContext(snmpEngine)` instantiation pattern — unchanged (only `addContext` helper on `config` is gone, and snmpfwd doesn't call that).

## Asyncio integration shape (for Steps 1.2 / 1.3)

- `AsyncioDispatcher` runs inside a single `asyncio` event loop. There is no `setSocketMap()` / global asyncore socket map equivalent — delete those call sites.
- The `jobStarted(1)` / `runDispatcher()` idiom still works: `runDispatcher()` now blocks by running the event loop. So the main-loop shape `while True: dispatcher.runDispatcher()` can largely stay, wrapped in a try/except as before. Alternative: boot via `asyncio.run(main_async())` where `main_async()` awaits `jobs_are_pending()` — cleaner if we want signal handlers wired up via `loop.add_signal_handler`, which is the modern way to handle SIGTERM/SIGINT under asyncio (vs. the current `signal.signal(...)`).
- Trunk rewrite shape: `trunking/client.py` + `server.py` become `asyncio.Protocol` subclasses. The callback-based public API to `TrunkingManager` (`sendReq`, `sendRsp`, `sendPing`, `sendAnnouncement`, plus `dataCbFun`/`ctlCbFun`) stays identical so the manager barely changes. `handle_read` → `data_received`; `handle_close` → `connection_lost`; `handle_connect` → `connection_made`. The partial-message buffering logic (`prepareDataElements` returning `SubstrateUnderrunError`-signaled incomplete reads) transfers verbatim.
- Signal handling: `daemon.py`'s `signal.signal(signal.SIGTERM, ...)` interacts poorly with asyncio's default SIGINT handling. Switch to `loop.add_signal_handler(signal.SIGTERM, cb)` inside `main_async()`. Double-fork daemonization must happen **before** creating the loop.

## Call-site inventory (for the port plan)

Specific files and concerns, derived from the above:

| File                                  | Changes required                                                  |
|---------------------------------------|-------------------------------------------------------------------|
| `snmpfwd/endpoint.py`                 | `carrier.asynsock` → `carrier.asyncio` imports; drop `unix` block or keep the ImportError fallthrough |
| `snmpfwd/trunking/client.py`          | `asyncore` → `asyncio.Protocol` rewrite; `pyasn1.compat.octets.null` → `b''` |
| `snmpfwd/trunking/server.py`          | `asyncore` → `asyncio.Protocol` rewrite; `pyasn1.compat.octets.null` → `b''` |
| `snmpfwd/trunking/crypto.py`          | `pyasn1.compat.octets.{int2oct,oct2int,str2octs}` removal         |
| `snmpfwd/lazylog.py`                  | `v2c.apiPDU.getVarBinds` → `get_varbinds`                         |
| `snmpfwd/scripts/snmpfwdserver.py`    | Dispatcher/engine/responder method renames (B); `rfc2576.v1ToV2` → `v1_to_v2`; `setSocketMap` removal; `handle_management_operation` override; `SUPPORTED_PDU_TYPES`; `send_pdu`/`release_state_information`; `pysnmp_debug.setLogger` → `set_logger`; `pyasn1_debug.flagMap` → `FLAG_MAP`; unix-dgram fallback; `NotificationReceiver` `process_pdu` override (verify signature); asyncio mainloop |
| `snmpfwd/scripts/snmpfwdclient.py`    | Dispatcher/engine renames; `setSocketMap` removal; `commandGenerator.sendPdu` → `send_pdu`; `notificationOriginator.sendPdu` → `send_pdu`; debug-module renames; unix-dgram fallback; asyncio mainloop |
| `snmpfwd/daemon.py`                   | Signal-handler setup moves to `loop.add_signal_handler` (Step 1.3) |
| `plugins/rewrite.py`                  | `getVarBinds`/`setVarBinds` → snake_case                          |
| `plugins/oidfilter.py`                | `getVarBinds`/`setVarBinds` → snake_case                          |
| `plugins/logger.py`                   | verify PDU type handling; likely `get_varbinds` rename only       |
| `pyproject.toml`                      | `python = "^3.11"`; `pysnmp = "^7"`; bump `pyasn1`; regenerate lock |

## Decisions crystallized by the spike

1. **Drop unix-domain SNMP transport** in the port. Not used by any example config. If we ever need it back, write a custom asyncio transport (small).
2. **Break plugin API for `getVarBinds`/`setVarBinds`** callers. This is a personal-fork trade: the camelCase forms are gone upstream and adding a compat shim per plugin is more work than just renaming.
3. **Use `asyncio.Protocol`** for the trunk rewrite rather than `StreamReader`/`Writer`. The existing `handle_read` callback-style fits `data_received` cleanly; Protocol subclasses are also lighter weight than coroutine-based stream handling.
4. **Use `loop.add_signal_handler`** for SIGTERM/SIGINT/SIGHUP/SIGQUIT in the daemon path; `signal.signal()` doesn't interop cleanly with asyncio.
5. **Keep the deprecated camelCase pysnmp aliases** where available (`jobStarted`, `runDispatcher`, `closeDispatcher`, `registerTransport`, `snmpEngineID`, USM constants, `config.addV1System`/etc., `pysnmp_debug.flagMap`). No point chasing every deprecation warning in Phase 1 — that's Phase 2 housekeeping.

## Questions surfaced

- **`NotificationReceiver.process_pdu` signature**: the new pysnmp is likely positional-argument compatible with the old `processPdu`, but Step 1.3 must verify against the pysnmp source before the rewrite. If the signature changed, `snmpfwdserver.py:main.processPdu` needs parameter-list updates too.
- **snmpsim-lextudio's own asyncio compatibility**: confirmed-installable; actual runtime behavior under the test harness will be validated in Step 0.3.
- **Whether `AsyncioDispatcher.runDispatcher()` blocks sanely** or needs an explicit `loop.run_forever()`: resolvable by reading `dispatch.py:118-170` in pysnmp; defer to Step 1.3.

---

# Step 0.2: baseline reference running on Python 3.11 + pinned old deps

Unmodified 0.4.5 code runs cleanly on Python 3.11 with `pysnmp==4.4.12` + `pyasn1==0.4.8`. End-to-end GET / GETNEXT / GETBULK / WALK through the proxy all round-trip correctly. Wrong-community auth failure logs the intended `SNMPv2 auth failure ... Unknown SNMP community name encountered` and silently drops the request (no response, timeout at client — expected behavior).

No deprecation warnings or tracebacks observed during startup or traffic.

## Reference setup (for Step 0.3 integration harness + future regression comparison)

**Working directory:** `/tmp/snmpfwd-baseline/`  **Reference venv:** `/tmp/snmpfwd-0.4.5/` (Python 3.11.15)

### Venv creation

```
uv python install 3.11
uv venv --python 3.11 /tmp/snmpfwd-0.4.5
VIRTUAL_ENV=/tmp/snmpfwd-0.4.5 uv pip install 'pysnmp<5' 'pyasn1<0.5' pycryptodomex
VIRTUAL_ENV=/tmp/snmpfwd-0.4.5 uv pip install -e /home/marshall/Development/snmpfwd --no-deps
```

### Topology

```
snmpget -v2c -c public-123 127.0.0.1:1161
        │
        ▼
  snmpfwd-server    (SNMP listener on 127.0.0.1:1161, trunk client → 30301)
        │ trunk msg
        ▼
  snmpfwd-client    (trunk server on 127.0.0.1:30301, SNMP manager → 11611)
        │ SNMP GET
        ▼
        snmpd        (127.0.0.1:11611, communities public-123 / public-321)
```

### `snmpd.conf` (scratch backend)

```
rocommunity public-123 127.0.0.1
rocommunity public-321 127.0.0.1
syslocation "snmpfwd-baseline-lab"
syscontact "test@localhost"
sysServices 72
```

### snmpfwd configs

Both configs derived from `conf/command-forwarding-server-classification/` with only the client-side `agent-1` / `agent-2` blocks rewritten to point at `127.0.0.1:11611` with communities `public-123` / `public-321` (upstream values pointed at dead host `104.236.166.95`), and corresponding `snmp-peer-id` / `using-snmp-peer-id-list` renames from `snmplabs-agent-*` to `local-agent-*`.

### Boot sequence (order matters: trunk-server side first)

```
# Terminal 1 — backend agent
/usr/sbin/snmpd -f -Lo -C -c /tmp/snmpfwd-baseline/snmpd.conf \
    --rwcommunity="" --noPersistentSave=true --noPersistentLoad=true \
    udp:127.0.0.1:11611

# Terminal 2 — snmpfwd-client (trunk server on 30301)
/tmp/snmpfwd-0.4.5/bin/snmpfwd-client \
    --config-file=/tmp/snmpfwd-baseline/client.conf \
    --logging-method=file:/tmp/snmpfwd-baseline/client.log --log-level=debug

# Terminal 3 — snmpfwd-server (SNMP listener + trunk client)
/tmp/snmpfwd-0.4.5/bin/snmpfwd-server \
    --config-file=/tmp/snmpfwd-baseline/server.conf \
    --logging-method=file:/tmp/snmpfwd-baseline/server.log --log-level=debug
```

### Validated round-trips

| Operation  | Command                                                                                   | Result |
|------------|-------------------------------------------------------------------------------------------|--------|
| GET        | `snmpget -v2c -c public-123 127.0.0.1:1161 1.3.6.1.2.1.1.1.0 ...1.4.0 ...1.6.0`           | OK — all 3 OIDs returned |
| GETNEXT    | `snmpgetnext -v2c -c public-123 127.0.0.1:1161 1.3.6.1.2.1.1.1`                           | OK — returns `.1.1.0` |
| GETBULK    | `snmpbulkget -v2c -c public-123 -Cn0 -Cr3 127.0.0.1:1161 1.3.6.1.2.1.1`                   | OK — 3 varbinds |
| WALK       | `snmpwalk -v2c -c public-123 127.0.0.1:1161 1.3.6.1.2.1.1`                                | OK — full system group |
| auth-fail  | `snmpget -v2c -c nope 127.0.0.1:1161 -t 1 -r 0 1.3.6.1.2.1.1.1.0`                         | Timeout (expected; server logs `SNMPv2 auth failure ... Unknown SNMP community name`) |

### Gotcha captured during baseline setup

The example config (`command-forwarding-server-classification`) exposes a subtle credentials-reuse quirk: both `agent-1` and `agent-2` in the client's `peers-group` inherit the same `snmp-security-name`/`security-model`/`security-level` from the parent scope, so pysnmp constructs a single credentials ID (`public/1/2`) used for both peers despite their per-peer `snmp-community-name` overrides. The log shows this as "using credentials ID public/1/2..." for agent-2. **Not a bug in snmpfwd** — the example is illustrating classification routing, not differentiated client credentials — but worth noting so we don't chase it during the port. If a test needs truly independent per-peer communities, the per-peer block must also override `snmp-security-name`.

## Artifacts preserved

- `/tmp/snmpfwd-baseline/{server,client,snmpd}.conf` — working config triplet
- `/tmp/snmpfwd-baseline/{server,client}.log` — successful trunk handshake + traffic logs
- `/tmp/snmpfwd-0.4.5/` — frozen reference venv (Python 3.11.15 + pysnmp 4.4.12 + pyasn1 0.4.8)

These should remain in place until Step 0.4 integration tests have reproduced all observed baseline behaviors on the modern stack; then can be deleted.

---

# Appendix: gotchas caught during Phase 1 / Phase 2

## `str(OctetString)` on binary pyasn1 values

`str(pyasn1.type.univ.OctetString)` returns the raw bytes reinterpreted as a Python string — not a hex dump, not `prettyPrint()`, not `repr()`. For printable bytes that's fine; for binary bytes it gives you literal control characters embedded in the string.

pysnmp 7 generates SNMPv3 engine-IDs as random OctetStrings. Roughly 1 byte in 43 will be `0x0a` (LF) or `0x0d` (CR). Any regex matching over a string built from `str(engine_id)` will fail on those values because Python's `re.match` treats `.` as "any char except newline" by default — a pattern like `.*?#.*?` (used to match engine-id + context-name in snmpfwd's request classifier) will *silently refuse to match* whenever the engine-id random draw happens to contain a newline-category byte.

Symptom in snmpfwd: tests flake at ~30%, with the server logging `no route configured` and `snmp-context-id=<nil>` — because the context-id regex match-key fell through to `None`.

**Fix:** always pretty-print binary pyasn1 values before building keys for regex matching. Use `x.prettyPrint() if hasattr(x, 'prettyPrint') else str(x)`. That returns a stable `0x01abc...` hex form regardless of which bytes the random draw produced. Applied in `snmpfwdserver.py:requestObserver` and `snmpfwdclient.py:trunkCbFun`, commit `32fabc5`.

## `self.releaseStateInformation` on pysnmp 7's CommandResponderBase

The Phase 1 rename sweep caught every `self.sendPdu` → `self.send_pdu` and most `self.releaseStateInformation` → `self.release_state_information` occurrences, but **one** call on the rarely-exercised "no route configured" error branch was missed. Only surfaced under Phase 2 load once the test matrix grew to 28+ scenarios, with cascading failures because the AttributeError propagated back through `pysnmp.entity.rfc3413.cmdrsp.process_pdu` as an uncaught callback exception. Written up in `32fabc5`.

**Preventive lesson:** when doing a rename sweep across a function body, take one extra pass through every error branch even if it looks obviously covered — those paths are by definition not exercised by the happy-path integration tests.

## pysnmp 7's `process_pdu` auto-releases state at return

In pysnmp 4.x, `CommandResponderBase.process_pdu` invoked `handle_management_operation` and returned — the subclass was responsible for calling `release_state_information` itself once the response had been sent.

pysnmp 7 unconditionally calls `release_state_information` at the *end* of `process_pdu`. That works for synchronous responders but breaks any handler that forwards the request over an async channel and responds later from a callback — which is exactly what snmpfwd does. The stale-state `KeyError` manifests as a traceback through `send_pdu → __pendingReqs[stateReference]` when `trunkCbFun` finally receives the backend's reply.

**Fix:** stash `self._CommandResponderBase__pendingReqs[stateReference]` into a subclass-owned dict on entry to `handle_management_operation`, then re-insert it right before the `send_pdu` call from the async trunk callback. Name-mangled attribute access is ugly but minimal. Landed in `e81a319`. A cleaner upstream fix would be a pysnmp hook to defer the auto-release.

## `AsyncioDispatcher` and transport loop coupling

`pysnmp.carrier.asyncio.dgram.udp.UdpAsyncioTransport()` with no arguments calls `asyncio.get_event_loop()` on construction, which on Python 3.10+ implicitly creates a brand-new loop if none is current. `AsyncioDispatcher` owns its own loop (`dispatcher.loop`) — if the UDP transports each create their own fresh loop, the dispatcher never runs them and packets land in a void.

**Fix:** always pass `loop=transportDispatcher.loop` when constructing UDP transports. The symptom if you don't is packets arriving at the OS socket, no exception, but `handle_management_operation` never being called. Landed in `e81a319`.

## `register_routing_callback` is still required

It looks vestigial (lambda that returns the transport-domain) but the dispatcher uses it to key recv-callables. Dropping it causes `CarrierError: No callback for "None" found - losing incoming event` on the very first packet, with no other symptom. Keep it.

---

# Phase 3B — end-to-end INFORM confirmation (shipped)

**Status:** implemented. The proxy now acks the original INFORM sender only after the downstream has acked the proxy. On downstream failure (timeout / unreachable / auth-fail), the ack is skipped so the sender can retry — RFC-strict semantic for a proxy.

Design decisions taken in the implementation:

1. **Trunk wire protocol:** unchanged. The existing `Response` message's `error-indication` + `snmp-pdu` fields already carry what the server needs. snmpfwd-client was already sending `error-indication='<pysnmp errorIndication>'` on downstream failure via `notificationOriginator.send_pdu(..., snmpCbFun, cbCtx)`'s callback — that payload was just being logged-and-ignored on the server side before. No protocol bump needed.

2. **Server side (`snmpfwdserver.py`):** `NotificationReceiver.process_pdu` stashes `(stateReference, messageProcessingModel, securityModel, securityName, securityLevel, contextEngineId, contextName, pduVersion, maxSizeResponseScopedPDU, requestPdu)` into the cbCtx tuple passed to `trunkingManager.sendReq(...)`. `trunkCbFun` unpacks that on the way back out and calls `snmpEngine.message_dispatcher.return_response_pdu(...)` with a fresh `ResponsePDU` built from the stashed `requestPdu` (using `v2c.apiPDU.get_response()` which copies the original request-id so the sender's message-dispatcher matches it).

3. **Client side (`snmpfwdclient.py`):** unchanged. Already did the right thing — forwards downstream, waits for ack, sends trunk Response with `error-indication` populated on failure.

4. **Timeout handling: strict mode.** On downstream failure the ack is skipped. The original INFORM sender's retry logic kicks in. This amplifies load on pathological downstreams, but it's RFC-strict and keeps the semantic clean. If a user ever wants optimistic mode, it would be a config flag that picks between skip and ack-anyway in `trunkCbFun`.

5. **Duplicate handling:** not addressed. If the downstream is slow and the sender retries before the first INFORM's ack propagates, the proxy forwards the retry as a separate trunk message. That's no worse than SNMP without a proxy and matches how most proxies behave.

6. **State cleanup:** relies on pysnmp's message dispatcher — when `return_response_pdu` gets called (success path), pysnmp releases its internal state keyed on `stateReference`. On failure where we never call `return_response_pdu`, pysnmp's state for that incoming INFORM is orphaned. In practice pysnmp's per-message state is small and gets garbage-collected; for very-long-running deployments with many failing downstream INFORMs this could leak, but not in a way that's tested or observed. Future: add an explicit release-without-response path if this ever becomes a problem.

7. **The "no-op cbFun" from 3A is still passed** to `NotificationReceiver(snmpEngine, _inform_ack_cb)` — 3B doesn't call `super().process_pdu(...)` at all, so the cbFun is never invoked in practice, but we keep the argument populated for defensive reasons. It documents that this slot exists and is intentionally unused.

Integration tests:
- `test_inform.py::test_inform_is_acked_by_proxy` — end-to-end happy path (downstream up, ack propagates).
- `test_inform.py::test_inform_forwards_to_backend` — INFORM payload arrives at snmptrapd alongside the ack.
- `test_inform.py::test_inform_server_log_shows_forwarding` — server records InformRequest handling.
- `test_inform_downstream.py::test_inform_no_ack_when_downstream_unreachable` — downstream dead, proxy logs "NOT responding", `snmpinform` on the sender sees a timeout.
