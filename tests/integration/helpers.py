"""
Low-level helpers for the integration test harness: port allocation, subprocess
supervision, net-snmp CLI wrappers. Kept separate from conftest.py so tests can
import them directly when needed.
"""
from __future__ import annotations

import dataclasses
import os
import re
import shutil
import signal
import socket
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, List, Optional, Sequence


# Deliberately small — in parallel-test scenarios bind(0) still gives
# us unique ports per worker since SO_REUSEADDR is not set.
def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def tcp_port_open(host: str, port: int, timeout: float = 0.25) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return True
        except OSError:
            return False


def log_contains(path: Path, needle: str) -> bool:
    try:
        return needle in path.read_text(errors="replace")
    except FileNotFoundError:
        return False


@dataclasses.dataclass
class ManagedProcess:
    """Handle to a supervised background process with its log file."""
    name: str
    proc: subprocess.Popen
    log_path: Path

    def log_text(self) -> str:
        try:
            return self.log_path.read_text(errors="replace")
        except FileNotFoundError:
            return ""

    def terminate(self, grace: float = 5.0) -> None:
        if self.proc.poll() is not None:
            return
        try:
            self.proc.terminate()
        except ProcessLookupError:
            return
        try:
            self.proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


def _wait_for_ready(name: str, proc: subprocess.Popen, ready: Callable[[], bool],
                    log_path: Path, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            tail = log_path.read_text(errors="replace")[-2000:] if log_path.exists() else ""
            raise RuntimeError(
                f"{name} exited prematurely (code={proc.returncode})\n--- log tail ---\n{tail}"
            )
        if ready():
            return
        time.sleep(0.1)
    tail = log_path.read_text(errors="replace")[-2000:] if log_path.exists() else ""
    raise TimeoutError(
        f"{name} did not become ready within {timeout:.1f}s\n--- log tail ---\n{tail}"
    )


def spawn_supervised(
    *,
    name: str,
    cmd: Sequence[str],
    log_path: Path,
    ready: Callable[[], bool],
    ready_timeout: float = 15.0,
    env: Optional[dict] = None,
) -> ManagedProcess:
    """Start a background daemon, redirect its output to log_path, wait for readiness."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_file = log_path.open("wb")
    try:
        proc = subprocess.Popen(
            list(cmd),
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env=env,
        )
    finally:
        # We need the log file open for the child; Popen dup'd the fd, so we
        # can close our copy to avoid leaking.
        log_file.close()

    handle = ManagedProcess(name=name, proc=proc, log_path=log_path)
    try:
        _wait_for_ready(name, proc, ready, log_path, ready_timeout)
    except BaseException:
        handle.terminate()
        raise
    return handle


# ---------------------------------------------------------------------------
# net-snmp CLI wrappers


@dataclasses.dataclass
class SnmpVarBind:
    oid: str
    type_name: str
    value: str


class SnmpCliError(RuntimeError):
    def __init__(self, returncode: int, stderr: str, stdout: str) -> None:
        super().__init__(f"snmp CLI failed (rc={returncode}): {stderr.strip() or stdout.strip()}")
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = stdout


_VARBIND_RE = re.compile(r"^(\S+)\s*=\s*([\w-]+):\s*(.*)$")
_VARBIND_NOTYPE_RE = re.compile(r"^(\S+)\s*=\s*(.*)$")


def _parse_varbinds(stdout: str) -> List[SnmpVarBind]:
    out: List[SnmpVarBind] = []
    for line in stdout.splitlines():
        line = line.rstrip()
        if not line:
            continue
        m = _VARBIND_RE.match(line)
        if m:
            out.append(SnmpVarBind(oid=m.group(1), type_name=m.group(2), value=m.group(3)))
            continue
        m = _VARBIND_NOTYPE_RE.match(line)
        if m:
            out.append(SnmpVarBind(oid=m.group(1), type_name="", value=m.group(2)))
    return out


def _run_snmp_cli(cmd: Sequence[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(cmd),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def snmp_get(
    *,
    target: str,
    community: str,
    oids: Sequence[str],
    version: str = "2c",
    timeout_secs: float = 4.0,
    retries: int = 1,
    numeric: bool = True,
) -> List[SnmpVarBind]:
    args = [
        "snmpget", f"-v{version}", "-c", community,
        "-t", str(int(timeout_secs)), "-r", str(retries),
    ]
    if numeric:
        args.append("-On")
    args.append(target)
    args.extend(oids)
    result = _run_snmp_cli(args, timeout=timeout_secs * (retries + 1) + 3)
    if result.returncode != 0:
        raise SnmpCliError(result.returncode, result.stderr, result.stdout)
    return _parse_varbinds(result.stdout)


def snmp_getnext(*, target: str, community: str, oid: str, version: str = "2c",
                 timeout_secs: float = 4.0, retries: int = 1,
                 numeric: bool = True) -> SnmpVarBind:
    args = [
        "snmpgetnext", f"-v{version}", "-c", community,
        "-t", str(int(timeout_secs)), "-r", str(retries),
    ]
    if numeric:
        args.append("-On")
    args.extend([target, oid])
    result = _run_snmp_cli(args, timeout=timeout_secs * (retries + 1) + 3)
    if result.returncode != 0:
        raise SnmpCliError(result.returncode, result.stderr, result.stdout)
    vbs = _parse_varbinds(result.stdout)
    if not vbs:
        raise SnmpCliError(result.returncode, result.stderr, result.stdout)
    return vbs[0]


def snmp_bulkget(*, target: str, community: str, oid: str,
                 non_repeaters: int = 0, max_repetitions: int = 10,
                 timeout_secs: float = 4.0, retries: int = 1,
                 numeric: bool = True) -> List[SnmpVarBind]:
    args = [
        "snmpbulkget", "-v2c", "-c", community,
        f"-Cn{non_repeaters}", f"-Cr{max_repetitions}",
        "-t", str(int(timeout_secs)), "-r", str(retries),
    ]
    if numeric:
        args.append("-On")
    args.extend([target, oid])
    result = _run_snmp_cli(args, timeout=timeout_secs * (retries + 1) + 3)
    if result.returncode != 0:
        raise SnmpCliError(result.returncode, result.stderr, result.stdout)
    return _parse_varbinds(result.stdout)


def snmp_trap(*, target: str, community: str, trap_oid: str,
              varbinds: Optional[Sequence[tuple]] = None,
              version: str = "2c", timeout_secs: float = 3.0) -> None:
    """Send a SNMPv2c trap via net-snmp's snmptrap CLI.

    varbinds is a sequence of (oid, type_letter, value) — type_letter follows
    snmptrap's -y notation (s=string, i=integer, o=oid, a=ipaddr, ...).
    The mandatory uptime (OID 1.3.6.1.2.1.1.3.0) and trap-oid bindings are
    added automatically by snmptrap; we pass '' for uptime and the trap OID
    as the second positional arg.
    """
    args = ["snmptrap", f"-v{version}", "-c", community, target, "", trap_oid]
    for (oid, type_letter, value) in (varbinds or ()):
        args.extend([oid, type_letter, value])
    result = _run_snmp_cli(args, timeout=timeout_secs)
    if result.returncode != 0:
        raise SnmpCliError(result.returncode, result.stderr, result.stdout)


def snmp_inform(*, target: str, community: str, trap_oid: str,
                varbinds: Optional[Sequence[tuple]] = None,
                version: str = "2c", timeout_secs: float = 5.0,
                retries: int = 0) -> None:
    """Send an INFORM via net-snmp's snmpinform CLI. Same arg shape as
    snmp_trap. Unlike traps, INFORMs wait for a Response ack — if the
    receiver doesn't ack within the per-request timeout, snmpinform
    will either retry (retries > 0) or exit non-zero.

    This helper exists to prove the proxy acks INFORM senders; success
    here (returncode == 0) is the proof that the proxy delivered a
    Response back to us."""
    args = [
        "snmpinform", f"-v{version}", "-c", community,
        "-t", str(int(timeout_secs)), "-r", str(retries),
        target, "", trap_oid,
    ]
    for (oid, type_letter, value) in (varbinds or ()):
        args.extend([oid, type_letter, value])
    result = _run_snmp_cli(args, timeout=timeout_secs * (retries + 1) + 3)
    if result.returncode != 0:
        raise SnmpCliError(result.returncode, result.stderr, result.stdout)


def snmp_walk(*, target: str, community: str, oid: str, version: str = "2c",
              timeout_secs: float = 5.0, retries: int = 1,
              wall_timeout_secs: float = 60.0,
              numeric: bool = True) -> List[SnmpVarBind]:
    args = [
        "snmpwalk", f"-v{version}", "-c", community,
        "-t", str(int(timeout_secs)), "-r", str(retries),
    ]
    if numeric:
        args.append("-On")
    args.extend([target, oid])
    # snmpwalk issues many GETNEXTs; budget the whole run separately from the
    # per-query timeout that we pass as -t.
    result = _run_snmp_cli(args, timeout=wall_timeout_secs)
    if result.returncode != 0:
        raise SnmpCliError(result.returncode, result.stderr, result.stdout)
    return _parse_varbinds(result.stdout)


# ---------------------------------------------------------------------------
# Executable discovery


def which_or_none(cmd: str) -> Optional[str]:
    path = shutil.which(cmd)
    return path if path else None


def require_cli(cmd: str) -> str:
    """Return path to `cmd` on PATH, raising a useful error if absent."""
    path = which_or_none(cmd)
    if not path:
        raise RuntimeError(
            f"required command '{cmd}' not on PATH; install net-snmp / pysnmp-tooling"
        )
    return path


def find_snmpsim_cmd() -> Optional[str]:
    """Locate snmpsim-command-responder.

    Order:
      1. $SNMPSIM_CMD (explicit override)
      2. shutil.which('snmpsim-command-responder') on current PATH
      3. /tmp/snmpfwd-spike/bin/snmpsim-command-responder (spike venv, if present)
    """
    explicit = os.environ.get("SNMPSIM_CMD")
    if explicit and Path(explicit).is_file() and os.access(explicit, os.X_OK):
        return explicit
    on_path = shutil.which("snmpsim-command-responder")
    if on_path:
        return on_path
    fallback = Path("/tmp/snmpfwd-spike/bin/snmpsim-command-responder")
    if fallback.is_file() and os.access(fallback, os.X_OK):
        return str(fallback)
    return None
