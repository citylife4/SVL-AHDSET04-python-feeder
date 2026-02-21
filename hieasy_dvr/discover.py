"""
DVR network discovery — scans the local subnet for HiEasy DVRs.

Uses parallel TCP connects to port 5050 to find candidate hosts quickly,
then sends a LoginGetFlag packet to confirm the responder is a real DVR.

Usage:
    from hieasy_dvr.discover import discover, resolve_dvr_host

    # Auto-discover DVR on the network
    ip = resolve_dvr_host()     # returns IP string or raises RuntimeError

    # Explicit subnet scan
    ips = discover('192.168.1.0/24')

    # Quick single-host check
    alive = probe_host('192.168.1.200')
"""

import os
import socket
import struct
import subprocess
import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

log = logging.getLogger('dvr.discover')

CMD_PORT    = 5050
TCP_TIMEOUT = 0.6   # seconds — tight enough for LAN, generous for Pi
MAX_WORKERS = 100   # parallel threads


def probe_host(ip: str, port: int = CMD_PORT, timeout: float = TCP_TIMEOUT) -> bool:
    """Return True if ip:port accepts a TCP connection in time."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_dvr(ip: str, port: int = CMD_PORT, timeout: float = 2.0) -> bool:
    """
    Send a LoginGetFlag command (ID=26) and confirm the reply is a DVR.
    Stronger check than plain TCP connect.
    """
    # Build a minimal LoginGetFlag header + body (same as auth.py)
    body = (b'<?xml version="1.0" encoding="GB2312"?>'
            b'<Command ID="26"><LoginGetFlagRequest UserName="probe"/></Command>\x00')
    body_len = len(body)
    # 36-byte header: magic, version, txn=26, 0, body_len, 3, 0, 0, 0
    header = struct.pack('>IIIIIIIII',
                         0x05011154, 0x00001001, 26,
                         0, body_len, 3, 0, 0, 0)
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.sendall(header + body)
            # Read at least the 36-byte reply header
            buf = b''
            s.settimeout(timeout)
            while len(buf) < 36:
                chunk = s.recv(256)
                if not chunk:
                    break
                buf += chunk
            if len(buf) < 36:
                return False
            magic = struct.unpack('>I', buf[0:4])[0]
            # DVR replies with same CMD magic and LoginGetFlagReply (ID=27)
            return magic == 0x05011154
    except OSError:
        return False


def _derive_subnet(host: str) -> str | None:
    """Derive the /24 subnet from a host IP string."""
    try:
        net = ipaddress.IPv4Network(f'{host}/24', strict=False)
        return str(net)
    except ValueError:
        return None


def _get_local_subnets() -> list[str]:
    """Detect local /24 subnets from the host's network interfaces."""
    subnets = []
    try:
        out = subprocess.check_output(
            ['ip', '-4', '-o', 'addr', 'show'],
            timeout=5, text=True, stderr=subprocess.DEVNULL,
        )
        for line in out.splitlines():
            # e.g. "2: eth0  inet 192.168.1.81/24 brd ..."
            parts = line.split()
            for i, tok in enumerate(parts):
                if tok == 'inet' and i + 1 < len(parts):
                    cidr = parts[i + 1]         # "192.168.1.81/24"
                    try:
                        iface = ipaddress.IPv4Interface(cidr)
                        net = iface.network
                        # Skip loopback and link-local
                        if net.is_loopback or net.is_link_local:
                            continue
                        # Only scan reasonably-sized subnets (≤ /16)
                        if net.prefixlen < 16:
                            net = ipaddress.IPv4Network(
                                f'{iface.ip}/24', strict=False)
                        s = str(net)
                        if s not in subnets:
                            subnets.append(s)
                    except ValueError:
                        pass
                    break
    except (subprocess.SubprocessError, OSError):
        pass
    return subnets


def discover(subnet: str | None = None,
             timeout: float = TCP_TIMEOUT,
             confirm: bool = True) -> list[str]:
    """
    Scan a subnet for DVRs listening on port 5050.

    Parameters
    ----------
    subnet  : CIDR string like '192.168.1.0/24'. If None, derived from
              DVR_HOST environment variable, then from the host's actual
              network interfaces.  Falls back to common private subnets.
    timeout : TCP connect timeout per host (seconds).
    confirm : If True, send a real LoginGetFlag to verify the responder is
              a HiEasy DVR (not just anything listening on 5050).

    Returns
    -------
    Sorted list of IP strings where a DVR was found.
    """
    # Resolve the subnet to scan
    if subnet is None:
        host = os.environ.get('DVR_HOST', '').strip()
        # Skip placeholders
        if host and host not in ('auto', '0.0.0.0'):
            subnet = _derive_subnet(host)
    
    if subnet:
        subnets_to_scan = [subnet]
    else:
        # Detect actual local subnets from network interfaces
        subnets_to_scan = _get_local_subnets()
        if not subnets_to_scan:
            # Last resort: common private /24 subnets
            subnets_to_scan = [
                '192.168.1.0/24',
                '192.168.0.0/24',
                '10.0.0.0/24',
            ]

    targets: list[str] = []
    for s in subnets_to_scan:
        try:
            net = ipaddress.IPv4Network(s, strict=False)
            targets.extend(str(h) for h in net.hosts())
        except ValueError:
            log.warning('Invalid subnet %s', s)

    if not targets:
        return []

    log.info('Probing %d hosts on %s ...', len(targets), ', '.join(subnets_to_scan))

    # Phase 1: fast TCP connect scan
    candidates: list[str] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futs = {pool.submit(probe_host, ip, CMD_PORT, timeout): ip
                for ip in targets}
        for fut in as_completed(futs):
            ip = futs[fut]
            try:
                if fut.result():
                    candidates.append(ip)
            except Exception:
                pass

    log.info('Phase-1 candidates (port 5050 open): %s', candidates)

    if not candidates:
        return []

    if not confirm:
        return sorted(candidates)

    # Phase 2: send LoginGetFlag to confirm HiEasy DVR
    dvrs: list[str] = []
    with ThreadPoolExecutor(max_workers=min(len(candidates), 8)) as pool:
        futs = {pool.submit(probe_dvr, ip, CMD_PORT, 2.0): ip
                for ip in candidates}
        for fut in as_completed(futs):
            ip = futs[fut]
            try:
                if fut.result():
                    dvrs.append(ip)
                    log.info('DVR confirmed at %s', ip)
            except Exception:
                pass

    return sorted(dvrs)


def resolve_dvr_host(env_host: str | None = None) -> str:
    """
    Return a reachable DVR IP address.

    Resolution order:
      1. *env_host* argument (or ``DVR_HOST`` env var) — if it's a valid IP
         and the DVR responds on port 5050, return it immediately.
      2. Network scan — discover DVRs on local subnets.
      3. Raise ``RuntimeError`` if nothing is found.

    When a DVR is found via scan, ``DVR_HOST`` is updated in the process
    environment so subsequent calls are instant.
    """
    host = env_host or os.environ.get('DVR_HOST', '').strip()

    # Skip placeholders
    if host in ('', 'auto', '0.0.0.0'):
        host = ''

    # Fast path: configured IP is still reachable
    if host:
        if probe_host(host, CMD_PORT, timeout=2.0):
            return host
        log.info('DVR_HOST %s unreachable — scanning network...', host)

    # Scan
    found = discover(timeout=TCP_TIMEOUT, confirm=True)
    if not found:
        raise RuntimeError(
            'No DVR found on the local network. '
            'Set DVR_HOST to the DVR IP address or ensure the DVR is powered on.')

    new_ip = found[0]
    log.info('DVR discovered at %s', new_ip)
    os.environ['DVR_HOST'] = new_ip
    return new_ip
