"""
Authentication for HiEasy DVRs.

The DVR uses a proprietary hash (NOT MD5) that is implemented inside
HieClientUnit.dll. Until the algorithm is reverse-engineered, we use
the DLL as a "hash oracle" on platforms where it's available:

  - Windows x86/x64: load DLL directly via ctypes
  - Linux x86_64:    use Wine to run 32-bit Python + DLL
  - Linux ARM (Pi):  use Wine + QEMU-user-static (binfmt_misc)

The hash oracle works by:
  1. Starting a fake DVR server on localhost
  2. Feeding the real DVR's nonce to the fake server
  3. Running the SDK login against the fake server
  4. Capturing the hash the SDK computes from the nonce + password
"""
import socket
import struct
import threading
import re
import time
import os
import sys
import subprocess
import logging

from .protocol import (
    CMD_MAGIC, VERSION, HEADER_SIZE,
    make_xml,
)

log = logging.getLogger(__name__)

ORACLE_PORT = 15050  # Localhost port for fake DVR server

# ---------------------------------------------------------------------------
# Fake DVR server (handles SDK login and captures the computed hash)
# ---------------------------------------------------------------------------

_captured_hash = [None]


def _handle_sdk_client(conn, flag_nonce):
    """Handle one SDK connection to the fake DVR server."""
    buf = b''
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            buf += data
            while len(buf) >= HEADER_SIZE:
                if struct.unpack('>I', buf[:4])[0] != CMD_MAGIC:
                    buf = buf[1:]
                    continue
                hdr = struct.unpack('>IIIIIIIII', buf[:HEADER_SIZE])
                cmd, blen = hdr[2], hdr[4]
                if len(buf) < HEADER_SIZE + blen:
                    break
                body = buf[HEADER_SIZE:HEADER_SIZE + blen].decode(
                    'utf-8', errors='replace'
                ).rstrip('\x00')
                buf = buf[HEADER_SIZE + blen:]

                reply_hdr = lambda r: struct.pack(
                    '>IIIIIIIII',
                    CMD_MAGIC, VERSION, cmd, 0, len(r), 3, 0, 0, 0
                )

                if 'LoginGetFlag' in body and 'Reply' not in body:
                    r = make_xml(
                        27,
                        '<LoginGetFlagReply LoginFlag="{}" Ret="-1" />'.format(
                            flag_nonce
                        ),
                    )
                    conn.sendall(reply_hdr(r) + r)

                elif 'UserLogin' in body and 'Reply' not in body:
                    m = re.search(r'LoginFlag="([^"]*)"', body)
                    if m:
                        _captured_hash[0] = m.group(1)
                    r = make_xml(
                        25,
                        '<UserLoginReply CmdReply="0" TCPPort="6050" '
                        'RTPPort="7050" CmdPort="5050" '
                        'LoginFlagClient="99">'
                        '<RemoteReboot Major="1" Minor="1" Revision="0" />'
                        '</UserLoginReply>',
                    )
                    conn.sendall(reply_hdr(r) + r)

                elif 'Logout' in body:
                    r = make_xml(29, '<LogoutReply CmdReply="0" />')
                    conn.sendall(reply_hdr(r) + r)
                    return
    except Exception:
        pass
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Hash oracle backends
# ---------------------------------------------------------------------------

def _oracle_via_dll(flag_nonce, username, password):
    """Use the DLL directly (Windows only)."""
    import ctypes

    sdk_dir = os.environ.get(
        'HIEASY_SDK_DIR', r'C:\temp\dvr_tools'
    )
    os.add_dll_directory(sdk_dir)

    _captured_hash[0] = None
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.settimeout(15)
    srv.bind(('127.0.0.1', ORACLE_PORT))
    srv.listen(5)

    stop = threading.Event()

    def accept_loop():
        while not stop.is_set():
            try:
                c, _ = srv.accept()
                threading.Thread(
                    target=_handle_sdk_client,
                    args=(c, flag_nonce),
                    daemon=True,
                ).start()
            except Exception:
                break

    threading.Thread(target=accept_loop, daemon=True).start()
    time.sleep(0.3)

    dll = ctypes.CDLL(os.path.join(sdk_dir, 'HieClientUnit.dll'))
    dll.HieClient_Start()

    info = ctypes.create_string_buffer(0x200)
    ctypes.memmove(ctypes.addressof(info), b'127.0.0.1\x00', 10)
    struct.pack_into('<I', info, 0x100, ORACLE_PORT)
    ctypes.memmove(
        ctypes.addressof(info) + 0x104,
        username.encode() + b'\x00',
        len(username) + 1,
    )
    ctypes.memmove(
        ctypes.addressof(info) + 0x124,
        password.encode() + b'\x00',
        len(password) + 1,
    )

    handle = ctypes.c_int(-1)
    dll.HieClient_UserLogin(ctypes.byref(handle), ctypes.byref(info))
    if handle.value >= 0:
        dll.HieClient_UserLogout(handle)

    time.sleep(0.5)
    stop.set()
    srv.close()
    dll.HieClient_Stop()
    time.sleep(0.3)

    return _captured_hash[0]


def _oracle_via_wine(flag_nonce, username, password):
    """
    Use Wine (+ optional QEMU on ARM) to run the hash oracle.
    Requires: wine, py32/python.exe, HieClientUnit.dll
    """
    sdk_dir = os.environ.get('HIEASY_SDK_DIR', '/opt/dvr/sdk')
    helper = os.path.join(os.path.dirname(__file__), '_wine_oracle.py')

    # Build the wine command
    wine_python = os.path.join(sdk_dir, 'py32', 'python.exe')
    env = os.environ.copy()
    env['WINEPREFIX'] = os.path.expanduser('~/.wine-dvr')
    env['WINEDEBUG'] = '-all'

    try:
        result = subprocess.run(
            ['wine', wine_python, helper, flag_nonce, username, password],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
            cwd=sdk_dir,
        )
        for line in result.stdout.strip().splitlines():
            if line.startswith('HASH='):
                return line[5:].strip()
    except FileNotFoundError:
        log.error("Wine not found. Install with: sudo apt install wine")
    except subprocess.TimeoutExpired:
        log.error("Wine hash oracle timed out")
    except Exception as e:
        log.error("Wine oracle error: %s", e)

    return None


def _wsl_to_win_path(linux_path):
    """Convert WSL /mnt/c/... path to Windows C:\\... path."""
    try:
        result = subprocess.run(
            ['wslpath', '-w', linux_path],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    # Fallback: manual conversion for /mnt/X/...
    if linux_path.startswith('/mnt/') and len(linux_path) > 6:
        drive = linux_path[5].upper()
        rest = linux_path[6:].replace('/', '\\')
        return '{}:{}'.format(drive, rest)
    return linux_path


def _oracle_via_wsl_interop(flag_nonce, username, password):
    """
    Use WSL2 Windows interop (py32/python.exe runs natively on WSL2).
    This is the primary method when running on WSL2.
    """
    sdk_dir = os.environ.get('HIEASY_SDK_DIR', '/mnt/c/temp/dvr_tools')
    helper = os.path.join(sdk_dir, '_wine_oracle.py')

    # On WSL2, Windows executables run natively
    python_exe = os.path.join(sdk_dir, 'py32', 'python.exe')

    if not os.path.exists(python_exe):
        return None

    # Windows Python needs Windows-style paths
    win_helper = _wsl_to_win_path(helper)

    try:
        result = subprocess.run(
            [python_exe, win_helper, flag_nonce, username, password],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=sdk_dir,
        )
        log.debug("WSL oracle stdout: %s", result.stdout[:200])
        if result.stderr:
            log.debug("WSL oracle stderr: %s", result.stderr[:200])
        for line in result.stdout.strip().splitlines():
            if line.startswith('HASH='):
                return line[5:].strip()
    except Exception as e:
        log.error("WSL interop oracle error: %s", e)

    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_hash(flag_nonce, username='admin', password='123456'):
    """
    Compute the login hash for a given nonce.
    Tries backends in order: DLL direct → WSL interop → Wine.
    Returns the hash string or None on failure.
    """
    # 1) Try DLL directly (Windows)
    if sys.platform == 'win32':
        try:
            h = _oracle_via_dll(flag_nonce, username, password)
            if h:
                log.debug("Hash via DLL: %s", h)
                return h
        except Exception as e:
            log.debug("DLL oracle failed: %s", e)

    # 2) Try WSL2 interop
    if os.path.exists('/proc/sys/fs/binfmt_misc/WSLInterop'):
        h = _oracle_via_wsl_interop(flag_nonce, username, password)
        if h:
            log.debug("Hash via WSL interop: %s", h)
            return h

    # 3) Try Wine
    h = _oracle_via_wine(flag_nonce, username, password)
    if h:
        log.debug("Hash via Wine: %s", h)
        return h

    log.error("All hash oracle backends failed")
    return None
