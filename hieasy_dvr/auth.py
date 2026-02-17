"""
Authentication for HiEasy DVRs.

The DVR uses a proprietary DES-based hash for challenge-response login.
The algorithm was reverse-engineered from HieClientUnit.dll:

  1. DVR sends a nonce string via LoginGetFlagReply
  2. Client builds a 16-byte plaintext:
       block1 = sprintf("%8x", atoi(nonce) + 1)   (space-padded hex)
       block2 = sprintf("%8x", rand())             (any value works)
  3. Key = password[:8] zero-padded to 8 bytes
  4. Hash = DES_ECB_encrypt(key, block1) || DES_ECB_encrypt(key, block2)
  5. The 16-byte ciphertext is hex-encoded → 32-char LoginFlag

The DES variant is non-standard ("HiEasy DES"):
  - Bit extraction is LSB-first (not MSB-first)
  - S-box output bits are extracted LSB-first
  - No L/R swap before final permutation (FP applied to L||R)
  - All permutation tables are standard DES

Fallback oracle backends (DLL/Wine) are kept for reference but the
pure-Python implementation is now the primary method.
"""
import os
import sys
import socket
import struct
import threading
import re
import time
import subprocess
import logging
import random

from .protocol import (
    CMD_MAGIC, VERSION, HEADER_SIZE,
    make_xml,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pure-Python HiEasy DES implementation (reverse-engineered from DLL)
# ---------------------------------------------------------------------------

# Standard DES tables (verified against HieClientUnit.dll at 0x100E8610+)
_IP = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
       57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
_FP = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
       36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
_E = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
_P = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
_PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,
        63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]
_PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,
        41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]
_SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
_SBOXES = [
    [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
     4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
    [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
     0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
    [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
     13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
    [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
     10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
    [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
     4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
    [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
     9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
    [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
     1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
    [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
     7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
]


def _permute(bits, table):
    return [0] + [bits[table[i]] for i in range(len(table))]


def _left_shift(half, n):
    data = half[1:]
    return [0] + data[n:] + data[:n]


def _bytes_to_bits(data):
    """LSB-first: bit[1] = (byte[0] >> 0) & 1 (matching DLL at 0x10046125)."""
    bits = [0]
    for byte_val in data:
        for j in range(8):
            bits.append((byte_val >> j) & 1)
    return bits


def _bits_to_bytes(bits, start=1, count=64):
    """LSB-first packing (matching DLL bit_pack at 0x10046500)."""
    result = bytearray()
    for i in range(0, count, 8):
        v = 0
        for j in range(8):
            if bits[start + i + j]:
                v |= (1 << j)
        result.append(v)
    return bytes(result)


def _key_schedule(key_bytes):
    key_bits = _bytes_to_bits(key_bytes)
    pc1_bits = _permute(key_bits, _PC1)
    C = [0] + pc1_bits[1:29]
    D = [0] + pc1_bits[29:57]
    subkeys = []
    for r in range(16):
        C = _left_shift(C, _SHIFTS[r])
        D = _left_shift(D, _SHIFTS[r])
        CD = [0] + C[1:] + D[1:]
        subkeys.append(_permute(CD, _PC2))
    return subkeys


def _feistel(R, subkey):
    expanded = _permute(R, _E)
    xored = [0] + [expanded[i] ^ subkey[i] for i in range(1, 49)]
    sbox_out = [0]
    for i in range(8):
        b = xored[1 + i * 6: 1 + i * 6 + 6]
        row = (b[0] << 1) | b[5]
        col = (b[1] << 3) | (b[2] << 2) | (b[3] << 1) | b[4]
        val = _SBOXES[i][row * 16 + col]
        # LSB-first output (DLL sbox_substitute at 0x10046480)
        for j in range(4):
            sbox_out.append((val >> j) & 1)
    return _permute(sbox_out, _P)


def _des_block(key_bytes, pt_bytes):
    """Encrypt one 8-byte block using HiEasy's non-standard DES."""
    subkeys = _key_schedule(key_bytes)
    pt_bits = _bytes_to_bits(pt_bytes)
    ip_bits = _permute(pt_bits, _IP)
    L = [0] + ip_bits[1:33]
    R = [0] + ip_bits[33:65]
    for i in range(16):
        f = _feistel(R, subkeys[i])
        new_R = [0] + [L[j] ^ f[j] for j in range(1, 33)]
        L = R
        R = new_R
    # DLL applies FP to L||R (no swap) — confirmed via DES_block at 0x10045EC0
    combined = [0] + L[1:] + R[1:]
    fp_bits = _permute(combined, _FP)
    return _bits_to_bytes(fp_bits)


def _compute_hash_pure(flag_nonce, password):
    """
    Pure-Python hash computation matching HieClientUnit.dll exactly.
    Returns 32-char hex string.
    """
    nonce_int = int(flag_nonce)
    val1 = (nonce_int + 1) & 0xFFFFFFFF
    val2 = random.randint(0, 0x7FFF)
    block1 = ("%8x" % val1).encode('ascii')
    block2 = ("%8x" % val2).encode('ascii')
    key = password.encode('ascii')[:8].ljust(8, b'\x00')
    ct = _des_block(key, block1) + _des_block(key, block2)
    return ct.hex()


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
    Uses pure-Python DES (primary), with DLL/Wine oracle as fallback.
    Returns the hash string or None on failure.
    """
    # 1) Pure Python — no external dependencies needed
    try:
        h = _compute_hash_pure(flag_nonce, password)
        log.debug("Hash via pure Python DES: %s", h)
        return h
    except Exception as e:
        log.warning("Pure Python hash failed: %s", e)

    # 2) Try DLL directly (Windows)
    if sys.platform == 'win32':
        try:
            h = _oracle_via_dll(flag_nonce, username, password)
            if h:
                log.debug("Hash via DLL: %s", h)
                return h
        except Exception as e:
            log.debug("DLL oracle failed: %s", e)

    # 3) Try WSL2 interop
    if os.path.exists('/proc/sys/fs/binfmt_misc/WSLInterop'):
        h = _oracle_via_wsl_interop(flag_nonce, username, password)
        if h:
            log.debug("Hash via WSL interop: %s", h)
            return h

    # 4) Try Wine
    h = _oracle_via_wine(flag_nonce, username, password)
    if h:
        log.debug("Hash via Wine: %s", h)
        return h

    log.error("All hash backends failed")
    return None
