"""
Wine oracle helper — runs under 32-bit Windows Python via Wine.

Called as: python.exe _wine_oracle.py <nonce> <username> <password>
Outputs:   HASH=<32-char hex hash>

This script loads HieClientUnit.dll, starts a fake DVR server on
localhost:15050, runs the SDK login, and captures the computed hash.
"""
import sys
import os
import socket
import struct
import threading
import re
import time
import ctypes

CMD_MAGIC = 0x05011154
VERSION = 0x00001001
HDR_SIZE = 36
PORT = 15050

captured_hash = [None]


def make_xml(cmd_id, inner):
    xml = (
        '<?xml version="1.0" encoding="GB2312" standalone="yes" ?>\n'
        '<Command ID="{}">\n'
        '    {}\n'
        '</Command>\n'
    ).format(cmd_id, inner)
    return xml.encode('utf-8') + b'\x00'


def handle_client(conn, nonce):
    buf = b''
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            buf += data
            while len(buf) >= HDR_SIZE:
                if struct.unpack('>I', buf[:4])[0] != CMD_MAGIC:
                    buf = buf[1:]
                    continue
                hdr = struct.unpack('>IIIIIIIII', buf[:HDR_SIZE])
                blen = hdr[4]
                if len(buf) < HDR_SIZE + blen:
                    break
                body = buf[HDR_SIZE:HDR_SIZE + blen].decode('utf-8', 'replace').rstrip('\x00')
                buf = buf[HDR_SIZE + blen:]

                def reply_hdr(r):
                    return struct.pack('>IIIIIIIII', CMD_MAGIC, VERSION, hdr[2], 0, len(r), 3, 0, 0, 0)

                if 'LoginGetFlag' in body and 'Reply' not in body:
                    r = make_xml(27, '<LoginGetFlagReply LoginFlag="{}" Ret="-1" />'.format(nonce))
                    conn.sendall(reply_hdr(r) + r)
                elif 'UserLogin' in body and 'Reply' not in body:
                    m = re.search(r'LoginFlag="([^"]*)"', body)
                    if m:
                        captured_hash[0] = m.group(1)
                    r = make_xml(25,
                        '<UserLoginReply CmdReply="0" TCPPort="6050" RTPPort="7050" CmdPort="5050" '
                        'LoginFlagClient="99"><RemoteReboot Major="1" Minor="1" Revision="0" /></UserLoginReply>')
                    conn.sendall(reply_hdr(r) + r)
                elif 'Logout' in body:
                    r = make_xml(29, '<LogoutReply CmdReply="0" />')
                    conn.sendall(reply_hdr(r) + r)
                    return
    except Exception:
        pass
    finally:
        conn.close()


def main():
    if len(sys.argv) < 4:
        print("Usage: python.exe _wine_oracle.py <nonce> <username> <password>", file=sys.stderr)
        sys.exit(1)

    nonce = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]

    # Start fake server
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.settimeout(15)
    srv.bind(('127.0.0.1', PORT))
    srv.listen(5)

    stop = threading.Event()

    def accept_loop():
        while not stop.is_set():
            try:
                c, _ = srv.accept()
                threading.Thread(target=handle_client, args=(c, nonce), daemon=True).start()
            except Exception:
                break

    threading.Thread(target=accept_loop, daemon=True).start()
    time.sleep(0.3)

    # Load DLL and login
    sdk_dir = os.path.dirname(os.path.abspath(__file__))
    dll_path = os.path.join(sdk_dir, 'HieClientUnit.dll')
    if not os.path.exists(dll_path):
        # Try parent directory
        dll_path = os.path.join(os.path.dirname(sdk_dir), 'HieClientUnit.dll')

    dll = ctypes.CDLL(dll_path)
    dll.HieClient_Start()

    info = ctypes.create_string_buffer(0x200)
    ctypes.memmove(ctypes.addressof(info), b'127.0.0.1\x00', 10)
    struct.pack_into('<I', info, 0x100, PORT)
    ctypes.memmove(ctypes.addressof(info) + 0x104, username.encode() + b'\x00', len(username) + 1)
    ctypes.memmove(ctypes.addressof(info) + 0x124, password.encode() + b'\x00', len(password) + 1)

    handle = ctypes.c_int(-1)
    dll.HieClient_UserLogin(ctypes.byref(handle), ctypes.byref(info))
    if handle.value >= 0:
        dll.HieClient_UserLogout(handle)

    time.sleep(0.5)
    stop.set()
    srv.close()
    dll.HieClient_Stop()

    if captured_hash[0]:
        print("HASH={}".format(captured_hash[0]))
    else:
        print("HASH_FAILED", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
