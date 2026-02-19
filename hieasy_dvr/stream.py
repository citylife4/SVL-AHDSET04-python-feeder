"""
H.264 stream parser for HiEasy DVR media frames.

Media frame structure:
  [36-byte media header][44-byte sub-header][payload: F3 bytes]

The 36-byte media header uses MEDIA_MAGIC and field[3] = payload size.
The 44-byte sub-header contains timestamp, codec info, frame counter.
The payload starts with a vendor NAL prefix (000001c7, 22 bytes)
followed by standard H.264 NAL units with 4-byte start codes.
"""
import struct
import socket
import logging

from .protocol import MEDIA_MAGIC

log = logging.getLogger(__name__)

SUB_HEADER_SIZE = 44


def extract_h264(payload):
    """
    Extract clean H.264 NAL units from a media payload.
    Skips the vendor-specific prefix (000001c6/c7 NALs) and filters out
    any non-standard NAL types to avoid crashes in downstream consumers.
    Returns bytes of H.264 data starting from the first standard NAL.
    """
    # Valid H264 NAL types (1-12 are standard, 24-31 are RTP extensions)
    # We accept types 1-12 (VCL + parameter sets) and skip vendor types
    VENDOR_NAL_TYPES = {0xC6, 0xC7}

    # Find ALL 4-byte NAL start codes and filter to valid H.264 only
    out_parts = []
    sc4 = b'\x00\x00\x00\x01'
    pos = 0
    while True:
        idx = payload.find(sc4, pos)
        if idx < 0:
            break
        # Find the end of this NAL (next start code or end of payload)
        next_idx = payload.find(sc4, idx + 4)
        if next_idx < 0:
            nal_data = payload[idx:]
        else:
            nal_data = payload[idx:next_idx]

        # Check the NAL type byte (first byte after start code, lower 5 bits)
        if len(nal_data) > 4:
            nal_type = nal_data[4] & 0x1F
            full_byte = nal_data[4]
            # Skip vendor NAL types and empty/forbidden NALs
            if full_byte not in VENDOR_NAL_TYPES and nal_type != 0 and len(nal_data) > 5:
                out_parts.append(nal_data)

        pos = (next_idx if next_idx >= 0 else len(payload))

    if out_parts:
        return b''.join(out_parts)

    # Fallback: find 3-byte start codes, skip vendor NALs
    pos = 0
    while pos < len(payload) - 3:
        if payload[pos:pos + 3] == b'\x00\x00\x01':
            if pos + 3 < len(payload) and payload[pos + 3] not in VENDOR_NAL_TYPES:
                return b'\x00' + payload[pos:]  # Promote to 4-byte start code
            pos += 4
        else:
            pos += 1

    return b''


def iter_frames(sock, timeout=5):
    """
    Generator yielding (frame_type, h264_bytes) tuples from a media socket.

    frame_type: int from sub-header (3 = H.264 video)
    h264_bytes: extracted H.264 data for this frame

    Raises StopIteration when the socket closes or times out repeatedly.
    """
    buf = b''
    consecutive_timeouts = 0
    max_timeouts = 3

    while True:
        try:
            sock.settimeout(timeout)
            chunk = sock.recv(65536)
            if not chunk:
                log.info("Media socket closed")
                return
            buf += chunk
            consecutive_timeouts = 0
        except socket.timeout:
            consecutive_timeouts += 1
            if consecutive_timeouts >= max_timeouts:
                log.warning("Media socket timed out %d times consecutively", max_timeouts)
                return
            continue
        except OSError as e:
            log.error("Media socket error: %s", e)
            return

        # Parse complete frames from buffer
        while len(buf) >= 80:  # 36 header + 44 sub-header minimum
            magic = struct.unpack('>I', buf[:4])[0]
            if magic != MEDIA_MAGIC:
                buf = buf[1:]
                continue

            hdr = struct.unpack('>IIIIIIIII', buf[:36])
            payload_size = hdr[3]
            total = 36 + SUB_HEADER_SIZE + payload_size

            if len(buf) < total:
                break  # Need more data

            if payload_size > 0:
                payload = buf[80:80 + payload_size]

                # Parse sub-header for frame type (codec)
                # at offset 36+32 = 68: 4 bytes codec type (3 = H.264)
                codec = struct.unpack('>I', buf[68:72])[0] if len(buf) >= 72 else 0

                h264 = extract_h264(payload)
                if h264:
                    yield codec, h264

            buf = buf[total:]
