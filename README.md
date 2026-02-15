# HiEasy DVR RTSP Bridge

Connects to SVL-AHDSET04 (and similar HiEasy Technology DVRs) and re-publishes
the camera streams as standard RTSP using [mediamtx](https://github.com/bluenviron/mediamtx).

Designed to run on a **Raspberry Pi** on the same LAN as the DVR.

## Architecture

```
DVR (192.168.1.174)          Raspberry Pi                    Clients
┌─────────────┐       ┌──────────────────────┐       ┌─────────────────┐
│  Port 5050  │◄─────►│  dvr_feeder.py       │       │  VLC / ffplay   │
│  (Command)  │       │       │ stdout        │       │  or any RTSP    │
│             │       │       ▼               │       │  player         │
│  Port 6050  │◄─────►│  ffmpeg ─► mediamtx  │◄─────►│                 │
│  (Media)    │       │        RTSP :8554     │       │ rtsp://pi:8554/ │
└─────────────┘       └──────────────────────┘       └─────────────────┘
```

## Quick Deploy

```bash
./deploy.sh pi@<raspberry-pi-ip>
```

This will:
1. Install system dependencies (Python 3, ffmpeg, Wine + QEMU)
2. Download mediamtx (auto-detects ARM architecture)
3. Copy all application files
4. Copy SDK DLL files (for hash oracle authentication)
5. Install and enable the systemd service

## Manual Usage

**Stream one channel to file:**
```bash
python3 dvr_feeder.py --channel 0 | ffmpeg -f h264 -i pipe:0 -c copy out.mp4
```

**Stream to RTSP (requires mediamtx running):**
```bash
python3 dvr_feeder.py --channel 0 | \
  ffmpeg -f h264 -i pipe:0 -c copy -f rtsp rtsp://localhost:8554/ch0
```

**Stream all channels:**
```bash
python3 dvr_rtsp_bridge.py
```

## RTSP Streams

Once running, streams are available at:
- `rtsp://<pi-ip>:8554/ch0` — Channel 0
- `rtsp://<pi-ip>:8554/ch1` — Channel 1
- `rtsp://<pi-ip>:8554/ch2` — Channel 2
- `rtsp://<pi-ip>:8554/ch3` — Channel 3

Streams start **on-demand** — the DVR connection is only made when a client connects.

## Configuration

Environment variables (also set in the systemd service):

| Variable | Default | Description |
|---|---|---|
| `DVR_HOST` | `192.168.1.174` | DVR IP address |
| `DVR_CMD_PORT` | `5050` | Command port |
| `DVR_MEDIA_PORT` | `6050` | Media port |
| `DVR_USERNAME` | `admin` | Username |
| `DVR_PASSWORD` | `123456` | Password |
| `HIEASY_SDK_DIR` | `/opt/dvr/sdk` | SDK DLL directory (for hash oracle) |

## Authentication

The DVR uses a proprietary hash algorithm (not MD5) implemented in `HieClientUnit.dll`.
Since the algorithm hasn't been reverse-engineered, authentication uses a "hash oracle"
that runs the DLL via:
- **WSL2 interop** (when running on WSL)
- **Wine + QEMU** (when running on ARM Linux / Raspberry Pi)

## Project Structure

```
hieasy_dvr/             Python package
├── __init__.py
├── protocol.py         Wire protocol (36-byte headers, XML commands)
├── auth.py             Hash oracle authentication
├── client.py           DVRClient class
├── stream.py           H.264 frame parser
└── _wine_oracle.py     Wine/WSL helper for hash computation

dvr_feeder.py           Single-channel H.264 feeder (stdout)
dvr_rtsp_bridge.py      Multi-channel RTSP bridge
mediamtx.yml            mediamtx RTSP server config
dvr-rtsp.service        systemd service unit
deploy.sh               One-command Pi deployment script
```

## Requirements

- Python 3.8+
- ffmpeg
- mediamtx (downloaded by deploy.sh)
- Wine + QEMU-user-static (for ARM — installed by deploy.sh)

## Video Specs

- Codec: H.264 Baseline
- Resolution: 1920×1080
- Frame rate: 25 fps
- Color: YUV420P
