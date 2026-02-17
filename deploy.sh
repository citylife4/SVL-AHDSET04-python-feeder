#!/bin/bash
#
# deploy.sh — Deploy DVR RTSP Bridge to Raspberry Pi
#
# Usage:
#   ./deploy.sh pi@192.168.1.XXX
#
# Prerequisites on Pi:
#   - Raspberry Pi OS (64-bit recommended)
#   - SSH access
#   - Internet connection (for package downloads)
#
set -euo pipefail

PI_HOST="${1:?Usage: $0 pi@hostname}"
DEPLOY_DIR="/opt/dvr"
MEDIAMTX_VERSION="1.11.3"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== DVR RTSP Bridge Deployment ==="
echo "Target: $PI_HOST"
echo "Deploy dir: $DEPLOY_DIR"
echo ""

# Detect Pi architecture
ARCH=$(ssh "$PI_HOST" "uname -m")
echo "Pi architecture: $ARCH"

case "$ARCH" in
    aarch64) MEDIAMTX_ARCH="linux_arm64v8" ;;
    armv7l)  MEDIAMTX_ARCH="linux_armv7" ;;
    armv6l)  MEDIAMTX_ARCH="linux_armv6" ;;
    x86_64)  MEDIAMTX_ARCH="linux_amd64" ;;
    *)       echo "ERROR: Unsupported architecture: $ARCH"; exit 1 ;;
esac

echo ""
echo "--- Step 1: Install system dependencies ---"
ssh "$PI_HOST" "sudo apt-get update -qq && sudo apt-get install -y -qq \
    python3 python3-pip ffmpeg"

echo ""
echo "--- Step 2: Create deploy directory ---"
ssh "$PI_HOST" "sudo mkdir -p $DEPLOY_DIR/hieasy_dvr && \
    sudo chown -R \$(whoami):\$(whoami) $DEPLOY_DIR"

echo ""
echo "--- Step 3: Download mediamtx ---"
MEDIAMTX_URL="https://github.com/bluenviron/mediamtx/releases/download/v${MEDIAMTX_VERSION}/mediamtx_v${MEDIAMTX_VERSION}_${MEDIAMTX_ARCH}.tar.gz"
echo "Downloading: $MEDIAMTX_URL"
ssh "$PI_HOST" "cd $DEPLOY_DIR && \
    curl -sL '$MEDIAMTX_URL' | tar xz mediamtx && \
    chmod +x mediamtx"

echo ""
echo "--- Step 4: Copy application files ---"
# Python package
scp -r "$SCRIPT_DIR/hieasy_dvr/"*.py "$PI_HOST:$DEPLOY_DIR/hieasy_dvr/"

# Feeder + bridge scripts
scp "$SCRIPT_DIR/dvr_feeder.py" "$PI_HOST:$DEPLOY_DIR/"
scp "$SCRIPT_DIR/dvr_rtsp_bridge.py" "$PI_HOST:$DEPLOY_DIR/"

# mediamtx config
scp "$SCRIPT_DIR/mediamtx.yml" "$PI_HOST:$DEPLOY_DIR/"

echo ""
echo "--- Step 5: Install systemd service ---"
scp "$SCRIPT_DIR/dvr-rtsp.service" "$PI_HOST:/tmp/dvr-rtsp.service"
ssh "$PI_HOST" "
    # Create service user if needed
    sudo useradd -r -s /usr/sbin/nologin -d $DEPLOY_DIR dvr 2>/dev/null || true
    sudo chown -R dvr:dvr $DEPLOY_DIR

    # Install service
    sudo mv /tmp/dvr-rtsp.service /etc/systemd/system/dvr-rtsp.service
    sudo systemctl daemon-reload
    sudo systemctl enable dvr-rtsp.service
"

echo ""
echo "--- Step 6: Test basic connectivity ---"
ssh "$PI_HOST" "
    cd $DEPLOY_DIR
    echo 'Testing mediamtx binary...'
    ./mediamtx --help > /dev/null 2>&1 && echo '  mediamtx: OK' || echo '  mediamtx: FAILED'

    echo 'Testing ffmpeg...'
    ffmpeg -version 2>/dev/null | head -1 || echo '  ffmpeg: NOT FOUND'

    echo 'Testing Python...'
    python3 -c 'import socket, struct, threading; print(\"  python3: OK\")'

    echo 'Testing DVR connectivity...'
    python3 -c \"
import socket
s = socket.socket()
s.settimeout(3)
try:
    s.connect(('192.168.1.174', 5050))
    print('  DVR port 5050: REACHABLE')
    s.close()
except:
    print('  DVR port 5050: NOT REACHABLE — check network')
\"
"

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "To start the service:"
echo "  ssh $PI_HOST 'sudo systemctl start dvr-rtsp'"
echo ""
echo "To check status:"
echo "  ssh $PI_HOST 'sudo systemctl status dvr-rtsp'"
echo "  ssh $PI_HOST 'sudo journalctl -u dvr-rtsp -f'"
echo ""
echo "To test RTSP streams:"
echo "  ffplay rtsp://<pi-ip>:8554/ch0"
echo "  vlc rtsp://<pi-ip>:8554/ch0"
echo ""
echo "Available streams:"
echo "  rtsp://<pi-ip>:8554/ch0  (Channel 0)"
echo "  rtsp://<pi-ip>:8554/ch1  (Channel 1)"
echo "  rtsp://<pi-ip>:8554/ch2  (Channel 2)"
echo "  rtsp://<pi-ip>:8554/ch3  (Channel 3)"
