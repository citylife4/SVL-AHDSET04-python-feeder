#!/usr/bin/env python3
"""
DVR RTSP Bridge — runs dvr_feeder + ffmpeg for each channel,
publishing to mediamtx.

Can be used standalone (without mediamtx runOnDemand) to keep
all channels streaming continuously.

Usage:
  python3 dvr_rtsp_bridge.py                    # All 4 channels
  python3 dvr_rtsp_bridge.py --channels 0 2     # Only ch0 and ch2
  python3 dvr_rtsp_bridge.py --rtsp-url rtsp://localhost:8554
"""
import subprocess
import signal
import sys
import os
import time
import argparse
import logging

log = logging.getLogger('dvr_rtsp_bridge')

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def start_channel(channel, rtsp_base, stream_type=1, verbose=False):
    """Start dvr_feeder | ffmpeg pipeline for one channel."""
    feeder_cmd = [
        sys.executable, os.path.join(SCRIPT_DIR, 'dvr_feeder.py'),
        '--channel', str(channel),
        '--stream-type', str(stream_type),
    ]
    if verbose:
        feeder_cmd.append('-v')

    ffmpeg_cmd = [
        'ffmpeg',
        '-hide_banner', '-loglevel', 'warning',
        '-f', 'h264',
        '-i', 'pipe:0',
        '-c', 'copy',
        '-f', 'rtsp',
        '-rtsp_transport', 'tcp',
        '{}/ch{}'.format(rtsp_base, channel),
    ]

    log.info("Starting channel %d: %s | %s", channel,
             ' '.join(feeder_cmd), ' '.join(ffmpeg_cmd))

    feeder = subprocess.Popen(
        feeder_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE if not verbose else None,
    )
    ffmpeg = subprocess.Popen(
        ffmpeg_cmd,
        stdin=feeder.stdout,
        stderr=subprocess.PIPE if not verbose else None,
    )
    # Allow feeder to receive SIGPIPE if ffmpeg dies
    feeder.stdout.close()

    return feeder, ffmpeg


def main():
    parser = argparse.ArgumentParser(description='DVR RTSP Bridge')
    parser.add_argument('--channels', type=int, nargs='+', default=[0, 1, 2, 3],
                        help='Channel numbers to stream (default: 0 1 2 3)')
    parser.add_argument('--rtsp-url', default='rtsp://localhost:8554',
                        help='mediamtx RTSP base URL')
    parser.add_argument('--stream-type', type=int, default=1,
                        help='1=main stream, 2=sub stream')
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s %(name)s %(levelname)s %(message)s',
    )

    processes = {}
    for ch in args.channels:
        feeder, ffmpeg = start_channel(
            ch, args.rtsp_url, args.stream_type, args.verbose
        )
        processes[ch] = (feeder, ffmpeg)
        time.sleep(2)  # Stagger connections to avoid DVR overload

    def shutdown(sig, frame):
        log.info("Shutting down all channels...")
        for ch, (feeder, ffmpeg) in processes.items():
            for p in (feeder, ffmpeg):
                try:
                    p.terminate()
                except Exception:
                    pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    log.info("All channels started. Monitoring...")

    # Monitor and restart failed channels
    while True:
        for ch in list(processes.keys()):
            feeder, ffmpeg = processes[ch]
            if feeder.poll() is not None or ffmpeg.poll() is not None:
                log.warning("Channel %d died (feeder=%s, ffmpeg=%s), restarting...",
                            ch, feeder.poll(), ffmpeg.poll())
                for p in (feeder, ffmpeg):
                    try:
                        p.terminate()
                    except Exception:
                        pass
                time.sleep(3)
                feeder, ffmpeg = start_channel(
                    ch, args.rtsp_url, args.stream_type, args.verbose
                )
                processes[ch] = (feeder, ffmpeg)
        time.sleep(5)


if __name__ == '__main__':
    main()
