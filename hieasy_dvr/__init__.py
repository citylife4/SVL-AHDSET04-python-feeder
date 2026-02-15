"""
hieasy_dvr - Pure Python client for HiEasy Technology DVRs
=========================================================
Connects to SVL-AHDSET04 and similar HiEasy DVRs using their
proprietary XML-over-TCP protocol. Extracts H.264 video streams.
"""
from .client import DVRClient
from .protocol import HEADER_SIZE, CMD_MAGIC, MEDIA_MAGIC, VERSION

__version__ = "1.0.0"
__all__ = ["DVRClient"]
