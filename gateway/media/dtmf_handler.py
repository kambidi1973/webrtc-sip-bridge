"""
DTMF Handler
==============

Handles DTMF tone translation between WebRTC (RFC 2833 / RFC 4733
telephone-event RTP packets) and SIP (SIP INFO with application/dtmf-relay).

WebRTC clients typically send DTMF as RFC 4733 telephone-event
RTP packets, while some SIP endpoints expect or produce DTMF
via SIP INFO messages. This module bridges both methods.

Author: Gopala Rao Kambidi <kambidi@gmail.com>
"""

import logging
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

logger = logging.getLogger(__name__)

# RFC 4733 telephone-event payload
# Byte layout:
#   0-7: event (DTMF digit)
#   8:   end flag
#   9:   reserved
#   10-15: volume
#   16-31: duration

DTMF_DIGITS = "0123456789*#ABCD"
DEFAULT_DURATION_MS = 160
DEFAULT_VOLUME = 10


class DTMFEvent(IntEnum):
    """RFC 4733 DTMF event codes."""
    DIGIT_0 = 0
    DIGIT_1 = 1
    DIGIT_2 = 2
    DIGIT_3 = 3
    DIGIT_4 = 4
    DIGIT_5 = 5
    DIGIT_6 = 6
    DIGIT_7 = 7
    DIGIT_8 = 8
    DIGIT_9 = 9
    STAR = 10
    HASH = 11
    A = 12
    B = 13
    C = 14
    D = 15
    FLASH = 16


@dataclass
class DTMFTone:
    """Represents a DTMF tone event."""
    digit: str
    duration_ms: int = DEFAULT_DURATION_MS
    volume: int = DEFAULT_VOLUME
    event_code: int = 0

    def __post_init__(self):
        if self.digit in DTMF_DIGITS:
            self.event_code = DTMF_DIGITS.index(self.digit)


class DTMFHandler:
    """
    Translates DTMF between RFC 4733 RTP events and SIP INFO.

    Handles bidirectional DTMF translation:
    - RTP telephone-event -> SIP INFO (WebRTC to SIP)
    - SIP INFO -> RTP telephone-event (SIP to WebRTC)
    """

    def __init__(self, telephone_event_pt: int = 101, clock_rate: int = 8000):
        self.telephone_event_pt = telephone_event_pt
        self.clock_rate = clock_rate

    def parse_rtp_dtmf(self, payload: bytes) -> Optional[DTMFTone]:
        """
        Parse a DTMF event from an RFC 4733 RTP payload.

        The payload (after RTP header) contains:
          - event (8 bits): the DTMF digit code
          - E flag (1 bit): end of event
          - R (1 bit): reserved
          - volume (6 bits): power level (0-63 dBm0)
          - duration (16 bits): in timestamp units
        """
        if len(payload) < 4:
            return None

        event = payload[0]
        end_flag = (payload[1] >> 7) & 0x01
        volume = payload[1] & 0x3F
        duration = struct.unpack("!H", payload[2:4])[0]

        # Only process end-of-event to avoid duplicates
        if not end_flag:
            return None

        if event > len(DTMF_DIGITS) - 1:
            logger.warning("Unknown DTMF event code: %d", event)
            return None

        digit = DTMF_DIGITS[event]
        duration_ms = int((duration / self.clock_rate) * 1000)

        return DTMFTone(
            digit=digit,
            duration_ms=duration_ms,
            volume=volume,
            event_code=event,
        )

    def build_rtp_dtmf(self, tone: DTMFTone, end: bool = True) -> bytes:
        """
        Build an RFC 4733 DTMF RTP payload.

        Returns the 4-byte telephone-event payload to be appended
        after the RTP header.
        """
        event = tone.event_code
        volume = min(tone.volume, 63)
        duration_ts = int((tone.duration_ms / 1000) * self.clock_rate)

        flags = volume
        if end:
            flags |= 0x80  # Set end-of-event bit

        payload = struct.pack("!BBH", event, flags, duration_ts)
        return payload

    def build_sip_info_body(self, tone: DTMFTone) -> str:
        """
        Build a SIP INFO message body for DTMF relay.

        Format (application/dtmf-relay):
          Signal=5
          Duration=160
        """
        return f"Signal={tone.digit}\r\nDuration={tone.duration_ms}\r\n"

    def parse_sip_info_body(self, body: str) -> Optional[DTMFTone]:
        """
        Parse a DTMF event from a SIP INFO body.

        Handles both application/dtmf-relay format:
          Signal=5
          Duration=160

        And application/dtmf format:
          5
        """
        body = body.strip()

        # Simple format: just the digit
        if len(body) == 1 and body in DTMF_DIGITS:
            return DTMFTone(digit=body)

        # Key=Value format
        digit = None
        duration = DEFAULT_DURATION_MS

        for line in body.split("\n"):
            line = line.strip().rstrip("\r")
            if "=" in line:
                key, value = line.split("=", 1)
                key = key.strip().lower()
                value = value.strip()
                if key == "signal":
                    digit = value
                elif key == "duration":
                    try:
                        duration = int(value)
                    except ValueError:
                        pass

        if digit and digit in DTMF_DIGITS:
            return DTMFTone(digit=digit, duration_ms=duration)

        return None

    def digit_to_event(self, digit: str) -> int:
        """Convert a DTMF digit character to RFC 4733 event code."""
        if digit in DTMF_DIGITS:
            return DTMF_DIGITS.index(digit)
        return -1

    def event_to_digit(self, event: int) -> str:
        """Convert an RFC 4733 event code to DTMF digit character."""
        if 0 <= event < len(DTMF_DIGITS):
            return DTMF_DIGITS[event]
        return ""
