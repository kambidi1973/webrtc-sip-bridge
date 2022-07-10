"""
WebRTC-SIP Bridge Gateway
=========================

A production-grade gateway that bridges WebRTC browser clients
to traditional SIP/PSTN infrastructure.

Provides:
- SIP protocol stack (RFC 3261 compliant)
- WebSocket signaling server for browser clients
- SDP translation between WebRTC and SIP formats
- RTP media relay with SRTP/RTP bridging
- Call routing with dial plan support
- CDR generation

Author: Gopala Rao Kambidi <kambidi@gmail.com>
"""

__version__ = "1.4.0"
__author__ = "Gopala Rao Kambidi"
