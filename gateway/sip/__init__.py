"""
SIP Protocol Implementation
============================

RFC 3261 compliant SIP stack with:
- Message parsing and serialization
- Transaction layer (INVITE and non-INVITE)
- Dialog management
- Registration handling
- UDP/TCP/TLS transport

This implementation focuses on the subset of SIP needed for
a WebRTC-SIP gateway: INVITE, ACK, BYE, CANCEL, REGISTER,
REFER, INFO, and OPTIONS methods.
"""
