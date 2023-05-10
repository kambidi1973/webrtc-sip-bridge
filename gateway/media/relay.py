"""
RTP Media Relay
================

Bidirectional RTP media relay that bridges WebRTC (SRTP) and
SIP (RTP) media streams. The relay operates as a back-to-back
media proxy, receiving RTP packets from both sides and
forwarding them to the opposite endpoint.

Architecture:
  WebRTC Client  <-- SRTP -->  [Relay]  <-- RTP -->  SIP Endpoint

The relay handles:
- Bidirectional RTP packet forwarding
- RTCP relay for quality feedback
- Codec passthrough (no transcoding)
- Symmetric RTP / latching for NAT traversal
- Jitter buffer awareness (packet timestamping)

Author: Gopala Rao Kambidi <kambidi@gmail.com>
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# RTP header constants
RTP_VERSION = 2
RTP_HEADER_SIZE = 12
RTCP_SR_TYPE = 200
RTCP_RR_TYPE = 201


class RelayState(Enum):
    """Media relay session state."""
    IDLE = "idle"
    ACTIVE = "active"
    HELD = "held"
    STOPPED = "stopped"


@dataclass
class RelayStats:
    """Statistics for a relay session."""
    packets_forwarded_to_sip: int = 0
    packets_forwarded_to_webrtc: int = 0
    bytes_forwarded_to_sip: int = 0
    bytes_forwarded_to_webrtc: int = 0
    packets_dropped: int = 0
    started_at: float = 0.0
    last_packet_at: float = 0.0

    @property
    def duration(self) -> float:
        """Session duration in seconds."""
        if not self.started_at:
            return 0.0
        end = self.last_packet_at or time.time()
        return end - self.started_at


@dataclass
class RelaySession:
    """
    Represents a bidirectional media relay session.

    Each session bridges one media stream between a WebRTC
    client and a SIP endpoint, using two UDP sockets.
    """
    session_id: str
    # WebRTC side
    webrtc_address: Optional[Tuple[str, int]] = None
    webrtc_port: int = 0
    # SIP side
    sip_address: Optional[Tuple[str, int]] = None
    sip_port: int = 0
    # State
    state: RelayState = RelayState.IDLE
    stats: RelayStats = field(default_factory=RelayStats)
    # Transports
    _webrtc_transport: Optional[asyncio.DatagramTransport] = None
    _sip_transport: Optional[asyncio.DatagramTransport] = None
    # Symmetric RTP latching
    _webrtc_latched: bool = False
    _sip_latched: bool = False


class RTPRelayProtocol(asyncio.DatagramProtocol):
    """
    Asyncio datagram protocol for RTP relay.

    Receives RTP packets on one side and forwards them to the
    other side of the relay.
    """

    def __init__(self, relay: "MediaRelay", session_id: str, side: str):
        self.relay = relay
        self.session_id = session_id
        self.side = side  # "webrtc" or "sip"
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """Handle an incoming RTP packet."""
        session = self.relay.get_session(self.session_id)
        if not session or session.state == RelayState.STOPPED:
            return

        if len(data) < RTP_HEADER_SIZE:
            return

        # Verify RTP version
        version = (data[0] >> 6) & 0x03
        if version != RTP_VERSION:
            # Might be RTCP or STUN
            if len(data) > 1:
                pt = data[1] & 0x7F
                if pt in (RTCP_SR_TYPE, RTCP_RR_TYPE):
                    # Forward RTCP as-is
                    self.relay._forward_rtcp(session, data, self.side)
                    return
            return

        # Symmetric RTP latching: learn the remote address from first packet
        if self.side == "webrtc" and not session._webrtc_latched:
            session.webrtc_address = addr
            session._webrtc_latched = True
            logger.info("Latched WebRTC address for %s: %s", self.session_id, addr)
        elif self.side == "sip" and not session._sip_latched:
            session.sip_address = addr
            session._sip_latched = True
            logger.info("Latched SIP address for %s: %s", self.session_id, addr)

        # Forward to the other side
        if session.state == RelayState.HELD:
            session.stats.packets_dropped += 1
            return

        self.relay._forward_rtp(session, data, self.side)


class MediaRelay:
    """
    Manages RTP media relay sessions between WebRTC and SIP endpoints.

    Creates bidirectional UDP relay sessions that forward RTP
    packets between the browser (SRTP, after DTLS decryption)
    and the SIP endpoint (plain RTP).
    """

    def __init__(
        self,
        listen_address: str = "0.0.0.0",
        port_range: Tuple[int, int] = (10000, 20000),
    ):
        self.listen_address = listen_address
        self.port_min, self.port_max = port_range
        self._next_port = self.port_min
        self._sessions: Dict[str, RelaySession] = {}
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    async def create_session(
        self,
        session_id: str,
        sip_address: Optional[Tuple[str, int]] = None,
        webrtc_address: Optional[Tuple[str, int]] = None,
    ) -> RelaySession:
        """
        Create a new media relay session.

        Allocates two UDP ports (one for WebRTC side, one for SIP side)
        and starts listening for RTP packets on both.
        """
        self._loop = asyncio.get_event_loop()

        webrtc_port = self._allocate_port()
        sip_port = self._allocate_port()

        session = RelaySession(
            session_id=session_id,
            webrtc_port=webrtc_port,
            sip_port=sip_port,
            sip_address=sip_address,
            webrtc_address=webrtc_address,
        )

        # Create UDP listeners for both sides
        webrtc_transport, _ = await self._loop.create_datagram_endpoint(
            lambda: RTPRelayProtocol(self, session_id, "webrtc"),
            local_addr=(self.listen_address, webrtc_port),
        )
        sip_transport, _ = await self._loop.create_datagram_endpoint(
            lambda: RTPRelayProtocol(self, session_id, "sip"),
            local_addr=(self.listen_address, sip_port),
        )

        session._webrtc_transport = webrtc_transport
        session._sip_transport = sip_transport
        session.state = RelayState.ACTIVE
        session.stats.started_at = time.time()

        self._sessions[session_id] = session
        logger.info(
            "Relay session created: %s (WebRTC port: %d, SIP port: %d)",
            session_id, webrtc_port, sip_port,
        )
        return session

    def _forward_rtp(self, session: RelaySession, data: bytes, from_side: str):
        """Forward an RTP packet to the opposite side."""
        if from_side == "webrtc":
            # Forward to SIP endpoint
            if session.sip_address and session._sip_transport:
                session._sip_transport.sendto(data, session.sip_address)
                session.stats.packets_forwarded_to_sip += 1
                session.stats.bytes_forwarded_to_sip += len(data)
        else:
            # Forward to WebRTC client
            if session.webrtc_address and session._webrtc_transport:
                session._webrtc_transport.sendto(data, session.webrtc_address)
                session.stats.packets_forwarded_to_webrtc += 1
                session.stats.bytes_forwarded_to_webrtc += len(data)

        session.stats.last_packet_at = time.time()

    def _forward_rtcp(self, session: RelaySession, data: bytes, from_side: str):
        """Forward an RTCP packet to the opposite side."""
        # RTCP uses the RTP port + 1 in traditional SIP, but with
        # rtcp-mux in WebRTC it shares the same port
        self._forward_rtp(session, data, from_side)

    def get_session(self, session_id: str) -> Optional[RelaySession]:
        """Get a relay session by ID."""
        return self._sessions.get(session_id)

    async def hold_session(self, session_id: str):
        """Put a relay session on hold (stop forwarding)."""
        session = self._sessions.get(session_id)
        if session:
            session.state = RelayState.HELD
            logger.info("Relay session held: %s", session_id)

    async def unhold_session(self, session_id: str):
        """Resume a held relay session."""
        session = self._sessions.get(session_id)
        if session and session.state == RelayState.HELD:
            session.state = RelayState.ACTIVE
            logger.info("Relay session resumed: %s", session_id)

    async def stop_session(self, session_id: str) -> Optional[RelayStats]:
        """Stop and clean up a relay session."""
        session = self._sessions.pop(session_id, None)
        if not session:
            return None

        session.state = RelayState.STOPPED

        if session._webrtc_transport:
            session._webrtc_transport.close()
        if session._sip_transport:
            session._sip_transport.close()

        logger.info(
            "Relay session stopped: %s (duration: %.1fs, "
            "packets: %d->SIP, %d->WebRTC)",
            session_id,
            session.stats.duration,
            session.stats.packets_forwarded_to_sip,
            session.stats.packets_forwarded_to_webrtc,
        )
        return session.stats

    def _allocate_port(self) -> int:
        """Allocate the next even RTP port number."""
        port = self._next_port
        if port % 2 != 0:
            port += 1
        self._next_port = port + 2
        if self._next_port >= self.port_max:
            self._next_port = self.port_min
        return port

    @property
    def active_sessions(self) -> int:
        """Number of active relay sessions."""
        return sum(
            1 for s in self._sessions.values()
            if s.state == RelayState.ACTIVE
        )
