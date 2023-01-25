"""
ICE Candidate Handler
======================

Manages Interactive Connectivity Establishment (ICE) candidates
for WebRTC connections. Handles candidate gathering, trickle ICE,
and candidate selection for the gateway's media path.

The gateway acts as a TURN-like relay — it terminates ICE on the
WebRTC side and uses plain RTP toward the SIP endpoint. This module
handles the WebRTC-facing ICE negotiation.

Author: Gopala Rao Kambidi <kambidi@gmail.com>
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class CandidateType(Enum):
    """ICE candidate types per RFC 8445."""
    HOST = "host"
    SRFLX = "srflx"      # Server reflexive
    PRFLX = "prflx"      # Peer reflexive
    RELAY = "relay"       # TURN relay


@dataclass
class IceCandidate:
    """Parsed ICE candidate."""
    foundation: str
    component: int         # 1 = RTP, 2 = RTCP
    transport: str         # UDP or TCP
    priority: int
    address: str
    port: int
    candidate_type: CandidateType
    related_address: str = ""
    related_port: int = 0
    generation: int = 0
    ufrag: str = ""
    raw: str = ""

    @classmethod
    def parse(cls, candidate_str: str) -> Optional["IceCandidate"]:
        """
        Parse an ICE candidate string (RFC 8445 format).

        Example:
          candidate:842163049 1 udp 1677729535 192.168.1.100 56032 typ srflx
          raddr 10.0.0.1 rport 56032 generation 0 ufrag abc1
        """
        # Strip "a=candidate:" or "candidate:" prefix
        raw = candidate_str.strip()
        text = raw
        if text.startswith("a=candidate:"):
            text = text[len("a=candidate:"):]
        elif text.startswith("candidate:"):
            text = text[len("candidate:"):]

        parts = text.split()
        if len(parts) < 8:
            return None

        try:
            foundation = parts[0]
            component = int(parts[1])
            transport = parts[2].upper()
            priority = int(parts[3])
            address = parts[4]
            port = int(parts[5])
            # parts[6] should be "typ"
            ctype = CandidateType(parts[7])
        except (ValueError, IndexError, KeyError):
            logger.warning("Failed to parse ICE candidate: %s", candidate_str)
            return None

        candidate = cls(
            foundation=foundation,
            component=component,
            transport=transport,
            priority=priority,
            address=address,
            port=port,
            candidate_type=ctype,
            raw=raw,
        )

        # Parse optional extensions
        i = 8
        while i < len(parts) - 1:
            key = parts[i]
            val = parts[i + 1]
            if key == "raddr":
                candidate.related_address = val
            elif key == "rport":
                candidate.related_port = int(val)
            elif key == "generation":
                candidate.generation = int(val)
            elif key == "ufrag":
                candidate.ufrag = val
            i += 2

        return candidate

    def to_sdp_line(self) -> str:
        """Serialize to SDP a=candidate: line."""
        line = (
            f"a=candidate:{self.foundation} {self.component} "
            f"{self.transport.lower()} {self.priority} "
            f"{self.address} {self.port} typ {self.candidate_type.value}"
        )
        if self.related_address:
            line += f" raddr {self.related_address} rport {self.related_port}"
        if self.generation:
            line += f" generation {self.generation}"
        return line


class IceHandler:
    """
    Manages ICE candidates for WebRTC sessions.

    Collects trickle ICE candidates from the WebRTC client,
    selects the best candidate pair, and generates gateway-side
    ICE candidates for the SDP answer.
    """

    def __init__(self, gateway_address: str = "0.0.0.0", rtp_port: int = 10000):
        self.gateway_address = gateway_address
        self.rtp_port = rtp_port
        # session_id -> list of candidates
        self._candidates: Dict[str, List[IceCandidate]] = {}
        self._selected: Dict[str, IceCandidate] = {}

    def add_candidate(self, session_id: str, candidate_str: str) -> Optional[IceCandidate]:
        """
        Add a trickle ICE candidate for a session.

        Returns the parsed candidate or None if parsing failed.
        """
        candidate = IceCandidate.parse(candidate_str)
        if not candidate:
            return None

        if session_id not in self._candidates:
            self._candidates[session_id] = []

        self._candidates[session_id].append(candidate)
        logger.debug(
            "ICE candidate added for %s: %s:%d (%s)",
            session_id, candidate.address, candidate.port,
            candidate.candidate_type.value,
        )
        return candidate

    def get_candidates(self, session_id: str) -> List[IceCandidate]:
        """Get all collected candidates for a session."""
        return self._candidates.get(session_id, [])

    def select_candidate(self, session_id: str) -> Optional[IceCandidate]:
        """
        Select the best candidate for media delivery.

        Priority order:
          1. Host candidates (direct connectivity)
          2. Server reflexive (NAT traversal)
          3. Relay candidates (TURN - worst latency)

        Within each type, prefer highest priority value.
        """
        candidates = self._candidates.get(session_id, [])
        if not candidates:
            return None

        # Filter RTP candidates only (component 1)
        rtp_candidates = [c for c in candidates if c.component == 1]
        if not rtp_candidates:
            rtp_candidates = candidates

        # Sort by type preference then priority
        type_preference = {
            CandidateType.HOST: 3,
            CandidateType.SRFLX: 2,
            CandidateType.PRFLX: 1,
            CandidateType.RELAY: 0,
        }

        best = max(
            rtp_candidates,
            key=lambda c: (type_preference.get(c.candidate_type, 0), c.priority),
        )

        self._selected[session_id] = best
        logger.info(
            "Selected ICE candidate for %s: %s:%d (%s)",
            session_id, best.address, best.port, best.candidate_type.value,
        )
        return best

    def get_selected(self, session_id: str) -> Optional[IceCandidate]:
        """Get the selected candidate for a session."""
        return self._selected.get(session_id)

    def generate_gateway_candidate(self, port: Optional[int] = None) -> IceCandidate:
        """
        Generate a host ICE candidate for the gateway.

        Used in the SDP answer sent to the WebRTC client,
        representing the gateway's media receive address.
        """
        return IceCandidate(
            foundation="1",
            component=1,
            transport="UDP",
            priority=2130706431,  # Host candidate priority
            address=self.gateway_address,
            port=port or self.rtp_port,
            candidate_type=CandidateType.HOST,
        )

    def cleanup_session(self, session_id: str):
        """Remove all candidates for a terminated session."""
        self._candidates.pop(session_id, None)
        self._selected.pop(session_id, None)

    def get_remote_address(self, session_id: str) -> Optional[Tuple[str, int]]:
        """Get the selected remote media address for RTP forwarding."""
        selected = self._selected.get(session_id)
        if selected:
            return (selected.address, selected.port)
        return None
