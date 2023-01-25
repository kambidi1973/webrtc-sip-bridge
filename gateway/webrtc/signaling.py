"""
WebSocket Signaling Server
============================

Implements a WebSocket-based signaling server for WebRTC clients.
Handles the signaling path between browser-based softphones and
the SIP gateway.

Protocol messages (JSON over WebSocket):
  - register:  Client registration with credentials
  - invite:    Outgoing call initiation with SDP offer
  - answer:    Call answer with SDP answer
  - bye:       Call termination
  - cancel:    Cancel pending call
  - dtmf:      DTMF digit relay
  - hold:      Call hold
  - unhold:    Call resume
  - transfer:  Attended/blind call transfer
  - ringing:   180 Ringing indication
  - ack:       Acknowledgment

Author: Gopala Rao Kambidi <kambidi@gmail.com>
"""

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

try:
    import websockets
    from websockets.server import serve as ws_serve
except ImportError:
    websockets = None

logger = logging.getLogger(__name__)


class SessionState(Enum):
    """WebRTC session states."""
    IDLE = "idle"
    REGISTERING = "registering"
    REGISTERED = "registered"
    CALLING = "calling"
    RINGING = "ringing"
    CONNECTED = "connected"
    HOLDING = "holding"
    DISCONNECTING = "disconnecting"


@dataclass
class WebRTCSession:
    """Tracks a connected WebRTC client session."""
    session_id: str
    websocket: Any  # websockets.WebSocketServerProtocol
    user_uri: str = ""
    display_name: str = ""
    state: SessionState = SessionState.IDLE
    call_id: Optional[str] = None
    dialog_id: Optional[str] = None
    peer_session_id: Optional[str] = None
    registered_at: Optional[float] = None
    connected_at: float = field(default_factory=time.time)
    auth_token: Optional[str] = None
    ice_candidates: List[Dict] = field(default_factory=list)
    remote_sdp: Optional[str] = None
    local_sdp: Optional[str] = None


class SignalingProtocol:
    """
    Defines the WebSocket signaling protocol messages.

    Each message is a JSON object with a 'type' field indicating
    the message kind, plus type-specific payload fields.
    """

    # Client -> Server message types
    MSG_REGISTER = "register"
    MSG_INVITE = "invite"
    MSG_ANSWER = "answer"
    MSG_BYE = "bye"
    MSG_CANCEL = "cancel"
    MSG_DTMF = "dtmf"
    MSG_HOLD = "hold"
    MSG_UNHOLD = "unhold"
    MSG_TRANSFER = "transfer"
    MSG_ICE_CANDIDATE = "ice_candidate"
    MSG_PING = "ping"

    # Server -> Client message types
    MSG_REGISTERED = "registered"
    MSG_INCOMING = "incoming"
    MSG_RINGING = "ringing"
    MSG_CONNECTED = "connected"
    MSG_HANGUP = "hangup"
    MSG_DTMF_EVENT = "dtmf_event"
    MSG_HELD = "held"
    MSG_TRANSFER_RESULT = "transfer_result"
    MSG_ERROR = "error"
    MSG_PONG = "pong"

    @staticmethod
    def validate_message(data: dict) -> bool:
        """Validate that a signaling message has required fields."""
        if "type" not in data:
            return False

        required_fields = {
            "register": ["uri"],
            "invite": ["target", "sdp"],
            "answer": ["call_id", "sdp"],
            "bye": ["call_id"],
            "cancel": ["call_id"],
            "dtmf": ["call_id", "digit"],
            "hold": ["call_id"],
            "unhold": ["call_id"],
            "transfer": ["call_id", "target"],
            "ice_candidate": ["call_id", "candidate"],
        }

        msg_type = data["type"]
        if msg_type in required_fields:
            return all(f in data for f in required_fields[msg_type])
        return True


class WebSocketSignalingServer:
    """
    WebSocket signaling server for WebRTC clients.

    Manages WebSocket connections from browser clients, handles
    signaling message routing, and interfaces with the SIP gateway
    for call setup and teardown.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8765,
        on_register: Optional[Callable] = None,
        on_invite: Optional[Callable] = None,
        on_answer: Optional[Callable] = None,
        on_bye: Optional[Callable] = None,
        on_dtmf: Optional[Callable] = None,
        on_hold: Optional[Callable] = None,
        on_transfer: Optional[Callable] = None,
    ):
        self.host = host
        self.port = port
        self._sessions: Dict[str, WebRTCSession] = {}
        self._uri_to_session: Dict[str, str] = {}
        self._call_to_session: Dict[str, str] = {}
        self._server = None

        # Gateway callbacks
        self.on_register = on_register
        self.on_invite = on_invite
        self.on_answer = on_answer
        self.on_bye = on_bye
        self.on_dtmf = on_dtmf
        self.on_hold = on_hold
        self.on_transfer = on_transfer

    async def start(self):
        """Start the WebSocket signaling server."""
        if websockets is None:
            raise RuntimeError("websockets package is required")

        self._server = await ws_serve(
            self._handle_connection,
            self.host,
            self.port,
            ping_interval=30,
            ping_timeout=10,
        )
        logger.info("Signaling server started on ws://%s:%d", self.host, self.port)

    async def stop(self):
        """Stop the signaling server and close all connections."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        # Close all active sessions
        for session in list(self._sessions.values()):
            try:
                await session.websocket.close()
            except Exception:
                pass
        self._sessions.clear()
        logger.info("Signaling server stopped")

    async def _handle_connection(self, websocket, path=None):
        """Handle a new WebSocket connection."""
        session_id = str(uuid.uuid4())
        session = WebRTCSession(session_id=session_id, websocket=websocket)
        self._sessions[session_id] = session

        logger.info("New WebSocket connection: %s from %s", session_id, websocket.remote_address)

        try:
            async for raw_message in websocket:
                try:
                    data = json.loads(raw_message)
                    if not SignalingProtocol.validate_message(data):
                        await self._send_error(session, "Invalid message format")
                        continue
                    await self._dispatch_message(session, data)
                except json.JSONDecodeError:
                    await self._send_error(session, "Invalid JSON")
                except Exception as e:
                    logger.exception("Error handling message in session %s", session_id)
                    await self._send_error(session, str(e))
        except websockets.ConnectionClosed:
            logger.info("WebSocket disconnected: %s", session_id)
        finally:
            await self._cleanup_session(session)

    async def _dispatch_message(self, session: WebRTCSession, data: dict):
        """Route a signaling message to the appropriate handler."""
        msg_type = data["type"]
        handlers = {
            SignalingProtocol.MSG_REGISTER: self._handle_register,
            SignalingProtocol.MSG_INVITE: self._handle_invite,
            SignalingProtocol.MSG_ANSWER: self._handle_answer,
            SignalingProtocol.MSG_BYE: self._handle_bye,
            SignalingProtocol.MSG_CANCEL: self._handle_cancel,
            SignalingProtocol.MSG_DTMF: self._handle_dtmf,
            SignalingProtocol.MSG_HOLD: self._handle_hold,
            SignalingProtocol.MSG_UNHOLD: self._handle_unhold,
            SignalingProtocol.MSG_TRANSFER: self._handle_transfer,
            SignalingProtocol.MSG_ICE_CANDIDATE: self._handle_ice_candidate,
            SignalingProtocol.MSG_PING: self._handle_ping,
        }
        handler = handlers.get(msg_type)
        if handler:
            await handler(session, data)
        else:
            await self._send_error(session, f"Unknown message type: {msg_type}")

    async def _handle_register(self, session: WebRTCSession, data: dict):
        """Handle client registration."""
        session.user_uri = data["uri"]
        session.display_name = data.get("display_name", "")
        session.auth_token = data.get("token")
        session.state = SessionState.REGISTERED
        session.registered_at = time.time()

        self._uri_to_session[session.user_uri] = session.session_id

        if self.on_register:
            await self.on_register(session, data)

        await self._send_message(session, {
            "type": SignalingProtocol.MSG_REGISTERED,
            "session_id": session.session_id,
            "uri": session.user_uri,
        })
        logger.info("Client registered: %s as %s", session.session_id, session.user_uri)

    async def _handle_invite(self, session: WebRTCSession, data: dict):
        """Handle outgoing call initiation."""
        call_id = str(uuid.uuid4())
        session.call_id = call_id
        session.local_sdp = data["sdp"]
        session.state = SessionState.CALLING

        self._call_to_session[call_id] = session.session_id

        if self.on_invite:
            await self.on_invite(session, {
                "call_id": call_id,
                "from_uri": session.user_uri,
                "to_uri": data["target"],
                "sdp": data["sdp"],
                "display_name": session.display_name,
            })

        await self._send_message(session, {
            "type": "call_initiated",
            "call_id": call_id,
        })

    async def _handle_answer(self, session: WebRTCSession, data: dict):
        """Handle call answer with SDP."""
        session.local_sdp = data["sdp"]
        session.state = SessionState.CONNECTED

        if self.on_answer:
            await self.on_answer(session, {
                "call_id": data["call_id"],
                "sdp": data["sdp"],
            })

    async def _handle_bye(self, session: WebRTCSession, data: dict):
        """Handle call hangup."""
        session.state = SessionState.DISCONNECTING

        if self.on_bye:
            await self.on_bye(session, {"call_id": data["call_id"]})

        session.state = SessionState.REGISTERED
        session.call_id = None

    async def _handle_cancel(self, session: WebRTCSession, data: dict):
        """Handle call cancellation."""
        session.state = SessionState.REGISTERED
        session.call_id = None

        if self.on_bye:
            await self.on_bye(session, {"call_id": data["call_id"], "cancel": True})

    async def _handle_dtmf(self, session: WebRTCSession, data: dict):
        """Handle DTMF digit relay."""
        if self.on_dtmf:
            await self.on_dtmf(session, {
                "call_id": data["call_id"],
                "digit": data["digit"],
                "duration": data.get("duration", 160),
            })

    async def _handle_hold(self, session: WebRTCSession, data: dict):
        """Handle call hold request."""
        session.state = SessionState.HOLDING
        if self.on_hold:
            await self.on_hold(session, {"call_id": data["call_id"], "hold": True})

    async def _handle_unhold(self, session: WebRTCSession, data: dict):
        """Handle call unhold request."""
        session.state = SessionState.CONNECTED
        if self.on_hold:
            await self.on_hold(session, {"call_id": data["call_id"], "hold": False})

    async def _handle_transfer(self, session: WebRTCSession, data: dict):
        """Handle call transfer request."""
        if self.on_transfer:
            await self.on_transfer(session, {
                "call_id": data["call_id"],
                "target": data["target"],
                "type": data.get("transfer_type", "blind"),
            })

    async def _handle_ice_candidate(self, session: WebRTCSession, data: dict):
        """Handle ICE candidate from client."""
        session.ice_candidates.append(data["candidate"])

    async def _handle_ping(self, session: WebRTCSession, data: dict):
        """Handle keepalive ping."""
        await self._send_message(session, {"type": SignalingProtocol.MSG_PONG})

    # --- Server-initiated messages to clients ---

    async def send_incoming_call(self, uri: str, call_id: str, from_uri: str, sdp: str, display_name: str = ""):
        """Notify a registered client of an incoming call."""
        session_id = self._uri_to_session.get(uri)
        if not session_id:
            logger.warning("No session found for URI %s", uri)
            return False

        session = self._sessions.get(session_id)
        if not session or session.state != SessionState.REGISTERED:
            return False

        session.call_id = call_id
        session.remote_sdp = sdp
        session.state = SessionState.RINGING
        self._call_to_session[call_id] = session_id

        await self._send_message(session, {
            "type": SignalingProtocol.MSG_INCOMING,
            "call_id": call_id,
            "from": from_uri,
            "display_name": display_name,
            "sdp": sdp,
        })
        return True

    async def send_ringing(self, call_id: str):
        """Send 180 Ringing to the calling client."""
        session = self._get_session_by_call(call_id)
        if session:
            await self._send_message(session, {
                "type": SignalingProtocol.MSG_RINGING,
                "call_id": call_id,
            })

    async def send_connected(self, call_id: str, sdp: str):
        """Send call connected notification with remote SDP."""
        session = self._get_session_by_call(call_id)
        if session:
            session.state = SessionState.CONNECTED
            session.remote_sdp = sdp
            await self._send_message(session, {
                "type": SignalingProtocol.MSG_CONNECTED,
                "call_id": call_id,
                "sdp": sdp,
            })

    async def send_hangup(self, call_id: str, reason: str = "normal"):
        """Send call hangup notification."""
        session = self._get_session_by_call(call_id)
        if session:
            session.state = SessionState.REGISTERED
            session.call_id = None
            await self._send_message(session, {
                "type": SignalingProtocol.MSG_HANGUP,
                "call_id": call_id,
                "reason": reason,
            })

    # --- Internal helpers ---

    def _get_session_by_call(self, call_id: str) -> Optional[WebRTCSession]:
        """Look up a session by call ID."""
        session_id = self._call_to_session.get(call_id)
        if session_id:
            return self._sessions.get(session_id)
        return None

    async def _send_message(self, session: WebRTCSession, data: dict):
        """Send a JSON message to a client."""
        try:
            await session.websocket.send(json.dumps(data))
        except Exception as e:
            logger.error("Failed to send message to %s: %s", session.session_id, e)

    async def _send_error(self, session: WebRTCSession, message: str):
        """Send an error message to a client."""
        await self._send_message(session, {
            "type": SignalingProtocol.MSG_ERROR,
            "message": message,
        })

    async def _cleanup_session(self, session: WebRTCSession):
        """Clean up a disconnected session."""
        if session.user_uri:
            self._uri_to_session.pop(session.user_uri, None)
        if session.call_id:
            self._call_to_session.pop(session.call_id, None)
            # Notify gateway of hangup
            if self.on_bye and session.state in (SessionState.CONNECTED, SessionState.CALLING, SessionState.RINGING):
                await self.on_bye(session, {"call_id": session.call_id})
        self._sessions.pop(session.session_id, None)
        logger.info("Session cleaned up: %s", session.session_id)

    @property
    def active_sessions(self) -> int:
        """Number of active WebSocket sessions."""
        return len(self._sessions)

    @property
    def registered_users(self) -> List[str]:
        """List of currently registered user URIs."""
        return list(self._uri_to_session.keys())
