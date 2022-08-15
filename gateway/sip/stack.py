"""
SIP Protocol Stack
===================

Core SIP message parsing, serialization, and request/response handling
per RFC 3261. This module provides the foundation for all SIP operations
in the gateway.

Key responsibilities:
- Parse incoming SIP messages (requests and responses)
- Serialize outgoing SIP messages
- Manage Via headers with branch parameters
- Handle Contact and Route headers
- Coordinate with the transaction and dialog layers

Author: Gopala Rao Kambidi <kambidi@gmail.com>
"""

import asyncio
import hashlib
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple

from gateway.sip.transport import SIPTransport
from gateway.sip.transaction import TransactionLayer, TransactionType
from gateway.sip.dialog import DialogManager
from gateway.sip.message_builder import SIPMessageBuilder

logger = logging.getLogger(__name__)

# SIP magic cookie for branch parameter (RFC 3261 §8.1.1.7)
BRANCH_MAGIC_COOKIE = "z9hG4bK"

# Standard SIP port
SIP_DEFAULT_PORT = 5060
SIP_TLS_PORT = 5061


class SIPMethod(Enum):
    """Supported SIP methods."""
    INVITE = "INVITE"
    ACK = "ACK"
    BYE = "BYE"
    CANCEL = "CANCEL"
    REGISTER = "REGISTER"
    OPTIONS = "OPTIONS"
    REFER = "REFER"
    INFO = "INFO"
    NOTIFY = "NOTIFY"
    UPDATE = "UPDATE"
    PRACK = "PRACK"


@dataclass
class SIPHeader:
    """Represents a parsed SIP header."""
    name: str
    value: str
    parameters: Dict[str, str] = field(default_factory=dict)

    def __str__(self):
        params = "".join(f";{k}={v}" for k, v in self.parameters.items())
        return f"{self.name}: {self.value}{params}"


@dataclass
class SIPURI:
    """Parsed SIP URI (sip:user@host:port;params)."""
    scheme: str = "sip"
    user: Optional[str] = None
    host: str = ""
    port: int = 5060
    parameters: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def parse(cls, uri_string: str) -> "SIPURI":
        """Parse a SIP URI string into components."""
        uri = cls()

        # Extract scheme
        if ":" in uri_string:
            scheme_part, rest = uri_string.split(":", 1)
            uri.scheme = scheme_part.lower()
        else:
            rest = uri_string

        # Extract headers (after ?)
        if "?" in rest:
            rest, header_part = rest.split("?", 1)
            for param in header_part.split("&"):
                if "=" in param:
                    k, v = param.split("=", 1)
                    uri.headers[k] = v

        # Extract parameters (after ;)
        parts = rest.split(";")
        user_host = parts[0]
        for param in parts[1:]:
            if "=" in param:
                k, v = param.split("=", 1)
                uri.parameters[k] = v
            else:
                uri.parameters[param] = ""

        # Extract user and host
        if "@" in user_host:
            uri.user, host_part = user_host.split("@", 1)
        else:
            host_part = user_host

        # Extract port
        if ":" in host_part and "[" not in host_part:
            uri.host, port_str = host_part.rsplit(":", 1)
            try:
                uri.port = int(port_str)
            except ValueError:
                uri.host = host_part
        else:
            uri.host = host_part

        return uri

    def __str__(self):
        result = f"{self.scheme}:"
        if self.user:
            result += f"{self.user}@"
        result += self.host
        if self.port and self.port != SIP_DEFAULT_PORT:
            result += f":{self.port}"
        for k, v in self.parameters.items():
            result += f";{k}={v}" if v else f";{k}"
        if self.headers:
            result += "?" + "&".join(f"{k}={v}" for k, v in self.headers.items())
        return result


@dataclass
class SIPMessage:
    """Represents a parsed SIP message (request or response)."""
    # Request line fields
    method: Optional[str] = None
    request_uri: Optional[str] = None

    # Response line fields
    status_code: Optional[int] = None
    reason_phrase: Optional[str] = None

    # Headers
    headers: Dict[str, List[str]] = field(default_factory=dict)
    body: str = ""

    # Parsed convenience fields
    call_id: str = ""
    cseq: int = 0
    cseq_method: str = ""
    from_uri: str = ""
    from_tag: str = ""
    to_uri: str = ""
    to_tag: str = ""
    via_branch: str = ""
    contact: str = ""
    content_type: str = ""

    @property
    def is_request(self) -> bool:
        return self.method is not None

    @property
    def is_response(self) -> bool:
        return self.status_code is not None

    def get_header(self, name: str) -> Optional[str]:
        """Get the first value for a header."""
        # Check both full name and compact form
        compact_forms = {
            "v": "Via", "f": "From", "t": "To", "i": "Call-ID",
            "m": "Contact", "l": "Content-Length", "c": "Content-Type",
            "e": "Content-Encoding", "k": "Supported", "s": "Subject",
        }
        normalized = compact_forms.get(name.lower(), name)

        for key in self.headers:
            if key.lower() == normalized.lower():
                values = self.headers[key]
                return values[0] if values else None
        return None

    def get_all_headers(self, name: str) -> List[str]:
        """Get all values for a header (e.g., multiple Via headers)."""
        for key in self.headers:
            if key.lower() == name.lower():
                return self.headers[key]
        return []

    def add_header(self, name: str, value: str):
        """Add a header value (appends if header already exists)."""
        if name not in self.headers:
            self.headers[name] = []
        self.headers[name].append(value)


class SIPParser:
    """
    SIP message parser.

    Handles both request and response messages, including:
    - Start line parsing (request-line or status-line)
    - Header parsing with multi-line continuation
    - Compact header form expansion
    - Body extraction based on Content-Length
    """

    # Compact header form mappings (RFC 3261 §7.3.3)
    COMPACT_HEADERS = {
        "v": "Via",
        "f": "From",
        "t": "To",
        "i": "Call-ID",
        "m": "Contact",
        "l": "Content-Length",
        "c": "Content-Type",
        "e": "Content-Encoding",
        "k": "Supported",
        "s": "Subject",
        "r": "Refer-To",
    }

    @classmethod
    def parse(cls, data: bytes) -> Optional[SIPMessage]:
        """Parse raw bytes into a SIPMessage."""
        try:
            text = data.decode("utf-8", errors="replace")
            return cls.parse_text(text)
        except Exception as e:
            logger.error("Failed to parse SIP message: %s", e)
            return None

    @classmethod
    def parse_text(cls, text: str) -> Optional[SIPMessage]:
        """Parse a SIP message from text."""
        msg = SIPMessage()

        # Split headers and body
        if "\r\n\r\n" in text:
            header_section, msg.body = text.split("\r\n\r\n", 1)
        elif "\n\n" in text:
            header_section, msg.body = text.split("\n\n", 1)
        else:
            header_section = text
            msg.body = ""

        lines = header_section.replace("\r\n", "\n").split("\n")
        if not lines:
            return None

        # Parse start line
        start_line = lines[0].strip()
        if start_line.startswith("SIP/2.0"):
            # Status line: SIP/2.0 200 OK
            parts = start_line.split(" ", 2)
            msg.status_code = int(parts[1])
            msg.reason_phrase = parts[2] if len(parts) > 2 else ""
        else:
            # Request line: INVITE sip:user@host SIP/2.0
            parts = start_line.split(" ", 2)
            msg.method = parts[0]
            msg.request_uri = parts[1] if len(parts) > 1 else ""

        # Parse headers (handle continuation lines)
        current_header = None
        current_value = None

        for line in lines[1:]:
            if not line:
                continue
            if line[0] in (" ", "\t"):
                # Continuation line
                if current_header:
                    current_value += " " + line.strip()
            else:
                # Save previous header
                if current_header:
                    cls._store_header(msg, current_header, current_value)

                if ":" in line:
                    current_header, current_value = line.split(":", 1)
                    current_header = current_header.strip()
                    current_value = current_value.strip()

                    # Expand compact form
                    if current_header.lower() in cls.COMPACT_HEADERS:
                        current_header = cls.COMPACT_HEADERS[current_header.lower()]

        # Don't forget the last header
        if current_header:
            cls._store_header(msg, current_header, current_value)

        # Extract commonly used fields
        cls._extract_fields(msg)

        return msg

    @classmethod
    def _store_header(cls, msg: SIPMessage, name: str, value: str):
        """Store a parsed header, handling comma-separated values for some headers."""
        # Headers that can have comma-separated values in a single line
        multi_value_headers = {"Via", "Route", "Record-Route", "Contact"}

        if name in multi_value_headers and "," in value:
            for v in value.split(","):
                msg.add_header(name, v.strip())
        else:
            msg.add_header(name, value)

    @classmethod
    def _extract_fields(cls, msg: SIPMessage):
        """Extract commonly used fields from headers for convenience."""
        # Call-ID
        call_id = msg.get_header("Call-ID")
        if call_id:
            msg.call_id = call_id.strip()

        # CSeq
        cseq = msg.get_header("CSeq")
        if cseq:
            parts = cseq.strip().split()
            if len(parts) >= 2:
                msg.cseq = int(parts[0])
                msg.cseq_method = parts[1]

        # From
        from_header = msg.get_header("From")
        if from_header:
            msg.from_uri = cls._extract_uri(from_header)
            tag_match = re.search(r";tag=([^\s;>]+)", from_header)
            if tag_match:
                msg.from_tag = tag_match.group(1)

        # To
        to_header = msg.get_header("To")
        if to_header:
            msg.to_uri = cls._extract_uri(to_header)
            tag_match = re.search(r";tag=([^\s;>]+)", to_header)
            if tag_match:
                msg.to_tag = tag_match.group(1)

        # Via branch
        via = msg.get_header("Via")
        if via:
            branch_match = re.search(r";branch=([^\s;]+)", via)
            if branch_match:
                msg.via_branch = branch_match.group(1)

        # Contact
        contact = msg.get_header("Contact")
        if contact:
            msg.contact = cls._extract_uri(contact)

        # Content-Type
        ct = msg.get_header("Content-Type")
        if ct:
            msg.content_type = ct.strip()

    @staticmethod
    def _extract_uri(header_value: str) -> str:
        """Extract URI from a header value (handles <uri> and bare uri)."""
        match = re.search(r"<([^>]+)>", header_value)
        if match:
            return match.group(1)
        # Bare URI — strip display name and parameters
        value = header_value.strip()
        if ";" in value:
            value = value.split(";")[0]
        return value.strip()


class SIPStack:
    """
    Main SIP protocol stack.

    Manages the full SIP message lifecycle:
    1. Transport layer (UDP/TCP/TLS)
    2. Transaction layer (retransmissions, timeouts)
    3. Dialog layer (session state)

    Provides high-level methods for sending INVITE, BYE, ACK, etc.
    """

    def __init__(
        self,
        listen_address: str = "0.0.0.0",
        listen_port: int = 5060,
        transport: str = "udp",
        domain: str = "localhost",
    ):
        self.listen_address = listen_address
        self.listen_port = listen_port
        self.transport_type = transport
        self.domain = domain

        self._transport: Optional[SIPTransport] = None
        self._transaction_layer: Optional[TransactionLayer] = None
        self._dialog_manager = DialogManager()
        self._message_builder = SIPMessageBuilder(domain=domain)

        self.is_running = False
        self._cseq_counter = 1

        # Callbacks
        self.on_request: Optional[Callable] = None
        self.on_response: Optional[Callable] = None

    @property
    def active_transactions(self) -> int:
        """Number of active SIP transactions."""
        if self._transaction_layer:
            return self._transaction_layer.active_count
        return 0

    async def start(self):
        """Start the SIP stack (transport + transaction layer)."""
        self._transport = SIPTransport(
            listen_address=self.listen_address,
            listen_port=self.listen_port,
            transport_type=self.transport_type,
        )
        self._transport.on_message_received = self._on_raw_message

        await self._transport.start()

        self._transaction_layer = TransactionLayer(
            transport=self._transport,
            on_request=self._on_transaction_request,
            on_response=self._on_transaction_response,
        )
        await self._transaction_layer.start()

        self.is_running = True
        logger.info("SIP stack started on %s:%d", self.listen_address, self.listen_port)

    async def stop(self):
        """Stop the SIP stack."""
        self.is_running = False
        if self._transaction_layer:
            await self._transaction_layer.stop()
        if self._transport:
            await self._transport.stop()
        logger.info("SIP stack stopped")

    def _generate_branch(self) -> str:
        """Generate a RFC 3261 compliant branch parameter."""
        unique = uuid.uuid4().hex[:12]
        return f"{BRANCH_MAGIC_COOKIE}{unique}"

    def _generate_tag(self) -> str:
        """Generate a random tag for From/To headers."""
        return uuid.uuid4().hex[:8]

    def _generate_call_id(self) -> str:
        """Generate a unique Call-ID."""
        return f"{uuid.uuid4().hex}@{self.domain}"

    def _next_cseq(self) -> int:
        """Get next CSeq number."""
        self._cseq_counter += 1
        return self._cseq_counter

    async def _on_raw_message(self, data: bytes, addr: Tuple[str, int]):
        """Handle raw SIP message from transport layer."""
        msg = SIPParser.parse(data)
        if not msg:
            logger.warning("Failed to parse SIP message from %s:%d", *addr)
            return

        if msg.is_request:
            await self._transaction_layer.handle_request(msg, addr)
        else:
            await self._transaction_layer.handle_response(msg, addr)

    async def _on_transaction_request(self, msg: SIPMessage, addr: Tuple[str, int]):
        """Handle a SIP request after transaction layer processing."""
        # Check if this is an in-dialog request
        dialog = self._dialog_manager.find_dialog(
            call_id=msg.call_id,
            local_tag=msg.to_tag,
            remote_tag=msg.from_tag,
        )

        request_info = {
            "method": msg.method,
            "request_uri": msg.request_uri,
            "call_id": msg.call_id,
            "from_uri": msg.from_uri,
            "from_tag": msg.from_tag,
            "to_uri": msg.to_uri,
            "to_tag": msg.to_tag,
            "cseq": msg.cseq,
            "contact": msg.contact,
            "sdp": msg.body if "application/sdp" in msg.content_type else None,
            "display_name": self._extract_display_name(msg.get_header("From") or ""),
            "source_address": addr,
            "transaction_id": msg.via_branch,
            "dialog_id": dialog.dialog_id if dialog else None,
        }

        if self.on_request:
            await self.on_request(request_info)

    async def _on_transaction_response(self, msg: SIPMessage, addr: Tuple[str, int]):
        """Handle a SIP response after transaction layer processing."""
        # Update dialog state for 2xx to INVITE
        if msg.cseq_method == "INVITE" and 200 <= msg.status_code < 300:
            dialog = self._dialog_manager.create_or_update_dialog(
                call_id=msg.call_id,
                local_tag=msg.from_tag,
                remote_tag=msg.to_tag,
                local_uri=msg.from_uri,
                remote_uri=msg.to_uri,
                remote_contact=msg.contact,
                route_set=msg.get_all_headers("Record-Route"),
            )
            dialog_id = dialog.dialog_id
        else:
            dialog = self._dialog_manager.find_dialog(
                call_id=msg.call_id,
                local_tag=msg.from_tag,
                remote_tag=msg.to_tag,
            )
            dialog_id = dialog.dialog_id if dialog else None

        # Extract media info from SDP
        media_address = None
        media_port = None
        if msg.body and "application/sdp" in (msg.content_type or ""):
            media_address, media_port = self._extract_media_from_sdp(msg.body)

        response_info = {
            "status_code": msg.status_code,
            "reason": msg.reason_phrase,
            "call_id": msg.call_id,
            "cseq": msg.cseq,
            "cseq_method": msg.cseq_method,
            "from_tag": msg.from_tag,
            "to_tag": msg.to_tag,
            "contact": msg.contact,
            "sdp": msg.body if msg.body else None,
            "dialog_id": dialog_id,
            "media_address": media_address,
            "media_port": media_port,
        }

        if self.on_response:
            await self.on_response(response_info)

    async def send_invite(
        self,
        from_uri: str,
        to_uri: str,
        call_id: str,
        sdp: str,
        trunk: "SIPTrunk" = None,
        display_name: str = "",
    ):
        """
        Send a SIP INVITE request.

        Constructs a properly formatted INVITE with:
        - Via header with branch parameter
        - From/To with tags
        - Call-ID, CSeq
        - Contact header
        - SDP body
        """
        from_tag = self._generate_tag()
        branch = self._generate_branch()
        cseq = self._next_cseq()

        # Determine destination
        if trunk:
            dest_host = trunk.host
            dest_port = trunk.port
            request_uri = f"sip:{to_uri}@{trunk.host}:{trunk.port}"
        else:
            parsed = SIPURI.parse(to_uri)
            dest_host = parsed.host
            dest_port = parsed.port
            request_uri = to_uri

        msg = self._message_builder.build_invite(
            request_uri=request_uri,
            from_uri=from_uri,
            from_tag=from_tag,
            to_uri=to_uri,
            call_id=call_id,
            cseq=cseq,
            branch=branch,
            contact=f"sip:gateway@{self.domain}:{self.listen_port}",
            sdp=sdp,
            display_name=display_name,
            listen_address=self.listen_address,
            listen_port=self.listen_port,
        )

        # Create client transaction
        await self._transaction_layer.create_client_transaction(
            message=msg,
            destination=(dest_host, dest_port),
            transaction_type=TransactionType.INVITE_CLIENT,
        )

        logger.info("INVITE sent to %s:%d (Call-ID: %s)", dest_host, dest_port, call_id)

    async def send_response(
        self,
        dialog_id: str = None,
        transaction_id: str = None,
        status_code: int = 200,
        reason: str = "OK",
        sdp: str = None,
    ):
        """Send a SIP response."""
        msg = self._message_builder.build_response(
            status_code=status_code,
            reason=reason,
            sdp=sdp,
        )
        if self._transport:
            await self._transaction_layer.send_response(
                transaction_id=transaction_id or dialog_id,
                message=msg,
            )

    async def send_ack(self, dialog_id: str):
        """Send ACK for a 2xx response (completes INVITE handshake)."""
        dialog = self._dialog_manager.get_dialog(dialog_id)
        if not dialog:
            logger.warning("Cannot send ACK: dialog %s not found", dialog_id)
            return

        msg = self._message_builder.build_ack(
            dialog=dialog,
            branch=self._generate_branch(),
            cseq=dialog.local_cseq,
            listen_address=self.listen_address,
            listen_port=self.listen_port,
        )

        dest = dialog.get_next_hop()
        if self._transport:
            await self._transport.send(msg.encode("utf-8"), dest)

    async def send_bye(self, dialog_id: str):
        """Send BYE to terminate a dialog."""
        dialog = self._dialog_manager.get_dialog(dialog_id)
        if not dialog:
            return

        cseq = self._next_cseq()
        branch = self._generate_branch()

        msg = self._message_builder.build_bye(
            dialog=dialog,
            branch=branch,
            cseq=cseq,
            listen_address=self.listen_address,
            listen_port=self.listen_port,
        )

        dest = dialog.get_next_hop()
        await self._transaction_layer.create_client_transaction(
            message=msg,
            destination=dest,
            transaction_type=TransactionType.NON_INVITE_CLIENT,
        )

        self._dialog_manager.terminate_dialog(dialog_id)
        logger.info("BYE sent for dialog %s", dialog_id)

    async def send_reinvite_hold(self, dialog_id: str):
        """Send re-INVITE with sendonly SDP to put call on hold."""
        dialog = self._dialog_manager.get_dialog(dialog_id)
        if not dialog:
            return

        cseq = self._next_cseq()
        branch = self._generate_branch()

        hold_sdp = self._message_builder.build_hold_sdp(
            address=self.listen_address,
        )

        msg = self._message_builder.build_reinvite(
            dialog=dialog,
            branch=branch,
            cseq=cseq,
            sdp=hold_sdp,
            listen_address=self.listen_address,
            listen_port=self.listen_port,
        )

        dest = dialog.get_next_hop()
        await self._transaction_layer.create_client_transaction(
            message=msg,
            destination=dest,
            transaction_type=TransactionType.INVITE_CLIENT,
        )

    async def send_reinvite_unhold(self, dialog_id: str):
        """Send re-INVITE with sendrecv SDP to resume from hold."""
        dialog = self._dialog_manager.get_dialog(dialog_id)
        if not dialog:
            return

        cseq = self._next_cseq()
        branch = self._generate_branch()

        unhold_sdp = self._message_builder.build_unhold_sdp(
            address=self.listen_address,
        )

        msg = self._message_builder.build_reinvite(
            dialog=dialog,
            branch=branch,
            cseq=cseq,
            sdp=unhold_sdp,
            listen_address=self.listen_address,
            listen_port=self.listen_port,
        )

        dest = dialog.get_next_hop()
        await self._transaction_layer.create_client_transaction(
            message=msg,
            destination=dest,
            transaction_type=TransactionType.INVITE_CLIENT,
        )

    async def send_refer(self, dialog_id: str, refer_to: str):
        """Send REFER for call transfer."""
        dialog = self._dialog_manager.get_dialog(dialog_id)
        if not dialog:
            return

        cseq = self._next_cseq()
        branch = self._generate_branch()

        msg = self._message_builder.build_refer(
            dialog=dialog,
            refer_to=refer_to,
            branch=branch,
            cseq=cseq,
            listen_address=self.listen_address,
            listen_port=self.listen_port,
        )

        dest = dialog.get_next_hop()
        await self._transaction_layer.create_client_transaction(
            message=msg,
            destination=dest,
            transaction_type=TransactionType.NON_INVITE_CLIENT,
        )

    @staticmethod
    def _extract_display_name(from_header: str) -> str:
        """Extract display name from From header value."""
        match = re.match(r'^"?([^"<]+)"?\s*<', from_header)
        if match:
            return match.group(1).strip()
        return ""

    @staticmethod
    def _extract_media_from_sdp(sdp: str) -> Tuple[Optional[str], Optional[int]]:
        """Extract media address and port from SDP body."""
        address = None
        port = None

        for line in sdp.split("\n"):
            line = line.strip()
            if line.startswith("c=IN IP4 "):
                address = line.split()[-1]
            elif line.startswith("m=audio "):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        port = int(parts[1])
                    except ValueError:
                        pass

        return address, port
