"""
SIP Dialog Management
======================

Implements SIP dialog state machine per RFC 3261 Section 12.

A dialog is a peer-to-peer SIP relationship established by specific
SIP methods (INVITE). Dialogs facilitate proper routing of subsequent
requests between two user agents.

Dialog identification uses the triple: (Call-ID, local-tag, remote-tag).

Author: Gopala Rao Kambidi <kambidi@gmail.com>
"""

import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class DialogState(Enum):
    """SIP dialog states per RFC 3261 Section 12."""
    EARLY = "early"           # After 1xx provisional response
    CONFIRMED = "confirmed"   # After 2xx final response
    TERMINATED = "terminated" # After BYE or error


@dataclass
class SipDialog:
    """
    Represents a SIP dialog (RFC 3261 Section 12).

    A dialog is identified by the combination of Call-ID,
    local tag, and remote tag. It tracks the CSeq for both
    directions and maintains the route set for in-dialog
    request routing.
    """
    dialog_id: str
    call_id: str
    local_tag: str
    remote_tag: str
    local_uri: str
    remote_uri: str
    route_set: List[str] = field(default_factory=list)
    local_cseq: int = 0
    remote_cseq: int = 0
    state: DialogState = DialogState.EARLY
    remote_contact: str = ""
    local_contact: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    secure: bool = False

    def get_next_hop(self) -> Tuple[str, int]:
        """
        Determine the next hop for an in-dialog request.

        If a route set exists, use the first route (loose routing).
        Otherwise, use the remote contact/target URI.

        Returns:
            Tuple of (host, port) for the next hop.
        """
        target = self.route_set[0] if self.route_set else self.remote_contact

        if not target:
            target = self.remote_uri

        # Parse host:port from the URI
        host, port = self._parse_host_port(target)
        return host, port

    def increment_local_cseq(self) -> int:
        """Increment and return the local CSeq value."""
        self.local_cseq += 1
        self.updated_at = time.time()
        return self.local_cseq

    def validate_remote_cseq(self, cseq: int) -> bool:
        """
        Validate an incoming CSeq value.

        Per RFC 3261 Section 12.2.2, the remote CSeq must be
        strictly increasing for each new transaction within a dialog.
        """
        if cseq <= self.remote_cseq:
            logger.warning(
                "Out-of-order CSeq in dialog %s: got %d, expected > %d",
                self.dialog_id, cseq, self.remote_cseq,
            )
            return False
        self.remote_cseq = cseq
        self.updated_at = time.time()
        return True

    @staticmethod
    def _parse_host_port(uri: str) -> Tuple[str, int]:
        """Extract host and port from a SIP URI."""
        # Strip angle brackets and sip: prefix
        uri = uri.strip("<>")
        if uri.startswith("sip:") or uri.startswith("sips:"):
            uri = uri.split(":", 1)[1]

        # Strip user part
        if "@" in uri:
            uri = uri.split("@", 1)[1]

        # Strip URI parameters
        if ";" in uri:
            uri = uri.split(";")[0]

        # Extract port
        if ":" in uri:
            host, port_str = uri.rsplit(":", 1)
            try:
                return host, int(port_str)
            except ValueError:
                return host, 5060
        return uri, 5060


class DialogManager:
    """
    Manages active SIP dialogs.

    Provides thread-safe dialog lifecycle management including
    creation, confirmation, termination, and lookup. Supports
    routing of in-dialog requests using the stored route set.
    """

    def __init__(self):
        self._dialogs: Dict[str, SipDialog] = {}
        # Index by (call_id, local_tag, remote_tag) for fast lookup
        self._dialog_index: Dict[Tuple[str, str, str], str] = {}

    def create_dialog(
        self,
        call_id: str,
        local_tag: str,
        remote_tag: str,
        local_uri: str,
        remote_uri: str,
        route_set: Optional[List[str]] = None,
        remote_contact: str = "",
        local_contact: str = "",
        local_cseq: int = 1,
    ) -> SipDialog:
        """
        Create a new dialog in EARLY state.

        Called when sending/receiving a 1xx response to INVITE,
        or when creating a dialog directly from a 2xx.
        """
        dialog_id = str(uuid.uuid4())
        dialog = SipDialog(
            dialog_id=dialog_id,
            call_id=call_id,
            local_tag=local_tag,
            remote_tag=remote_tag,
            local_uri=local_uri,
            remote_uri=remote_uri,
            route_set=list(reversed(route_set)) if route_set else [],
            remote_contact=remote_contact,
            local_contact=local_contact,
            local_cseq=local_cseq,
        )
        self._dialogs[dialog_id] = dialog
        self._dialog_index[(call_id, local_tag, remote_tag)] = dialog_id
        logger.info(
            "Dialog created: %s (Call-ID: %s, state: %s)",
            dialog_id, call_id, dialog.state.value,
        )
        return dialog

    def create_or_update_dialog(
        self,
        call_id: str,
        local_tag: str,
        remote_tag: str,
        local_uri: str,
        remote_uri: str,
        remote_contact: str = "",
        route_set: Optional[List[str]] = None,
    ) -> SipDialog:
        """
        Create a new dialog or update an existing one.

        If a dialog already exists for this (call_id, local_tag, remote_tag)
        triple, update it and confirm it. Otherwise create a new confirmed dialog.
        """
        existing = self.find_dialog(call_id, local_tag, remote_tag)
        if existing:
            existing.remote_contact = remote_contact or existing.remote_contact
            if route_set is not None:
                existing.route_set = list(reversed(route_set))
            if existing.state == DialogState.EARLY:
                existing.state = DialogState.CONFIRMED
            existing.updated_at = time.time()
            return existing

        dialog = self.create_dialog(
            call_id=call_id,
            local_tag=local_tag,
            remote_tag=remote_tag,
            local_uri=local_uri,
            remote_uri=remote_uri,
            route_set=route_set,
            remote_contact=remote_contact,
        )
        dialog.state = DialogState.CONFIRMED
        return dialog

    def confirm_dialog(self, dialog_id: str) -> Optional[SipDialog]:
        """
        Transition a dialog from EARLY to CONFIRMED.

        Called upon receiving a 2xx response to the initial INVITE.
        """
        dialog = self._dialogs.get(dialog_id)
        if dialog and dialog.state == DialogState.EARLY:
            dialog.state = DialogState.CONFIRMED
            dialog.updated_at = time.time()
            logger.info("Dialog confirmed: %s", dialog_id)
        return dialog

    def terminate_dialog(self, dialog_id: str) -> Optional[SipDialog]:
        """
        Terminate a dialog.

        Called when BYE is sent/received or on error conditions.
        The dialog record is kept for a grace period for
        retransmission handling.
        """
        dialog = self._dialogs.get(dialog_id)
        if dialog:
            dialog.state = DialogState.TERMINATED
            dialog.updated_at = time.time()
            logger.info("Dialog terminated: %s", dialog_id)
        return dialog

    def get_dialog(self, dialog_id: str) -> Optional[SipDialog]:
        """Retrieve a dialog by its ID."""
        return self._dialogs.get(dialog_id)

    def find_dialog(
        self, call_id: str, local_tag: str, remote_tag: str,
    ) -> Optional[SipDialog]:
        """
        Find a dialog by the identifying triple.

        Per RFC 3261 Section 12, a dialog is identified by
        (Call-ID, local-tag, remote-tag).
        """
        key = (call_id, local_tag, remote_tag)
        dialog_id = self._dialog_index.get(key)
        if dialog_id:
            return self._dialogs.get(dialog_id)

        # Try without remote tag (early dialog before remote tag assigned)
        for (cid, ltag, rtag), did in self._dialog_index.items():
            if cid == call_id and ltag == local_tag and not rtag:
                return self._dialogs.get(did)

        return None

    def route_request(self, dialog_id: str) -> Optional[Tuple[str, int]]:
        """
        Get the routing destination for an in-dialog request.

        Uses the dialog's route set (from Record-Route headers)
        or falls back to the remote contact URI.
        """
        dialog = self._dialogs.get(dialog_id)
        if not dialog:
            return None
        return dialog.get_next_hop()

    def remove_dialog(self, dialog_id: str):
        """Remove a terminated dialog from storage."""
        dialog = self._dialogs.pop(dialog_id, None)
        if dialog:
            key = (dialog.call_id, dialog.local_tag, dialog.remote_tag)
            self._dialog_index.pop(key, None)

    def cleanup_terminated(self, max_age: float = 300.0):
        """Remove terminated dialogs older than max_age seconds."""
        now = time.time()
        to_remove = [
            did for did, d in self._dialogs.items()
            if d.state == DialogState.TERMINATED
            and (now - d.updated_at) > max_age
        ]
        for did in to_remove:
            self.remove_dialog(did)

    @property
    def active_dialog_count(self) -> int:
        """Number of non-terminated dialogs."""
        return sum(
            1 for d in self._dialogs.values()
            if d.state != DialogState.TERMINATED
        )
