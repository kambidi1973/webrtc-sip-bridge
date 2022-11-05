"""
SIP Registrar
==============

Handles SIP REGISTER requests and manages address-of-record (AOR)
to contact URI bindings per RFC 3261 Section 10.

The registrar maintains a binding table that maps each AOR
(e.g., sip:alice@example.com) to one or more contact addresses
where the user agent can be reached.

Author: Gopala Rao Kambidi <kambidi@gmail.com>
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Default registration expiry (seconds), per RFC 3261
DEFAULT_EXPIRES = 3600
MIN_EXPIRES = 60
MAX_EXPIRES = 86400


@dataclass
class Registration:
    """
    Represents a SIP registration binding.

    Maps an address-of-record (AOR) to a contact URI with
    associated metadata (expiry, transport, user agent info).
    """
    aor: str                    # Address of Record (sip:user@domain)
    contact_uri: str            # Contact URI (sip:user@ip:port)
    expires: int = DEFAULT_EXPIRES
    registered_at: float = field(default_factory=time.time)
    call_id: str = ""           # Call-ID of the REGISTER request
    cseq: int = 0               # CSeq of the REGISTER request
    user_agent: str = ""        # User-Agent header value
    source_address: Tuple[str, int] = ("", 0)
    transport: str = "udp"
    q_value: float = 1.0        # Priority (0.0 - 1.0)
    instance_id: str = ""       # +sip.instance for GRUU

    @property
    def expires_at(self) -> float:
        """Absolute time when this registration expires."""
        return self.registered_at + self.expires

    @property
    def is_expired(self) -> bool:
        """Check if the registration has expired."""
        return time.time() > self.expires_at

    @property
    def remaining_ttl(self) -> int:
        """Seconds remaining until expiry."""
        remaining = self.expires_at - time.time()
        return max(0, int(remaining))


class SipRegistrar:
    """
    SIP registration service.

    Manages the binding table for user registrations, handling
    REGISTER requests, contact lookup, and expiry cleanup.
    """

    def __init__(self, default_expires: int = DEFAULT_EXPIRES):
        self.default_expires = default_expires
        # AOR -> list of active registrations (one AOR can have multiple contacts)
        self._bindings: Dict[str, List[Registration]] = {}

    def register(
        self,
        aor: str,
        contact_uri: str,
        expires: Optional[int] = None,
        call_id: str = "",
        cseq: int = 0,
        user_agent: str = "",
        source_address: Tuple[str, int] = ("", 0),
        transport: str = "udp",
        q_value: float = 1.0,
    ) -> Registration:
        """
        Register or refresh a contact binding for an AOR.

        If a binding already exists for this AOR + contact_uri,
        it is refreshed. Otherwise, a new binding is created.
        Per RFC 3261 Section 10.3, the registrar validates the
        request and updates the binding table.
        """
        # Clamp expires value
        if expires is None:
            expires = self.default_expires
        expires = max(MIN_EXPIRES, min(MAX_EXPIRES, expires))

        if aor not in self._bindings:
            self._bindings[aor] = []

        # Check for existing binding with same contact
        for reg in self._bindings[aor]:
            if reg.contact_uri == contact_uri:
                # Validate CSeq ordering (RFC 3261 Section 10.3 step 7)
                if reg.call_id == call_id and cseq <= reg.cseq:
                    logger.warning(
                        "Stale REGISTER for %s: CSeq %d <= %d",
                        aor, cseq, reg.cseq,
                    )
                    return reg

                # Refresh existing binding
                reg.expires = expires
                reg.registered_at = time.time()
                reg.call_id = call_id
                reg.cseq = cseq
                reg.user_agent = user_agent
                reg.source_address = source_address
                logger.info(
                    "Registration refreshed: %s -> %s (expires: %ds)",
                    aor, contact_uri, expires,
                )
                return reg

        # Create new binding
        registration = Registration(
            aor=aor,
            contact_uri=contact_uri,
            expires=expires,
            call_id=call_id,
            cseq=cseq,
            user_agent=user_agent,
            source_address=source_address,
            transport=transport,
            q_value=q_value,
        )
        self._bindings[aor].append(registration)
        logger.info(
            "New registration: %s -> %s (expires: %ds)",
            aor, contact_uri, expires,
        )
        return registration

    def unregister(self, aor: str, contact_uri: Optional[str] = None) -> bool:
        """
        Remove a registration binding.

        If contact_uri is None or '*', removes all bindings for the AOR.
        Otherwise, removes only the specified contact binding.
        """
        if aor not in self._bindings:
            return False

        if contact_uri is None or contact_uri == "*":
            del self._bindings[aor]
            logger.info("All registrations removed for %s", aor)
            return True

        bindings = self._bindings[aor]
        original_count = len(bindings)
        self._bindings[aor] = [
            r for r in bindings if r.contact_uri != contact_uri
        ]

        if not self._bindings[aor]:
            del self._bindings[aor]

        removed = original_count - len(self._bindings.get(aor, []))
        if removed > 0:
            logger.info("Registration removed: %s -> %s", aor, contact_uri)
        return removed > 0

    def lookup(self, aor: str) -> List[Registration]:
        """
        Look up active (non-expired) contacts for an AOR.

        Returns contacts sorted by q-value (highest priority first).
        Expired bindings are filtered out.
        """
        bindings = self._bindings.get(aor, [])
        active = [r for r in bindings if not r.is_expired]

        # Update stored list to remove expired entries
        if len(active) != len(bindings):
            self._bindings[aor] = active

        # Sort by q-value descending (highest priority first)
        return sorted(active, key=lambda r: r.q_value, reverse=True)

    def expire_registrations(self) -> int:
        """
        Remove all expired registration bindings.

        Should be called periodically (e.g., every 60 seconds)
        to clean up stale registrations.

        Returns:
            Number of expired registrations removed.
        """
        expired_count = 0
        empty_aors = []

        for aor, bindings in self._bindings.items():
            active = [r for r in bindings if not r.is_expired]
            expired_count += len(bindings) - len(active)
            if active:
                self._bindings[aor] = active
            else:
                empty_aors.append(aor)

        for aor in empty_aors:
            del self._bindings[aor]

        if expired_count > 0:
            logger.info("Expired %d registration(s)", expired_count)

        return expired_count

    def get_all_aors(self) -> List[str]:
        """Return all registered addresses of record."""
        return list(self._bindings.keys())

    @property
    def total_bindings(self) -> int:
        """Total number of active registration bindings."""
        return sum(len(b) for b in self._bindings.values())
