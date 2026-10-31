"""TTL/TCP-window OS fingerprinting for the stealth scan (-os).

IPv4 reply leaks the initial TTL and the TCP window; turn that pair into a OS guess.
"""

from typing import Dict, FrozenSet, Iterable, NamedTuple, Optional, Tuple

CANONICAL_TTLS = (64, 128, 255)

LINUX = "Linux"
WINDOWS = "Windows"
NETWORK_GEAR = "Network gear"
UNKNOWN = "Unknown"

MODERATE = "moderate"
LOW = "low"
CONFIDENCE_LEVELS = (MODERATE, LOW)

# Beyond this many hops the TTL bucket is more likely an accident
MAX_PLAUSIBLE_HOPS = 30

_MATCH = "match"
_SHARED = "shared"
_UNKNOWN = "unknown"
_CONFLICT = "conflict"


class Signature(NamedTuple):
    """initial TTL and typical window values."""

    os_guess: str
    initial_ttl: int
    windows: FrozenSet[int]


SIGNATURES = (
    Signature(LINUX, 64, frozenset({5840, 14600, 65535})),
    Signature(WINDOWS, 128, frozenset({8192, 64240, 65535})),
    # Network gear picks freely (often 0 or tiny), so the TTL
    # is the only usable signal for this family.
    Signature(NETWORK_GEAR, 255, frozenset()),
)

FAMILY_BY_TTL: Dict[int, str] = {
    signature.initial_ttl: signature.os_guess for signature in SIGNATURES
}
WINDOWS_BY_FAMILY: Dict[str, FrozenSet[int]] = {
    signature.os_guess: signature.windows for signature in SIGNATURES
}


class Fingerprint(NamedTuple):
    """Coarse OS family and how much the reply supports it."""

    os_guess: str
    confidence: str


class OsGuess(NamedTuple):
    os_guess: str
    confidence: str
    ttl: Optional[int]
    window: Optional[int]

NO_REPLY = OsGuess(UNKNOWN, LOW, None, None)

# detect_os() ranking: stronger confidence first, then a known family over Unknown.
_CONFIDENCE_RANK = {MODERATE: 1, LOW: 0}


def canonical_ttl(ttl: Optional[int]) -> Optional[int]:
    """Round an observed TTL up to the nearest initial TTL (64/128/255).

    Returns None for a value that cannot appear on the wire rather than crash."""
    if not _valid_ttl(ttl):
        return None
    for initial in CANONICAL_TTLS:
        if ttl <= initial:
            return initial
    return CANONICAL_TTLS[-1]  # unreachable for a validated TTL


def estimate_hops(ttl: Optional[int]) -> Optional[int]:
    initial = canonical_ttl(ttl)
    if initial is None:
        return None
    return initial - ttl


def fingerprint(
    ttl: Optional[int],
    window: Optional[int],
) -> Fingerprint:
    """Guess the OS family from one reply's TTL and TCP window."""
    initial = canonical_ttl(ttl)
    hops = estimate_hops(ttl)
    if initial is None or hops is None:
        return Fingerprint(UNKNOWN, LOW)

    family = FAMILY_BY_TTL[initial]
    if hops > MAX_PLAUSIBLE_HOPS:
        # The bucket was reached by too many hops to trust.
        return Fingerprint(family, LOW)

    if family == NETWORK_GEAR:
        # Only an exact 255 is useful: gear windows vary by vendor.
        confidence = MODERATE if hops == 0 else LOW
        return Fingerprint(family, confidence)

    relation = _window_relation(family, window)
    if relation == _CONFLICT:
        # TTL says one family, window says the other: do not pick sides.
        return Fingerprint(UNKNOWN, LOW)
    if relation == _MATCH:
        return Fingerprint(family, MODERATE)
    if relation == _SHARED and hops == 0:
        # The window fits both desktop families
        return Fingerprint(family, MODERATE)
    return Fingerprint(family, LOW)


def detect_os(replies: Iterable[Tuple[int, int]]) -> OsGuess:
    """Pick the strongest fingerprint from (ttl, window) reply pairs.

    Moderate beats low; a known family beats Unknown at the same
    confidence."""

    best = NO_REPLY
    best_rank = (-1, False)
    for ttl, window in replies:
        guess = fingerprint(ttl, window)
        rank = (_CONFIDENCE_RANK.get(guess.confidence, 0),
                guess.os_guess != UNKNOWN)
        if rank > best_rank:
            best = OsGuess(guess.os_guess, guess.confidence, ttl, window)
            best_rank = rank
    return best


def _valid_ttl(ttl: Optional[int]) -> bool:
    return (isinstance(ttl, int) and not isinstance(ttl, bool)
            and 1 <= ttl <= 255)


def _valid_window(window: Optional[int]) -> bool:
    return (isinstance(window, int) and not isinstance(window, bool)
            and 0 <= window <= 0xFFFF)


def _window_relation(family: str, window: Optional[int]) -> str:
    """Classify window against a desktop family's signature value."""
    if not _valid_window(window):
        return _UNKNOWN
    own = WINDOWS_BY_FAMILY[family]
    other = WINDOWS if family == LINUX else LINUX
    if window not in own:
        if window in WINDOWS_BY_FAMILY[other]:
            return _CONFLICT
        return _UNKNOWN
    if window in WINDOWS_BY_FAMILY[other]:
        return _SHARED
    return _MATCH
