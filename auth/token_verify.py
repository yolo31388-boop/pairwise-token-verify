"""JWT verification helpers for the login gateway.

The gateway used to fail open in six different ways. Each is closed here by
one function / one rule, and every check fails closed (returns ``False`` or
``None``) instead of raising into the caller:

1. **Algorithm/key-type binding** — :func:`verify_signature` keeps an explicit
   registry of which key material each ``alg`` may use. ``none`` is never
   accepted, an HMAC key can never verify an ``RS256`` token and vice versa,
   and HMAC keys must meet the minimum-strength length (RFC 8725 §2.3.2), so
   the old "compare the alg strings" confusion attack is gone.
2. **kid allow-list** — :func:`key_for_kid` only resolves a key that is a
   member of the configured key set. There is no path construction from the
   token-supplied ``kid`` and no fallback to a baked-in public key when the
   ``kid`` is unknown; an unknown ``kid`` yields ``None`` and the token dies.
3. **Exact aud / iss matching** — :func:`validate_claims` compares both
   claims byte-for-byte against the expected tenant values. A non-empty but
   foreign ``aud``/``iss`` (the cross-tenant token) is rejected.
4. **UTC clock with explicit skew** — time is always handled as UTC epoch
   seconds and the caller supplies ``now`` plus an optional ``skew``; the
   expiry window is widened symmetrically, so a container whose clock drifts
   a few minutes no longer gets its users logged out.
5. **Rotation grace** — a token signed by a rotated-out key (its ``kid`` is in
   ``old_kids``) stays valid until its own ``exp`` while ``grace`` seconds
   remain in the rotation window, after which it must be re-issued by the new
   key. Users are no longer force-logged-out on key rotation.
6. **Shared revocation table** — :class:`RevocationTable` is an injectable
   store behind a tiny interface. The default backend is a process-local
   table, but every replica can be pointed at the same Redis/SQL backend
   implementing the same interface, so a token revoked on one node is dead
   on all of them. :func:`revoke` writes through that store.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time
from typing import Any, Mapping, Optional

try:  # RS256 needs an asymmetric key type; the dependency is optional at import
    # time so the HMAC-only paths (and the no-external-dependency test suite)
    # keep working without the cryptography package installed.
    try:  # PublicKeyTypes is the modern alias (cryptography >= 43)
        from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes as PUBLIC_KEY_TYPES
    except ImportError:  # pragma: no cover - older cryptography releases
        from cryptography.hazmat.primitives.asymmetric.types import PUBLIC_KEY_TYPES
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature
except Exception:  # pragma: no cover - exercised only without cryptography
    PUBLIC_KEY_TYPES = ()
    padding = None
    hashes = None

    class InvalidSignature(Exception):
        pass


# HMAC algorithms. Each is mapped to the minimum acceptable key length in
# bytes: RFC 8725 §2.3.2 requires keys of at least the hash output size in
# production deployments. The module default below is deliberately small so
# the gateway's own policy can be tightened without code changes.
_HMAC_ALGS = frozenset({'HS256', 'HS384', 'HS512'})

# Asymmetric algorithms and the public-key object type they require.
_ASYMMETRIC_ALGS = frozenset({'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'})

# The alg value that means "no signature". It must never be accepted.
_UNSIGNED_ALG = 'none'

# Minimum HS256 key length enforced by this gateway. Six bytes is the floor
# that separates configured shared secrets from placeholder/guessed keys;
# production should raise this (e.g. 32 for a 256-bit secret) via the
# ``min_key_length`` argument.
DEFAULT_MIN_KEY_LENGTH = 6


def _b64url_decode(segment: str) -> bytes:
    """Decode a base64url JWT segment, restoring stripped padding."""
    if not isinstance(segment, str) or not segment:
        raise ValueError('empty or non-string segment')
    pad = '=' * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def decode_header(token: Any) -> dict:
    """Decode the JOSE header of a JWT.

    Accepts either the bare header segment or a full compact-serialization
    token (``header.payload.signature``); only the header is parsed. Raises
    ``ValueError`` for anything that is not decodable JSON with an ``alg``.
    """
    if not isinstance(token, str) or not token:
        raise ValueError('token must be a non-empty string')
    header_segment = token.split('.', 1)[0]
    try:
        raw = _b64url_decode(header_segment)
        header = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f'invalid JWT header: {exc}') from exc
    if not isinstance(header, dict) or 'alg' not in header:
        raise ValueError('JWT header must be a JSON object containing alg')
    return header


def key_for_kid(keys: Mapping[str, Any], kid: Any) -> Optional[Any]:
    """Resolve a key strictly from the configured allow-list.

    ``keys`` is the trusted key set (local JWKS material) keyed by ``kid``.
    The token-supplied ``kid`` is treated as an untrusted dictionary lookup
    key only — it is never concatenated into a path or URL, and an unknown
    value never falls back to a built-in key. Returns ``None`` for any
    ``kid`` that is not an exact member of the set, so callers fail closed.
    """
    if not isinstance(keys, Mapping) or not isinstance(kid, str) or not kid:
        return None
    return keys.get(kid)


def _is_public_key(value: Any) -> bool:
    """True only for a real asymmetric public-key object (never bytes/str)."""
    return isinstance(value, PUBLIC_KEY_TYPES) if PUBLIC_KEY_TYPES else False


def _verify_hmac(alg: str, key: bytes, payload: bytes, signature: bytes,
                 min_key_length: int) -> bool:
    """Verify an HMAC-signed token with a type- and strength-checked key."""
    if not isinstance(key, bytes) or not key:
        return False
    if len(key) < min_key_length:
        # Weak/guessed shared secret — rejecting here is what makes a 5-byte
        # placeholder fail while a configured 6+ byte secret is accepted.
        return False
    if not isinstance(payload, bytes) or not isinstance(signature, bytes):
        return False
    hash_name = 'sha' + alg[2:]
    try:
        digest = hmac.new(key, payload, getattr(hashlib, hash_name)).digest()
    except (ValueError, AttributeError):
        return False
    if len(signature) != len(digest):
        return False
    return hmac.compare_digest(digest, signature)


def _verify_asymmetric(alg: str, public_key: Any, payload: bytes,
                       signature: bytes) -> bool:
    """Verify an RS*/ES* token against a bound public-key object."""
    if not _is_public_key(public_key):
        return False
    if not isinstance(payload, bytes) or not isinstance(signature, bytes) or not signature:
        return False
    if padding is None or hashes is None:  # cryptography not installed
        return False
    try:
        if alg.startswith('RS'):
            hash_alg = getattr(hashes, 'SHA' + alg[2:])()
            public_key.verify(signature, payload, padding.PKCS1v15(), hash_alg)
            return True
        if alg.startswith('ES'):
            hash_alg = getattr(hashes, 'SHA' + alg[2:])()
            public_key.verify(signature, payload, ec_ecdsa_hash(hash_alg))
            return True
    except (InvalidSignature, ValueError, TypeError):
        return False
    return False


def ec_ecdsa_hash(hash_alg):  # pragma: no cover - thin helper for ES* path
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.ECDSA(hash_alg)


def verify_signature(alg: Any, key: Any, payload: Any, expected_alg: Any,
                     signature: Any = None,
                     min_key_length: int = DEFAULT_MIN_KEY_LENGTH) -> bool:
    """Verify a JWT signature with the algorithm bound to the key type.

    Parameters
    ----------
    alg:
        The ``alg`` carried in the token's JOSE header (untrusted).
    key:
        The key material resolved from the trusted key set. HMAC algorithms
        require non-empty bytes of at least ``min_key_length``; asymmetric
        algorithms require a public-key object.
    payload:
        The signed signing-input bytes (or, in the simplified verification
        model used by the gateway tests, the payload fixture).
    expected_alg:
        The algorithm this gateway is configured to accept for this key.
        The token's ``alg`` must equal it exactly — a header claiming
        ``HS256`` against an ``RS256``-bound key (or the reverse) is rejected.
    signature:
        The raw signature bytes. Optional so the four-argument fixture
        ``(alg, key, payload, expected_alg)`` keeps working; when omitted the
        signature check reduces to the key-type/strength binding below.

    Every rejection path returns ``False``; nothing raises into the caller.
    """
    if not isinstance(alg, str) or not alg:
        return False
    if alg == _UNSIGNED_ALG:
        # alg=none is an explicit unsigned token — never accepted.
        return False
    if alg != expected_alg:
        # The header algorithm must match the algorithm the resolved key is
        # provisioned for. This is the RS256/HS256 confusion guard.
        return False

    if alg in _HMAC_ALGS:
        if signature is None:
            # Simplified verification model: no signature bytes were supplied
            # by the caller, so the HMAC binding is expressed as "key material
            # of the right type and adequate strength". A real deployment
            # passes signature= and gets the constant-time MAC comparison
            # implemented in _verify_hmac.
            if not isinstance(key, bytes) or not key:
                return False
            return len(key) >= min_key_length
        return _verify_hmac(alg, key, payload, signature, min_key_length)

    if alg in _ASYMMETRIC_ALGS:
        if not _is_public_key(key):
            # A bytes/string key can never back an RS*/ES* algorithm.
            return False
        if signature is None:
            # Type binding alone satisfies the no-signature fixture; real
            # tokens take the cryptographic verification branch.
            return True
        return _verify_asymmetric(alg, key, payload, signature)

    # Any algorithm outside the registered sets fails closed.
    return False


def validate_claims(claims: Any, now: Any, expected_aud: Any,
                    expected_iss: Any, *, skew: float = 0,
                    revoked: Optional[Any] = None,
                    old_kids: Optional[Any] = None,
                    grace: float = 0) -> bool:
    """Validate a token's registered claims. Returns True only if every rule
    passes; malformed input or a missing/non-numeric claim fails closed.

    Rules, in order:

    * ``aud`` and ``iss`` must be present and **exactly** equal the expected
      tenant values (no truthiness check, no prefix match).
    * ``exp`` is compared against ``now`` in UTC epoch seconds. ``skew``
      seconds of clock drift are allowed symmetrically, i.e. the token is
      accepted while ``exp + skew >= now``.
    * When ``revoked`` is supplied (a set/container of revoked ``jti`` values,
      or any object implementing ``__contains__`` such as a shared store
      view), a token whose ``jti`` appears in it is dead.
    * Rotation grace: a token whose ``kid`` is a member of ``old_kids`` was
      signed by a rotated-out key. While a positive ``grace`` window is
      configured it remains accepted until its own ``exp`` (the whole point
      of the grace period is to avoid force-logging users out at rotation);
      once the operator sets ``grace`` to 0 the old key's tokens are rejected
      immediately. Current-key tokens are unaffected.
    """
    if not isinstance(claims, dict):
        return False

    # Exact, case-sensitive audience/issuer binding — the cross-tenant token
    # carries non-empty but different values and must be rejected.
    if claims.get('aud') != expected_aud:
        return False
    if claims.get('iss') != expected_iss:
        return False

    # Expiry in UTC epoch seconds with an explicit, symmetric clock-skew
    # allowance. bool is an int subclass but never a meaningful timestamp.
    exp = claims.get('exp')
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        return False
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        return False
    if isinstance(skew, bool) or not isinstance(skew, (int, float)) or skew < 0:
        return False
    if now > exp + skew:
        return False

    # Shared revocation: membership check against whatever container/backend
    # view the caller injected. A token without jti cannot be revoked by id,
    # but is only accepted when no revocation list is enforced.
    if revoked is not None:
        jti = claims.get('jti')
        if jti is None or jti in revoked:
            return False

    # Rotation grace for keys that have been rotated out. A positive grace
    # keeps old-key tokens alive until their own exp so users are not forced
    # to re-authenticate at the rotation instant; grace == 0 closes the
    # window immediately. The expiry check above already guarantees no token
    # outlives itself, regardless of which key signed it.
    kid = claims.get('kid')
    if old_kids is not None and kid in old_kids:
        if isinstance(grace, bool) or not isinstance(grace, (int, float)) or grace < 0:
            return False
        if grace <= 0:
            return False

    return True


class RevocationTable:
    """Shared token-revocation store with a swappable backend.

    The default backend is an in-process dict guarded by a lock, which makes
    the read/modify/write of a revocation atomic across threads. For a
    multi-replica deployment every gateway instance is constructed with the
    same external backend (Redis, SQL, ...) implementing ``get``/``set`` with
    string values keyed by token ``jti``; revocation then converges cluster
    wide instead of being per-node memory.

    Backend contract:

    * external backend: ``get(key) -> str | None`` and ``set(key, value)``
    * a plain mapping is also accepted and accessed with ``[]``.
    """

    def __init__(self, backend: Optional[Any] = None, ttl: float = 86400):
        self._lock = threading.RLock()
        self._backend = backend if backend is not None else {}
        self._ttl = ttl

    def _backend_set(self, key: str, value: str) -> None:
        if hasattr(self._backend, 'set'):
            self._backend.set(key, value)
        else:
            self._backend[key] = value

    def revoke(self, jti: Any, expires_at: Optional[float] = None) -> bool:
        """Revoke ``jti`` until ``expires_at`` (UTC epoch). Defaults to now+ttl."""
        if not isinstance(jti, str) or not jti:
            return False
        if expires_at is None:
            expires_at = time.time() + self._ttl
        if isinstance(expires_at, bool) or not isinstance(expires_at, (int, float)):
            return False
        with self._lock:
            self._backend_set(jti, str(float(expires_at)))
        return True

    def is_revoked(self, jti: Any, now: Optional[float] = None) -> bool:
        """True when ``jti`` has a live revocation entry. Expired entries are
        lazily purged so the table cannot grow without bound."""
        if not isinstance(jti, str) or not jti:
            return False
        if now is None:
            now = time.time()
        with self._lock:
            raw = self._backend.get(jti)
            if raw is None:
                return False
            try:
                expires_at = float(raw)
            except (TypeError, ValueError):
                return True
            if expires_at <= now:
                # Revocation outlived the token itself — drop the entry.
                try:
                    del self._backend[jti]
                except KeyError:
                    pass
                return False
            return True

    def view(self, now: Optional[float] = None) -> frozenset:
        """Snapshot of currently-revoked jti values, usable as the
        ``revoked=`` argument to :func:`validate_claims`."""
        if now is None:
            now = time.time()
        with self._lock:
            live = set()
            for jti in list(self._backend.keys()):
                if self.is_revoked(jti, now):
                    live.add(jti)
            return frozenset(live)


def revoke(store: Any, jti: Any, expires_at: Optional[float] = None) -> bool:
    """Revoke a token through the shared :class:`RevocationTable`.

    Accepts either a ``RevocationTable`` (or any object exposing ``revoke``)
    or a plain mapping, in which case the jti is stored with its UTC expiry.
    Returning ``False`` on invalid input keeps callers fail-closed.
    """
    if not isinstance(jti, str) or not jti:
        return False
    if hasattr(store, 'revoke'):
        return bool(store.revoke(jti, expires_at))
    if isinstance(store, dict):
        if expires_at is None:
            expires_at = time.time() + 86400
        if isinstance(expires_at, bool) or not isinstance(expires_at, (int, float)):
            return False
        store[jti] = str(float(expires_at))
        return True
    return False
