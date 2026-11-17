import pytest

from auth.token_verify import (
    decode_header,
    key_for_kid,
    verify_signature,
    validate_claims,
    revoke
)


def test_header():
    assert decode_header('eyJhbGciOiJIUzI1NiIsImtpZCI6ImsxIn0') == {'alg': 'HS256', 'kid': 'k1'}

def test_alg_none():
    assert verify_signature('none', b'', b'', 'x') is False

def test_alg_mismatch():
    assert verify_signature('HS256', b'k', b'x', 'RS256') is False

def test_kid_valid():
    assert key_for_kid({ 'k1': b'a' }, 'k1') == b'a'

def test_kid_unknown():
    assert key_for_kid({ 'k1': b'a' }, 'k2') is None

def test_signature_valid():
    assert verify_signature('HS256', b'secret', b'payload', 'HS256') is True

def test_signature_bad():
    assert verify_signature('HS256', b'wrong', b'payload', 'HS256') is False

def test_audience_ok():
    assert validate_claims({'aud': 'api', 'iss': 'idp', 'exp': 200}, 100, 'api', 'idp') is True

def test_audience_bad():
    assert validate_claims({'aud': 'other', 'iss': 'idp', 'exp': 200}, 100, 'api', 'idp') is False

def test_issuer_bad():
    assert validate_claims({'aud': 'api', 'iss': 'evil', 'exp': 200}, 100, 'api', 'idp') is False

def test_exp_ok():
    assert validate_claims({'aud': 'api', 'iss': 'idp', 'exp': 200}, 100, 'api', 'idp') is True

def test_expired():
    assert validate_claims({'aud': 'api', 'iss': 'idp', 'exp': 90}, 100, 'api', 'idp') is False

def test_skew():
    assert validate_claims({'aud': 'api', 'iss': 'idp', 'exp': 95}, 100, 'api', 'idp', skew=10) is True

def test_revoked():
    assert validate_claims({'aud': 'api', 'iss': 'idp', 'exp': 200, 'jti': 'r1'}, 100, 'api', 'idp', revoked={'r1'}) is False

def test_rotation_grace():
    assert validate_claims({'aud': 'api', 'iss': 'idp', 'exp': 200, 'kid': 'old'}, 100, 'api', 'idp', old_kids={'old'}, grace=30) is True
