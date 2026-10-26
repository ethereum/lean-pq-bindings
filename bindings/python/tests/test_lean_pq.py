import py_lean_pq as lpq
import pytest

MESSAGE = b"\x42" * 32
OTHER_MESSAGE = b"\x43" * 32


def test_xmss_signs_and_verifies():
    key = lpq.XmssSecretKey.from_seed(b"\x01" * 32)
    key.prepare(3)
    signature = key.sign(MESSAGE, 3)

    assert lpq.xmss_verify(key.public_key, MESSAGE, signature) is None
    with pytest.raises(lpq.LeanPqError):
        lpq.xmss_verify(key.public_key, OTHER_MESSAGE, signature)


def test_sphincs_signs_and_verifies():
    key = lpq.SphincsSecretKey.from_seed(b"\x02" * 32, 4)
    signature = key.sign(MESSAGE)

    assert lpq.sphincs_verify(key.public_key, MESSAGE, signature) is None
    with pytest.raises(lpq.LeanPqError):
        lpq.sphincs_verify(key.public_key, OTHER_MESSAGE, signature)


def test_secret_keys_round_trip_through_bytes():
    xmss_key = lpq.XmssSecretKey.from_seed(b"\x03" * 32)
    restored_xmss = lpq.XmssSecretKey.from_bytes(xmss_key.to_bytes())
    assert restored_xmss.public_key == xmss_key.public_key
    lpq.xmss_verify(xmss_key.public_key, MESSAGE, restored_xmss.sign(MESSAGE, 9))

    sphincs_key = lpq.SphincsSecretKey.from_seed(b"\x04" * 32, 3)
    restored_sphincs = lpq.SphincsSecretKey.from_bytes(sphincs_key.to_bytes())
    assert restored_sphincs.public_key == sphincs_key.public_key
    assert restored_sphincs.kept_height == 3
    lpq.sphincs_verify(sphincs_key.public_key, MESSAGE, restored_sphincs.sign(MESSAGE))


def test_aggregates_both_schemes_recursively():
    lpq.setup()
    first = b"\x11" * 32
    second = b"\x22" * 32
    xmss_key = lpq.XmssSecretKey.from_seed(b"\x05" * 32)
    sphincs_key = lpq.SphincsSecretKey.from_seed(b"\x06" * 32, 4)

    left = lpq.aggregate(
        xmss=[(xmss_key.public_key, first, xmss_key.sign(first, 0))]
    )
    right = lpq.aggregate(
        sphincs=[(sphincs_key.public_key, second, sphincs_key.sign(second))]
    )
    root = lpq.aggregate(
        children=[left, right],
        xmss=[(xmss_key.public_key, second, xmss_key.sign(second, 1))],
    )

    received = lpq.Aggregate.from_bytes(root.to_bytes())
    assert received.xmss_claims == sorted(
        [(xmss_key.public_key, first), (xmss_key.public_key, second)]
    )
    assert received.sphincs_claims == [(sphincs_key.public_key, second)]

    tampered = bytearray(root.to_bytes())
    tampered[-1] ^= 1
    with pytest.raises(lpq.LeanPqError):
        lpq.Aggregate.from_bytes(bytes(tampered))
