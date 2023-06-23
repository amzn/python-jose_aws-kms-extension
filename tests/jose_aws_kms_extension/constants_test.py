from jose.constants import ALGORITHMS


def test_algorithms_contain_kms_cryptographic_algorithms() -> None:
    assert ALGORITHMS.KMS_CRYPTOGRAPHIC_ALGORITHMS.issubset(ALGORITHMS.SUPPORTED)
    assert ALGORITHMS.KMS_CRYPTOGRAPHIC_ALGORITHMS.issubset(ALGORITHMS.ALL)
