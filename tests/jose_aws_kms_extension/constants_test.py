from jose.constants import ALGORITHMS


def test_algorithms_contain_kms_cryptographic_algorithms() -> None:
    assert ALGORITHMS.KMS_CRYPTOGRAPHIC_ALGORITHMS.issubset(ALGORITHMS.SUPPORTED)
    assert ALGORITHMS.KMS_CRYPTOGRAPHIC_ALGORITHMS.issubset(ALGORITHMS.ALL)


def test_algorithms_contain_parent_class_and_kms_hashes() -> None:
    assert len(ALGORITHMS.HASHES.keys()) == 18  # Total number of hash algorithms defined in the parent and child class.
    assert 'HS256' in ALGORITHMS.HASHES  # Hash algorithm defined in the parent class.
    assert 'RSASSA_PKCS1_V1_5_SHA_256' in ALGORITHMS.HASHES  # Hash algorithm defined in the child class.
