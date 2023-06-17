from jose.constants import ALGORITHMS


def test_algorithm_contains_kms_symmetric_algorithms() -> None:
    assert ALGORITHMS.SYMMETRIC_DEFAULT in ALGORITHMS.SUPPORTED
    assert ALGORITHMS.SYMMETRIC_DEFAULT in ALGORITHMS.ALL
