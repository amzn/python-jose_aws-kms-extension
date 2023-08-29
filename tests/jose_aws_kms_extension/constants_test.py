# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from jose.constants import ALGORITHMS


def test_algorithms_contain_kms_cryptographic_algorithms() -> None:
    assert ALGORITHMS.KMS_CRYPTOGRAPHIC_ALGORITHMS.issubset(ALGORITHMS.SUPPORTED)
    assert ALGORITHMS.KMS_CRYPTOGRAPHIC_ALGORITHMS.issubset(ALGORITHMS.ALL)


def test_algorithms_contain_parent_class_and_kms_hashes() -> None:
    assert len(ALGORITHMS.HASHES.keys()) == 18  # Total number of hash algorithms defined in the parent and child class.
    assert 'HS256' in ALGORITHMS.HASHES  # Hash algorithm defined in the parent class.
    assert 'RSASSA_PKCS1_V1_5_SHA_256' in ALGORITHMS.HASHES  # Hash algorithm defined in the child class.
