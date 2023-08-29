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

#  type: ignore

"""
Code in the module is temporary. It is present to fill general feature gaps in *python-jose*.
I.e. features which are not related to KMS. Once the features gap(s) are filled, this code should be removed in favour
of the new *python-jose* version.
"""

import json

import pytest
from jose import jwe
from jose.constants import ALGORITHMS, ZIPS
from jose.jwk import AESKey
from jose.utils import base64url_decode

backends = []
try:
    import jose.backends.cryptography_backend  # noqa E402

    backends.append(jose.backends.cryptography_backend)
except ImportError:
    pass

import jose.backends.native  # noqa E402

try:
    from jose.backends.rsa_backend import RSAKey as RSABackendRSAKey
except ImportError:
    RSABackendRSAKey = None

backends.append(jose.backends.native)


PRIVATE_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA3AyQGW/Q8AKJH2Mfjv1c67iYcwIn+Z2tpqHDQQV9CfSx9CMs
+Zg2buopXJ7AWd03ZR08g9O2bmlJPIQV1He3vfzZH9+6aJAQLJ+VzpME2sXl5Boa
yla1JjyoH7ix/i02QHDTVClDMb6dy0rMVpc7cBxwgX54fcR5x3AMscYCTQrhQc7q
YRzoLTfP9lGJT1DgyGcOt4paa77z4uqqaQxQ4QqxM9in3DU0mzVxXigHVakjiS6v
kSNEhSl+VLIp1sHiOhOSpcxWkhTikjm+XpwE5H0L9I1mQ2e2nTvX7uADg/pgFMy0
uP833rQzTxNqTTPJZFLtLkTyq1Hr2MUeQ3dRNQIDAQABAoIBAFK9+pVGAVeubGc7
+4rl5EHSqKheQC/RRZGps+TILotG0n9NlsTHong0XpcwLn3b+89unemn+yorNtml
hRveZF3xLKealdppiVtuKoOBrsqgrWAHHNnGntkg58r9xRghYgv7IMu9tEGJPoZJ
uuo4daYjW36l0qLf9Ta0AGH8ZbMX2LnNO+r4EQmZ1YJShEYOS94WJnFB7XuZ/bQH
AI3IRPkQvXQNq1nnMxhAj91hOhJvTVCS04yVVzMkntcpeNP7pc7ARtSA5IepJvdK
HbcoSQ1aIK/NPkhiDs/KOoWdnB8Mqr3fXFTVJ3/YTJKwODugJ5QCbSyIC8JewgIn
d6mA6iECgYEA7028RNk65c5NRkv6rkveTT1ybrvYUUO/pbAlS4MqZmtx69n4LFrW
qicXw7sJd+O8emyvF3xHPAfVviJKg6yudtI0nM9WUuOgKr+qoKRWJMpspXdpjTXs
AQXrFAJjrDIFujsbnRmT2nbRX8nSBWvI5oSG4JqILWYs0OdchIkPo0kCgYEA62bq
mjnlz7Mqvznf8b9jOSEJKub81aUz/fK62gXcEdvffUdlDecAzotjryI678TvEBpI
w1rmHLND60o+Lczd3quyEPQfYrf8P4/6sqGfE/QtB7zKR1bXmkV0dNlr9h6zpm/Y
BpLNiqr3Ntf4OCkKiD6ch+sZ4NjKBCwzodolUo0CgYEAk/PEzfBcqM5nGmpJX8/K
bojqIiqDcKLpb4A7XreG1HHjqkVGWe4DwImQ+NO/497qnepqSqPsyuGxNe+vkD+I
UjBelQDfxzmywhtkXBOeqvp4N8lfeg33jx5gnCtqAoGe5ug6h2PT9QL3Kjj2X6Gn
QVZ4qY8BWMhONw6ENfEjuPkCgYBP0ps05vMdpgSVyXs9z4dG5QPlz2Pm0lk6AKgJ
rDj+uU8kfSQwPafRYgTQa0wO5/mkvTT1QYqMKuGaFJfXEgQeMJx2EUHfSMI5j4oU
LqfxrTfjysnQvQrpHioqQVvRnoGOq5hWSkt2fRjNORjLemc+4fRURo2E6B5Aofh0
JrPHNQKBgBGYzDGJyFnu7GYTby18aPNkQYweNDM6aZ/tUN8yZ4ryq7QnodiKLe2b
VxSr8Y+1w4xRjN67PGrS3IpQX9CAoTqyBN7VLhuq/mixOPccmo/5ui3fig/WEYwK
+ox4tfIuhfmskPNS235vLwbNIBkzP3PWVM5Chq1pEnHQUeiZq3U+
-----END RSA PRIVATE KEY-----
"""
PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3AyQGW/Q8AKJH2Mfjv1c
67iYcwIn+Z2tpqHDQQV9CfSx9CMs+Zg2buopXJ7AWd03ZR08g9O2bmlJPIQV1He3
vfzZH9+6aJAQLJ+VzpME2sXl5Boayla1JjyoH7ix/i02QHDTVClDMb6dy0rMVpc7
cBxwgX54fcR5x3AMscYCTQrhQc7qYRzoLTfP9lGJT1DgyGcOt4paa77z4uqqaQxQ
4QqxM9in3DU0mzVxXigHVakjiS6vkSNEhSl+VLIp1sHiOhOSpcxWkhTikjm+XpwE
5H0L9I1mQ2e2nTvX7uADg/pgFMy0uP833rQzTxNqTTPJZFLtLkTyq1Hr2MUeQ3dR
NQIDAQAB
-----END PUBLIC KEY-----
"""

OCT_128_BIT_KEY = b"\x04\xd3\x1f\xc5T\x9d\xfc\xfe\x0bd\x9d\xfa?\xaaj\xce"
OCT_192_BIT_KEY = b"\x04\xd3\x1f\xc5T\x9d\xfc\xfe\x0bd\x9d\xfa?\xaaj\xcek|\xd4-ok\t\xdb"
OCT_256_BIT_KEY = b"\x04\xd3\x1f\xc5T\x9d\xfc\xfe\x0bd\x9d\xfa?\xaaj\xcek|\xd4-ok\t\xdb\xc8\xb1\x00\xf0\x8f\x9c,\xcf"
OCT_384_BIT_KEY = b"\x04\xd3\x1f\xc5T\x9d\xfc\xfe\x0bd\x9d\xfa?\xaaj\xcek|\xd4-ok\t\xdb\xc8\xb1\x00\xf0\x8f\x9c,\xcf" \
                  b"\x04\xd3\x1f\xc5T\x9d\xfc\xfe\x0bd\x9d\xfa?\xaaj\xce"
OCT_512_BIT_KEY = b"\x04\xd3\x1f\xc5T\x9d\xfc\xfe\x0bd\x9d\xfa?\xaaj\xcek|\xd4-ok\t\xdb\xc8\xb1\x00\xf0\x8f\x9c,\xcf" \
                  b"\x04\xd3\x1f\xc5T\x9d\xfc\xfe\x0bd\x9d\xfa?\xaaj\xcek|\xd4-ok\t\xdb\xc8\xb1\x00\xf0\x8f\x9c,\xcf"


class TestEncrypt:
    """
    This test class is an exact copy of the same class present in *python-jose* package (at path
    :class:`~tests.test_jwe.TestEncrypt`). We have copied this class since we have temporarily overridden the
    :func:`~jose.jwe.encrypt` function, to add additional capabilities. New tests, for the additional capabilities added
    in the overriden function, are present in the
    :class:`~tests.jose_aws_kms_extension.jwe_tmp_test.TestEncryptAdditionalHeaders` class.

    TODO: Remove this class and related code, once the following issue is resolved.
        https://github.com/mpdavis/python-jose/issues/321
    """
    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_rfc7516_appendix_b_direct(self, monkeypatch):
        algorithm = ALGORITHMS.DIR
        encryption = ALGORITHMS.A128CBC_HS256
        key = bytes(
            bytearray(
                [
                    4,
                    211,
                    31,
                    197,
                    84,
                    157,
                    252,
                    254,
                    11,
                    100,
                    157,
                    250,
                    63,
                    170,
                    106,
                    206,
                    107,
                    124,
                    212,
                    45,
                    111,
                    107,
                    9,
                    219,
                    200,
                    177,
                    0,
                    240,
                    143,
                    156,
                    44,
                    207,
                ]
            )
        )
        plain_text = b"Live long and prosper."
        expected_iv = bytes(bytearray([3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101]))

        for backend in backends:
            monkeypatch.setattr(backend, "get_random_bytes", lambda x: expected_iv if x == 16 else key)

        expected = b"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4Hf" \
                   b"fxPSUrfmqCHXaI9wOGY.BIiCkt8mWOVyJOqDMwNqaQ"
        actual = jwe.encrypt(plain_text, key, encryption, algorithm)

        assert actual == expected

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    @pytest.mark.parametrize("alg", filter(lambda x: x in ALGORITHMS.SUPPORTED, ALGORITHMS.RSA_KW))
    @pytest.mark.parametrize("enc", filter(lambda x: x in ALGORITHMS.SUPPORTED, ALGORITHMS.AES_ENC))
    @pytest.mark.parametrize("zip", ZIPS.SUPPORTED)
    def test_encrypt_decrypt_rsa_kw(self, alg, enc, zip):
        expected = b"Live long and prosper."
        jwe_value = jwe.encrypt(expected[:], PUBLIC_KEY_PEM, enc, alg, zip)
        actual = jwe.decrypt(jwe_value, PRIVATE_KEY_PEM)
        assert actual == expected

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    @pytest.mark.parametrize("alg", ALGORITHMS.AES_KW)
    @pytest.mark.parametrize("enc", filter(lambda x: x in ALGORITHMS.SUPPORTED, ALGORITHMS.AES_ENC))
    @pytest.mark.parametrize("zip", ZIPS.SUPPORTED)
    def test_encrypt_decrypt_aes_kw(self, alg, enc, zip):
        if alg == ALGORITHMS.A128KW:
            key = OCT_128_BIT_KEY
        elif alg == ALGORITHMS.A192KW:
            key = OCT_192_BIT_KEY
        elif alg == ALGORITHMS.A256KW:
            key = OCT_256_BIT_KEY
        else:
            pytest.fail(f"I don't know how to handle enc {alg}")
        expected = b"Live long and prosper."
        jwe_value = jwe.encrypt(expected[:], key, enc, alg, zip)
        actual = jwe.decrypt(jwe_value, key)
        assert actual == expected

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    @pytest.mark.parametrize("enc", filter(lambda x: x in ALGORITHMS.SUPPORTED, ALGORITHMS.AES_ENC))
    @pytest.mark.parametrize("zip", ZIPS.SUPPORTED)
    def test_encrypt_decrypt_dir_kw(self, enc, zip):
        if enc == ALGORITHMS.A128GCM:
            key = OCT_128_BIT_KEY
        elif enc == ALGORITHMS.A192GCM:
            key = OCT_192_BIT_KEY
        elif enc in (ALGORITHMS.A128CBC_HS256, ALGORITHMS.A256GCM):
            key = OCT_256_BIT_KEY
        elif enc == ALGORITHMS.A192CBC_HS384:
            key = OCT_384_BIT_KEY
        elif enc == ALGORITHMS.A256CBC_HS512:
            key = OCT_512_BIT_KEY
        else:
            pytest.fail(f"I don't know how to handle enc {enc}")
        expected = b"Live long and prosper."
        jwe_value = jwe.encrypt(expected[:], key, enc, ALGORITHMS.DIR, zip)
        actual = jwe.decrypt(jwe_value, key)
        assert actual == expected

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_alg_enc_headers(self):
        enc = ALGORITHMS.A256CBC_HS512
        alg = ALGORITHMS.RSA_OAEP_256
        encrypted = jwe.encrypt("Text", PUBLIC_KEY_PEM, enc, alg)
        header = json.loads(base64url_decode(encrypted.split(b".")[0]))
        assert header["enc"] == enc
        assert header["alg"] == alg

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_cty_header_present_when_provided(self):
        enc = ALGORITHMS.A256CBC_HS512
        alg = ALGORITHMS.RSA_OAEP_256
        encrypted = jwe.encrypt("Text", PUBLIC_KEY_PEM, enc, alg, cty="expected")
        header = json.loads(base64url_decode(encrypted.split(b".")[0]))
        assert header["cty"] == "expected"

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_cty_header_not_present_when_not_provided(self):
        enc = ALGORITHMS.A256CBC_HS512
        alg = ALGORITHMS.RSA_OAEP_256
        encrypted = jwe.encrypt("Text", PUBLIC_KEY_PEM, enc, alg)
        header = json.loads(base64url_decode(encrypted.split(b".")[0]))
        assert "cty" not in header

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_zip_header_present_when_provided(self):
        enc = ALGORITHMS.A256CBC_HS512
        alg = ALGORITHMS.RSA_OAEP_256
        encrypted = jwe.encrypt(b"Text", PUBLIC_KEY_PEM, enc, alg, zip=ZIPS.DEF)
        header = json.loads(base64url_decode(encrypted.split(b".")[0]))
        assert header["zip"] == ZIPS.DEF

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_zip_header_not_present_when_not_provided(self):
        enc = ALGORITHMS.A256CBC_HS512
        alg = ALGORITHMS.RSA_OAEP_256
        encrypted = jwe.encrypt(b"Text", PUBLIC_KEY_PEM, enc, alg)
        header = json.loads(base64url_decode(encrypted.split(b".")[0]))
        assert "zip" not in header

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_zip_header_not_present_when_none(self):
        enc = ALGORITHMS.A256CBC_HS512
        alg = ALGORITHMS.RSA_OAEP_256
        encrypted = jwe.encrypt("Text", PUBLIC_KEY_PEM, enc, alg, zip=ZIPS.NONE)
        header = json.loads(base64url_decode(encrypted.split(b".")[0]))
        assert "zip" not in header

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_kid_header_present_when_provided(self):
        enc = ALGORITHMS.A256CBC_HS512
        alg = ALGORITHMS.RSA_OAEP_256
        encrypted = jwe.encrypt("Text", PUBLIC_KEY_PEM, enc, alg, kid="expected")
        header = json.loads(base64url_decode(encrypted.split(b".")[0]))
        assert header["kid"] == "expected"

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_kid_header_not_present_when_not_provided(self):
        enc = ALGORITHMS.A256CBC_HS512
        alg = ALGORITHMS.RSA_OAEP_256
        encrypted = jwe.encrypt("Text", PUBLIC_KEY_PEM, enc, alg)
        header = json.loads(base64url_decode(encrypted.split(b".")[0]))
        assert "kid" not in header


class TestEncryptAdditionalHeaders:
    """
    Class to test the `additional_header` parameter, added as an override, in the :func:`~jose.jwe.encrypt` function.

    TODO: Remove this class and related code, once the following issue is resolved.
        https://github.com/mpdavis/python-jose/issues/321
    """
    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_additional_headers_present_when_provided(self):
        enc = ALGORITHMS.A256CBC_HS512
        alg = ALGORITHMS.RSA_OAEP_256
        additional_headers = {'test-header1': 'val1', 'test-header2': 'val1'}
        encrypted = jwe.encrypt("Text", PUBLIC_KEY_PEM, enc, alg, additional_headers=additional_headers.copy())
        header = json.loads(base64url_decode(encrypted.split(b".")[0]))
        assert set(header.items()).issuperset(set(additional_headers.items()))
