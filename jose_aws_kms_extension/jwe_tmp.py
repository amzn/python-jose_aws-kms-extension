#  type: ignore

"""
Code in the module is temporary. It is present to fill general feature gaps in *python-jose*.
I.e. features which are not related to KMS. Once the features gap(s) are filled, this code should be removed in favour
of the new *python-jose* version.
"""

import json

from jose import exceptions as jose_exceptions
from jose import jwe as jose_jwe
from jose import jwk as jose_jwk
from jose import utils as jose_utils
from jose.constants import ALGORITHMS


def _encrypt(
    plaintext, key, encryption=ALGORITHMS.A256GCM, algorithm=ALGORITHMS.DIR, zip=None, cty=None, kid=None,
    additional_headers=None
):
    """
    Override of :func:`~jose.jwe.encrypt` function, to add `additional_headers` parameter. Apart from the
    `additional_headers` parameter everything else is an exact copy of the original function.

    :param additional_headers: Dict containing additional JWE protected headers.

    See the original function's doc-string for more details.

    TODO: Remove this function and related code, once the following issue is resolved.
        https://github.com/mpdavis/python-jose/issues/321
    """
    plaintext = jose_jwe.ensure_binary(plaintext)  # Make sure it's bytes
    if algorithm not in ALGORITHMS.SUPPORTED:
        raise jose_exceptions.JWEError("Algorithm %s not supported." % algorithm)
    if encryption not in ALGORITHMS.SUPPORTED:
        raise jose_exceptions.JWEError("Algorithm %s not supported." % encryption)
    key = jose_jwk.construct(key, algorithm)
    encoded_header = _encoded_header(algorithm, encryption, zip, cty, kid, additional_headers)

    plaintext = jose_jwe._compress(zip, plaintext)
    enc_cek, iv, cipher_text, auth_tag = jose_jwe._encrypt_and_auth(
        key, algorithm, encryption, zip, plaintext, encoded_header
    )

    jwe_string = jose_jwe._jwe_compact_serialize(encoded_header, enc_cek, iv, cipher_text, auth_tag)
    return jwe_string


def _encoded_header(alg, enc, zip, cty, kid, additional_headers):
    """
    Override of :func:`~jose.jwe._encoded_header` function, to add `additional_headers` parameter. Apart from the
    `additional_headers` parameter everything else is an exact copy of the original function.

    :param additional_headers: Additional JWE protected headers.

    See the original function's doc-string for more details.

    TODO: Remove this function, once the following issue is resolved.
        https://github.com/mpdavis/python-jose/issues/321
    """
    header = {"alg": alg, "enc": enc}
    if zip:
        header["zip"] = zip
    if cty:
        header["cty"] = cty
    if kid:
        header["kid"] = kid

    header.update(additional_headers or {})

    json_header = json.dumps(
        header,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return jose_utils.base64url_encode(json_header)


jose_jwe.encrypt = _encrypt
