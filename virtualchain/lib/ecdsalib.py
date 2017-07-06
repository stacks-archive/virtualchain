#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
     Virtualchain
     ~~~~~
     copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
     copyright: (c) 2016-2017 by Blockstack.org

     This file is part of Virtualchain

     Virtualchain is free software: you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published by
     the Free Software Foundation, either version 3 of the License, or
     (at your option) any later version.

     Virtualchain is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
     GNU General Public License for more details.
     You should have received a copy of the GNU General Public License
     along with Virtualchain.  If not, see <http://www.gnu.org/licenses/>.
"""

from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.util import sigencode_der, sigdecode_der
from ecdsa import BadSignatureError

import keylib
from keylib import ECPrivateKey 

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.exceptions import InvalidSignature

from .config import get_logger

import base64
import hashlib

log = get_logger("virtualchain-ecdsalib")

class ECSigner(object):
    """
    Generic ECDSA signer object
    """
    def __init__(self, privkey_hex):
        """
        Instantiate a signer with a hex-encoded ECDSA private key
        """
        pk_i = decode_privkey_hex(privkey_hex)
        privk = ec.derive_private_key(pk_i, ec.SECP256K1(), default_backend())
        self.signer = privk.signer(ec.ECDSA(hashes.SHA256()))

    def update(self, data):
        """
        Update the hash used to generate the signature
        """
        try:
            self.signer.update(data)
        except TypeError:
            log.error("Invalid data: {} ({})".format(type(data), data))
            raise

    def finalize(self):
        """
        Get the base64-encoded signature itself.
        Can only be called once.
        """
        signature = self.signer.finalize()
        sig_r, sig_s = decode_dss_signature(signature)
        sig_b64 = encode_signature(sig_r, sig_s)
        return sig_b64


class ECVerifier(object):
    """
    Generic ECDSA verifier object
    """
    def __init__(self, pubkey_hex, sigb64):
        """
        Instantiate the verifier with a hex-encoded public key and a base64-encoded signature
        """
        sig_r, sig_s = decode_signature(sigb64)
        pubkey_hex_decompressed = keylib.key_formatting.decompress(pubkey_hex)
        pubk = ec.EllipticCurvePublicNumbers.from_encoded_point(ec.SECP256K1(), pubkey_hex_decompressed.decode('hex')).public_key(default_backend())
        signature = encode_dss_signature(sig_r, sig_s)
        self.verifier = pubk.verifier(signature, ec.ECDSA(hashes.SHA256()))

    def update(self, data):
        """
        Update the hash used to generate the signature
        """
        try:
            self.verifier.update(data)
        except TypeError:
            log.error("Invalid data: {} ({})".format(type(data), data))
            raise

    def verify(self):
        """
        Verify whether or not the public key matches the signature, given the data
        """
        try:
            self.verifier.verify()
            return True
        except InvalidSignature:
            return False


def ecdsa_private_key(privkey_str=None):
    """
    Make a private key, but enforce the following rule:
    * unless the key's hex encoding specifically ends in '01', treat it as uncompressed.
    """
    compressed = False
    if privkey_str is not None:
        assert isinstance(privkey_str, (str, unicode))
        privkey_str = str(privkey_str)

    if privkey_str is None or keylib.key_formatting.get_privkey_format(privkey_str).endswith('compressed'):
        compressed = True

    return ECPrivateKey(privkey_str, compressed=compressed)


def set_privkey_compressed(privkey, compressed=True):
    """
    Make sure the private key given is compressed or not compressed
    """
    assert len(privkey) == 64 or len(privkey) == 66, "BUG: expected 32-byte private key as a hex string"

    # compressed?
    if compressed and len(privkey) == 64:
        privkey += '01'

    if not compressed and len(privkey) == 66:
        assert privkey[-2:] == '01'
        privkey = privkey[:-2]

    return privkey


def get_pubkey_hex( privatekey_hex ):
    """
    Get the uncompressed hex form of a private key
    """
    assert isinstance(privatekey_hex, (str, unicode)), str(type(privatekey_hex))

    # remove 'compressed' hint
    if len(privatekey_hex) > 64:
        assert privatekey_hex[-2:] == '01'
        privatekey_hex = privatekey_hex[:64]

    # get hex public key
    privatekey_int = int(privatekey_hex, 16)
    privk = ec.derive_private_key(privatekey_int, ec.SECP256K1(), default_backend())
    pubk = privk.public_key()
    x = pubk.public_numbers().x
    y = pubk.public_numbers().y

    pubkey_hex = "04{:064x}{:064x}".format(x, y)
    return pubkey_hex


def get_uncompressed_private_and_public_keys( privkey_str ):
    """
    Get the private and public keys from a private key string.
    Make sure the both are *uncompressed*
    """
    assert isinstance(privkey_str, (str, unicode))

    pk = ecdsa_private_key(str(privkey_str))
    pk_hex = pk.to_hex()

    # force uncompressed
    if len(pk_hex) > 64:
        assert pk_hex[-2:] == '01'
        pk_hex = pk_hex[:64]

    pubk_hex = ecdsa_private_key(pk_hex).public_key().to_hex()
    return pk_hex, pubk_hex


def decode_privkey_hex(privkey_hex):
    """
    Decode a private key for ecdsa signature
    """
    assert isinstance(privkey_hex, (str, unicode))

    # force uncompressed
    priv = str(privkey_hex)
    if len(priv) > 64:
        assert priv[-2:] == '01'
        priv = priv[:64]

    pk_i = int(priv, 16)
    return pk_i


def decode_pubkey_hex(pubkey_hex):
    """
    Decode a public key for ecdsa verification
    """
    assert isinstance(pubkey_hex, (str, unicode))

    pubk = str(pubkey_hex)
    if keylib.key_formatting.get_pubkey_format(pubk) == 'hex_compressed':
        pubk = keylib.key_formatting.decompress(pubk)

    assert len(pubk) == 130

    pubk_raw = pubk[2:]
    pubk_i = (int(pubk_raw[:64], 16), int(pubk_raw[64:], 16))
    return pubk_i


def encode_signature(sig_r, sig_s):
    """
    Encode an ECDSA signature, with low-s
    """
    # enforce low-s 
    if sig_s * 2 >= SECP256k1.order:
        log.debug("High-S to low-S")
        sig_s = SECP256k1.order - sig_s

    sig_bin = '{:064x}{:064x}'.format(sig_r, sig_s).decode('hex')
    assert len(sig_bin) == 64

    sig_b64 = base64.b64encode(sig_bin)
    return sig_b64


def decode_signature(sigb64):
    """
    Decode a signature into r, s
    """
    sig_bin = base64.b64decode(sigb64)
    assert len(sig_bin) == 64

    sig_hex = sig_bin.encode('hex')
    sig_r = int(sig_hex[:64], 16)
    sig_s = int(sig_hex[64:], 16)
    return sig_r, sig_s


def sign_raw_data(raw_data, privatekey_hex):
    """
    Sign a string of data.
    Returns signature as a base64 string
    """
    assert isinstance(raw_data, (str, unicode))
    raw_data = str(raw_data)

    si = ECSigner(privatekey_hex)
    si.update(raw_data)
    return si.finalize()


def verify_raw_data(raw_data, pubkey_hex, sigb64):
    """
    Verify the signature over a string, given the public key
    and base64-encode signature.
    Return True on success.
    Return False on error.
    """
    assert isinstance(raw_data, (str, unicode))
    raw_data = str(raw_data)

    vi = ECVerifier(pubkey_hex, sigb64)
    vi.update(raw_data)
    return vi.verify()


def sign_digest(hash_hex, privkey_hex, hashfunc=hashlib.sha256):
    """
    Given a digest and a private key, sign it.
    Return the base64-encoded signature
    """
    assert isinstance(hash_hex, (str, unicode))
    hash_hex = str(hash_hex)

    pk_uncompressed_hex, pubk_uncompressed_hex = get_uncompressed_private_and_public_keys(privkey_hex)

    sk = SigningKey.from_string(pk_uncompressed_hex.decode('hex'), curve=SECP256k1)
    sig_bin = sk.sign_digest(hash_hex.decode('hex'), sigencode=sigencode_der)
    
    sig_r, sig_s = sigdecode_der( sig_bin, SECP256k1.order )
    sigb64 = encode_signature(sig_r, sig_s)
    return sigb64


def verify_digest(hash_hex, pubkey_hex, sigb64, hashfunc=hashlib.sha256):
    """
    Given a digest, public key (as hex), and a base64 signature,
    verify that the public key signed the digest.
    Return True if so
    Return False if not
    """
    # NOTE: this method uses the ecdsa package, not cryptography.
    # it is much slower, since it's pure Python.

    assert isinstance(hash_hex, (str, unicode))
    hash_hex = str(hash_hex)

    sig_r, sig_s = decode_signature(sigb64)
    pubk_uncompressed_hex = keylib.key_formatting.decompress(pubkey_hex)

    sig_bin = sigencode_der( sig_r, sig_s, SECP256k1.order )
    vk = VerifyingKey.from_string(pubk_uncompressed_hex[2:].decode('hex'), curve=SECP256k1)

    try:
        res = vk.verify_digest(sig_bin, hash_hex.decode('hex'), sigdecode=sigdecode_der)
        return res
    except BadSignatureError:
        log.debug("Bad signature {}; not from {} on {}?".format(sigb64, pubkey_hex, hash_hex))
        return False
