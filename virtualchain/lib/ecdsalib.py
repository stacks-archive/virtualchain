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

import keylib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.exceptions import InvalidSignature

from .config import get_logger

import base64
import hashlib
import re
from binascii import hexlify

log = get_logger("virtualchain-ecdsalib")

SECP256k1_order = 115792089237316195423570985008687907852837564279074904382605163141518161494337L

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


class _ECPrivateKey(object):
    _pubkeyhash_version_byte = 0

    def __init__(self, private_key=None, compressed=True):
        """ Takes in a private key/secret exponent.
        """
        pk_i = None
        if private_key is None:
            pk_i = ec.generate_private_key(ec.SECP256K1(), default_backend()).private_numbers().private_value
        else:
            pk_i = keylib.key_formatting.encode_privkey(private_key, 'decimal')

        privkey_str = '{:064x}'.format(pk_i)
        assert len(privkey_str) == 64

        self._ecdsa_private_key_string = privkey_str.decode('hex')
        self._compressed = compressed

    @classmethod
    def wif_version_byte(cls):
        if hasattr(cls, '_wif_version_byte'):
            return cls._wif_version_byte
        return (cls._pubkeyhash_version_byte + 128) % 256

    def to_bin(self):
        if self._compressed:
            return keylib.key_formatting.encode_privkey(
                self._ecdsa_private_key_string, 'bin_compressed')
        else:
            return self._ecdsa_private_key_string

    def to_hex(self):
        if self._compressed:
            return keylib.key_formatting.encode_privkey(
                self._ecdsa_private_key_string, 'hex_compressed')
        else:
            return hexlify(self.to_bin())

    def to_wif(self):
        if self._compressed:
            return keylib.key_formatting.encode_privkey(
                self._ecdsa_private_key_string, 'wif_compressed', vbyte=self._pubkeyhash_version_byte)
        else:
            return keylib.b58check.b58check_encode(
                self.to_bin(), version_byte=self.wif_version_byte())

    def public_key(self):
        # lazily calculate and set the public key
        if not hasattr(self, '_public_key'):

            privk = ec.derive_private_key(int(self._ecdsa_private_key_string.encode('hex'), 16), ec.SECP256K1(), default_backend())
            pubk = privk.public_key()

            ecdsa_public_key_str = pubk.public_numbers().encode_point().encode('hex')
            if self._compressed:
                ecdsa_public_key_str = keylib.key_formatting.compress(ecdsa_public_key_str)

            self._public_key = _ECPublicKey(ecdsa_public_key_str, version_byte=self._pubkeyhash_version_byte)

        # return the public key object
        return self._public_key


class _ECPublicKey(object):
    _version_byte = 0

    @classmethod
    def version_byte(cls):
        return cls._version_byte

    def __init__(self, public_key_string, version_byte=None, verify=True):
        """ Takes in a public key in hex format.
        """
        # set the version byte
        if version_byte:
            self._version_byte = version_byte

        self._charencoding, self._type = keylib.public_key_encoding.get_public_key_format(public_key_string)

        # extract the binary key (compressed/uncompressed w magic byte)
        self._bin_public_key = keylib.public_key_encoding.extract_bin_ecdsa_pubkey(public_key_string)

        if verify:
            pubkey_hex_decompressed = keylib.key_formatting.decompress(self._bin_public_key.encode('hex'))
            pubk = ec.EllipticCurvePublicNumbers.from_encoded_point(ec.SECP256K1(), pubkey_hex_decompressed.decode('hex')).public_key(default_backend())

    def to_bin(self):
        return self._bin_public_key

    def to_hex(self):
        return hexlify(self.to_bin())

    def bin_hash160(self):
        if not hasattr(self, '_bin_hash160'):
            binary_key = self.to_bin()  
            if self._type == keylib.public_key_encoding.PubkeyType.compressed:
                binary_key = keylib.key_formatting.compress(binary_key)

            self._bin_hash160 = keylib.hashing.bin_hash160(binary_key)
        return self._bin_hash160

    def hash160(self):
        return hexlify(self.bin_hash160())

    def address(self):
        return keylib.address_formatting.bin_hash160_to_address(
            self.bin_hash160(), version_byte=self._version_byte)



def ecdsa_private_key(privkey_str=None, compressed=None):
    """
    Make a private key, but enforce the following rule:
    * unless the key's hex encoding specifically ends in '01', treat it as uncompressed.
    """
    if compressed is None:
        compressed = False
        if privkey_str is not None:
            if len(privkey_str) == 66 and privkey_str[-2:] == '01':
                compressed = True

    return _ECPrivateKey(privkey_str, compressed=compressed)


def ecdsa_public_key(pubkey_str, compressed=None):
    """
    Make a public key object, but enforce the following rule:
    * if compressed is True or False, make the key compressed/uncompressed.
    * otherwise, return whatever the hex encoding is
    """
    if compressed == True:
        pubkey_str = keylib.key_formatting.compress(pubkey_str)
    elif compressed == False:
        pubkey_str = keylib.key_formatting.decompress(pubkey_str)

    return _ECPublicKey(pubkey_str)


def set_privkey_compressed(privkey, compressed=True):
    """
    Make sure the private key given is compressed or not compressed
    """
    if len(privkey) != 64 and len(privkey) != 66:
        raise ValueError("expected 32-byte private key as a hex string")

    # compressed?
    if compressed and len(privkey) == 64:
        privkey += '01'

    if not compressed and len(privkey) == 66:
        if privkey[-2:] != '01':
            raise ValueError("private key does not end in '01'")

        privkey = privkey[:-2]

    return privkey


def get_pubkey_hex( privatekey_hex ):
    """
    Get the uncompressed hex form of a private key
    """
    if not isinstance(privatekey_hex, (str, unicode)):
        raise ValueError("private key is not a hex string but {}".format(str(type(privatekey_hex))))

    # remove 'compressed' hint
    if len(privatekey_hex) > 64:
        if privatekey_hex[-2:] != '01':
            raise ValueError("private key does not end in 01")

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
    if not isinstance(privkey_str, (str, unicode)):
        raise ValueError("private key given is not a string")

    pk = ecdsa_private_key(str(privkey_str))
    pk_hex = pk.to_hex()

    # force uncompressed
    if len(pk_hex) > 64:
        if pk_hex[-2:] != '01':
            raise ValueError("private key does not end in '01'")

        pk_hex = pk_hex[:64]

    pubk_hex = ecdsa_private_key(pk_hex).public_key().to_hex()
    return pk_hex, pubk_hex


def decode_privkey_hex(privkey_hex):
    """
    Decode a private key for ecdsa signature
    """
    if not isinstance(privkey_hex, (str, unicode)):
        raise ValueError("private key is not a string")

    # force uncompressed
    priv = str(privkey_hex)
    if len(priv) > 64:
        if priv[-2:] != '01':
            raise ValueError("private key does not end in '01'")

        priv = priv[:64]

    pk_i = int(priv, 16)
    return pk_i


def decode_pubkey_hex(pubkey_hex):
    """
    Decode a public key for ecdsa verification
    """
    if not isinstance(pubkey_hex, (str, unicode)):
        raise ValueError("public key is not a string")

    pubk = keylib.key_formatting.decompress(str(pubkey_hex))
    assert len(pubk) == 130

    pubk_raw = pubk[2:]
    pubk_i = (int(pubk_raw[:64], 16), int(pubk_raw[64:], 16))
    return pubk_i


def encode_signature(sig_r, sig_s):
    """
    Encode an ECDSA signature, with low-s
    """
    # enforce low-s 
    if sig_s * 2 >= SECP256k1_order:
        log.debug("High-S to low-S")
        sig_s = SECP256k1_order - sig_s

    sig_bin = '{:064x}{:064x}'.format(sig_r, sig_s).decode('hex')
    assert len(sig_bin) == 64

    sig_b64 = base64.b64encode(sig_bin)
    return sig_b64


def decode_signature(sigb64):
    """
    Decode a signature into r, s
    """
    sig_bin = base64.b64decode(sigb64)
    if len(sig_bin) != 64:
        raise ValueError("Invalid base64 signature")

    sig_hex = sig_bin.encode('hex')
    sig_r = int(sig_hex[:64], 16)
    sig_s = int(sig_hex[64:], 16)
    return sig_r, sig_s


def sign_raw_data(raw_data, privatekey_hex):
    """
    Sign a string of data.
    Returns signature as a base64 string
    """
    if not isinstance(raw_data, (str, unicode)):
        raise ValueError("Data is not a string")

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
    if not isinstance(raw_data, (str, unicode)):
        raise ValueError("data is not a string")

    raw_data = str(raw_data)

    vi = ECVerifier(pubkey_hex, sigb64)
    vi.update(raw_data)
    return vi.verify()


def sign_digest(hash_hex, privkey_hex, hashfunc=hashlib.sha256):
    """
    Given a digest and a private key, sign it.
    Return the base64-encoded signature
    """
    if not isinstance(hash_hex, (str, unicode)):
        raise ValueError("hash hex is not a string")

    hash_hex = str(hash_hex)

    pk_i = decode_privkey_hex(privkey_hex)
    privk = ec.derive_private_key(pk_i, ec.SECP256K1(), default_backend())

    sig = privk.sign(hash_hex.decode('hex'), ec.ECDSA(utils.Prehashed(hashes.SHA256())))

    sig_r, sig_s = decode_dss_signature(sig)
    sigb64 = encode_signature(sig_r, sig_s)
    return sigb64


def verify_digest(hash_hex, pubkey_hex, sigb64, hashfunc=hashlib.sha256):
    """
    Given a digest, public key (as hex), and a base64 signature,
    verify that the public key signed the digest.
    Return True if so
    Return False if not
    """
    if not isinstance(hash_hex, (str, unicode)):
        raise ValueError("hash hex is not a string")

    hash_hex = str(hash_hex)
    pubk_uncompressed_hex = keylib.key_formatting.decompress(pubkey_hex)
    sig_r, sig_s = decode_signature(sigb64)

    pubk = ec.EllipticCurvePublicNumbers.from_encoded_point(ec.SECP256K1(), pubk_uncompressed_hex.decode('hex')).public_key(default_backend())
    signature = encode_dss_signature(sig_r, sig_s)

    try:
        pubk.verify(signature, hash_hex.decode('hex'), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except InvalidSignature:
        return False

