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
from keylib import ECPrivateKey, ECPublicKey

import fastecdsa
import fastecdsa.curve
import fastecdsa.keys
import fastecdsa.ecdsa

from .blockchain.session import get_logger

OLD_FASTECDSA = False
try:
    import fastecdsa.point
except:
    # older fastecdsa library
    OLD_FASTECDSA = True
    pass 

from fastecdsa import _ecdsa
from fastecdsa.util import RFC6979

import hmac
import hashlib
import base64

log = get_logger("virtualchain-ecdsalib")

class RFC6979_blockstack(RFC6979):
    """
    Generate RFC6979 nonces from a file or a digest.
    Derived from the same code in fastecdsa.
    """
    def __init__(self, x, q, hashfunc):
        RFC6979.__init__(self, '', x, q, hashfunc)


    def gen_nonce_from_digest( self, h1 ):
        """
        Make the nonce from the digest.
        @h1: bin-encoded digest
        @hash_size: size of the digest
        """
        hash_size = self.hashfunc().digest_size
        key_and_msg = self._int2octets(self.x) + self._bits2octets(h1)

        v = b''.join([b'\x01' for _ in range(hash_size)])
        k = b''.join([b'\x00' for _ in range(hash_size)])

        k = hmac.new(k, v + b'\x00' + key_and_msg, self.hashfunc).digest()
        v = hmac.new(k, v, self.hashfunc).digest()
        k = hmac.new(k, v + b'\x01' + key_and_msg, self.hashfunc).digest()
        v = hmac.new(k, v, self.hashfunc).digest()

        while True:
            t = b''

            while len(t) * 8 < self.qlen:
                v = hmac.new(k, v, self.hashfunc).digest()
                t = t + v

            nonce = self._bits2int(t)
            if nonce >= 1 and nonce < self.q:
                return nonce

            k = hmac.new(k, v + b'\x00', self.hashfunc).digest()
            v = hmac.new(k, v, self.hashfunc).digest()


    def gen_nonce_from_file(self, fd, fd_len=None):
        ''' http://tools.ietf.org/html/rfc6979#section-3.2 '''
        # based on gen_nonce()
        
        h1 = self.hashfunc()

        count = 0
        while True:
            buf = f.read(65536)
            if len(buf) == 0:
                break

            if fd_len is not None:
                if count + len(buf) > fd_len:
                    buf = buf[:fd_len - count]

            h.update(buf)
            count += len(buf)

        h1 = h1.digest()

        return self.gen_nonce_from_digest(h1)


def ecdsa_private_key(privkey_str=None):
    """
    Make a private key, but enforce the following rule:
    * unless the key's hex encoding specifically ends in '01', treat it as uncompressed.
    """
    compressed = False
    if privkey_str is None or keylib.key_formatting.get_privkey_format(privkey_str).endswith('compressed'):
        compressed = True

    return ECPrivateKey(privkey_str, compressed=compressed)


def get_pubkey_hex( privatekey_hex ):
    """
    Get the uncompressed hex form of a private key
    """

    global OLD_FASTECDSA

    if len(privatekey_hex) > 64:
        assert privatekey_hex[-2:] == '01'
        privatekey_hex = privatekey_hex[:64]

    # get hex public key
    privatekey_int = int(privatekey_hex, 16)
    pubkey_parts = fastecdsa.keys.get_public_key( privatekey_int, curve=fastecdsa.curve.secp256k1 )
    x = None
    y = None

    if isinstance(pubkey_parts, (list, tuple)):
        # older fastecdsa 
        x = pubkey_parts[0]
        y = pubkey_parts[1]

    elif not OLD_FASTECDSA:
        if isinstance(pubkey_parts, fastecdsa.point.Point):
            # newer fastecdsa interface uses a Point class instead of a tuple
            x = pubkey_parts.x
            y = pubkey_parts.y
        
        else:
            raise Exception("Incompatible fastecdsa library")

    else:
        raise Exception("Incompatible fastecdsa library")

    pubkey_hex = "04{:064x}{:064x}".format(x, y)
    return pubkey_hex


def get_uncompressed_private_and_public_keys( privkey_str ):
    """
    Get the private and public keys from a private key string.
    Make sure the both are *uncompressed*
    """
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
    if sig_s * 2 >= fastecdsa.curve.secp256k1.q:
        log.debug("High-S to low-S")
        sig_s = fastecdsa.curve.secp256k1.q - sig_s

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
    pk_i = decode_privkey_hex(privatekey_hex)
    sig_r, sig_s = fastecdsa.ecdsa.sign(raw_data, pk_i, curve=fastecdsa.curve.secp256k1)
    sig_b64 = encode_signature(sig_r, sig_s)
    return sig_b64


def verify_raw_data(raw_data, pubkey_hex, sigb64):
    """
    Verify the signature over a string, given the public key
    and base64-encode signature.
    Return True on success.
    Return False on error.
    """
    try:
        sig_r, sig_s = decode_signature(sigb64)
        pubk_i = decode_pubkey_hex(pubkey_hex)
        res = fastecdsa.ecdsa.verify((sig_r, sig_s), raw_data, pubk_i, curve=fastecdsa.curve.secp256k1)
        return res
    except (fastecdsa.ecdsa.EcdsaError, AssertionError):
        # invalid signature
        log.debug("Invalid signature {}".format(sigb64))
        return False


def sign_digest( digest_hex, privkey_hex, curve=fastecdsa.curve.secp256k1, hashfunc=hashlib.sha256 ):
    """
    Sign a digest with ECDSA
    Return base64 signature
    """
    pk_i = decode_privkey_hex(str(privkey_hex))

    # generate a deterministic nonce per RFC6979
    rfc6979 = RFC6979_blockstack(pk_i, curve.q, hashfunc)
    k = rfc6979.gen_nonce_from_digest(digest_hex.decode('hex'))

    r, s = _ecdsa.sign(digest_hex, str(pk_i), str(k), curve.name)
    return encode_signature(int(r), int(s))


def verify_digest( digest_hex, pubkey_hex, sigb64, curve=fastecdsa.curve.secp256k1, hashfunc=hashlib.sha256 ):
    """
    Verify a digest and signature with ECDSA
    Return True if it matches
    """

    Q = decode_pubkey_hex(str(pubkey_hex))
    r, s = decode_signature(sigb64)

    # validate Q, r, s
    if not curve.is_point_on_curve(Q):
        raise fastecdsa.ecdsa.EcdsaError('Invalid public key, point is not on curve {}'.format(curve.name))
    elif r > curve.q or r < 1:
        raise fastecdsa.ecdsa.EcdsaError('Invalid Signature: r is not a positive integer smaller than the curve order')
    elif s > curve.q or s < 1:
        raise fastecdsa.ecdsa.EcdsaError('Invalid Signature: s is not a positive integer smaller than the curve order')

    qx, qy = Q
    return _ecdsa.verify(str(r), str(s), digest_hex, str(qx), str(qy), curve.name)

