#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Virtualchain
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org
    
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

import traceback
import sys

from .opcodes import *
from .keys import *
from .bits import *
from ....lib import hashing
from ....lib.config import get_logger

import os
import binascii

log = get_logger('virtualchain')

def make_multisig_script( pubs, m ):
    """
    Make a multisig scriptSig/witness script, as a hex string
    """
    return btc_script_serialize( [m] + pubs + [len(pubs)] + [OPCODE_VALUES['OP_CHECKMULTISIG']] )
   

def make_multisig_address(pubs, m):
    """
    Make a multisig (p2sh) address, given the list of public keys (as hex strings) and the number required for validation
    """
    return btc_make_p2sh_address(make_multisig_script(pubs, m))


def make_multisig_segwit_address(pubs, m):
    """
    make an address for p2sh-p2wsh multisig
    """
    script = make_multisig_script(pubs, m)
    return make_multisig_segwit_address_from_witness_script(script)


def make_multisig_segwit_address_from_witness_script(script):
    """
    multisig witness script (p2sh-p2wsh) to address
    """
    script_hash = hashing.bin_sha256(script.decode('hex')).encode('hex')
    scriptsig_script = '0020' + script_hash
    addr = btc_make_p2sh_address(scriptsig_script)
    return addr


def make_multisig_info( m, pks, compressed=None ):
    """
    Make a multisig address and redeem script.
    @m of the given @pks must sign.

    Return {'address': p2sh address, 'redeem_script': redeem script, 'private_keys': private keys, 'segwit': False}
    * privkeys will be hex-encoded
    * redeem_script will be hex-encoded
    """

    pubs = []
    privkeys = []
    for pk in pks:
        priv = None
        if compressed in [True, False]:
            priv = BitcoinPrivateKey(pk, compressed=compressed)
        else:
            priv = BitcoinPrivateKey(pk)

        priv_hex = priv.to_hex()
        pub_hex = priv.public_key().to_hex()

        privkeys.append(priv_hex)
        pubs.append(pub_hex)

    script = make_multisig_script(pubs, m)
    addr = btc_make_p2sh_address(script)

    return {
        'address': addr,
        'redeem_script': script,
        'private_keys': privkeys,
        'segwit': False,
    }


def make_multisig_segwit_info( m, pks ):
    """
    Make either a p2sh-p2wpkh or p2sh-p2wsh
    redeem script and p2sh address.

    Return {'address': p2sh address, 'redeem_script': **the witness script**, 'private_keys': privkeys, 'segwit': True}
    * privkeys and redeem_script will be hex-encoded
    """
    pubs = []
    privkeys = []
    for pk in pks:
        priv = BitcoinPrivateKey(pk, compressed=True)
        priv_hex = priv.to_hex()
        pub_hex = priv.public_key().to_hex()

        privkeys.append(priv_hex)
        pubs.append(keylib.key_formatting.compress(pub_hex))

    script = None

    if len(pubs) == 1:
        if m != 1:
            raise ValueError("invalid m: len(pubkeys) == 1")

        # 1 pubkey means p2wpkh
        key_hash = hashing.bin_hash160(pubs[0].decode('hex')).encode('hex')
        script = '160014' + key_hash
        addr = btc_make_p2sh_address(script[2:])

    else:
        # 2+ pubkeys means p2wsh 
        script = make_multisig_script(pubs, m)
        addr = make_multisig_segwit_address_from_witness_script(script)

    return {
        'address': addr,
        'redeem_script': script,
        'private_keys': privkeys,
        'segwit': True,
        'm': m
    }


def make_multisig_wallet( m, n ):
    """
    Create a bundle of information
    that can be used to generate an 
    m-of-n multisig scriptsig.
    """

    if m <= 1 and n <= 1:
        raise ValueError("Invalid multisig parameters")

    pks = []
    for i in xrange(0, n):
        pk = BitcoinPrivateKey(compressed=True).to_wif()
        pks.append(pk)

    return make_multisig_info( m, pks )


def make_segwit_info(privkey=None):
    """
    Create a bundle of information
    that can be used to generate
    a p2sh-p2wpkh transaction
    """

    if privkey is None:
        privkey = BitcoinPrivateKey(compressed=True).to_wif()

    return make_multisig_segwit_info(1, [privkey])


def make_multisig_segwit_wallet( m, n ):
    """
    Create a bundle of information
    that can be used to generate an
    m-of-n multisig witness script.
    """
    pks = []
    for i in xrange(0, n):
        pk = BitcoinPrivateKey(compressed=True).to_wif()
        pks.append(pk)

    return make_multisig_segwit_info(m, pks)


def parse_multisig_redeemscript( redeem_script_hex ):
    """
    Given a redeem script (as hex), extract multisig information.
    Return m, list of public keys on success
    Return (None, None)
    """
    script_parts = []
    redeem_script_hex = str(redeem_script_hex)

    try:
        script_parts = btc_script_deserialize(redeem_script_hex)
    except:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            traceback.print_exc()

        log.error("Invalid redeem script %s" % redeem_script_hex)
        return None, None

    try:
        assert len(script_parts) > 2
        assert script_parts[-1] == OPCODE_VALUES['OP_CHECKMULTISIG']
        script_parts.pop(-1)

        # get n
        n = script_parts.pop(-1)
        pubkeys = []

        # get m
        m = script_parts.pop(0)

        for i in xrange(0, n):
            pubk = script_parts.pop(0)
            
            # must be a public key
            BitcoinPublicKey(pubk)
            pubkeys.append(pubk)

        assert len(script_parts) == 0, "script_parts = %s" % script_parts
        return (m, pubkeys)
    except Exception, e:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            traceback.print_exc()

        log.error("Invalid redeem script %s (parses to %s)" % (redeem_script_hex, script_parts))
        return (None, None)


def parse_multisig_scriptsig( scriptsig_hex ):
    """
    Given a scriptsig (as hex), extract the signatures.
    Return list of signatures on success
    Return None on error
    """
    try:
        script_parts = btc_script_deserialize(scriptsig_hex)
    except:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            traceback.print_exc()

        return None

    # sanity check 
    return script_parts


