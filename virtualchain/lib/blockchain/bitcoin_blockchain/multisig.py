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

import os
import binascii

def make_multisig_script( pubs, m ):
    """
    Make a multisig scriptSig script, as a hex string
    """
    return btc_script_serialize( [m] + pubs + [len(pubs)] + [OPCODE_VALUES['OP_CHECKMULTISIG']] )
   

def make_multisig_address(pubs, m):
    """
    Make a multisig address, given the list of public keys (as hex strings) and the number required for validation
    """
    return btc_make_p2sh_address(make_multisig_script(pubs, m))


def make_multisig_info( m, pks ):
    """
    Make a multisig address and redeem script.
    @m of the given @pks must sign.

    Return {'address': p2sh address, 'redeem_script': redeem script, 'private_keys': private keys}
    * privkeys will be hex-encoded
    * redeem_script will be hex-encoded
    """

    pubs = []
    privkeys = []
    for pk in pks:
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
        'private_keys': privkeys
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
            print >> sys.stderr, "Invalid redeem script %s" % redeem_script_hex

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
            print >> sys.stderr, "Invalid redeem script %s (parses to %s)" % (redeem_script_hex, script_parts)

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


