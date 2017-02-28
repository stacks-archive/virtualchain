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

import os
import sys
import time
import socket
import types
import random
import copy
import bitcoin
import binascii
import json
import pybitcoin
import pprint
from decimal import *
import cPickle as pickle

from keys import version_byte as VERSION_BYTE
from keys import script_hex_to_address

from opcodes import *

import pybitcoin
import bitcoin
import bits

import traceback
import logging

log = logging.getLogger("virtualchain")

def tx_is_coinbase( tx ):
    """
    Is a transaction a coinbase transaction?
    """
    for inp in tx['vin']:
        if 'coinbase' in inp.keys():
            return True 

    return False


def tx_serialize( tx ):
     """
     Convert a bitcoin-given transaction into its hex string.
     tx format is {'vin': [...], 'vout': [...], 'locktime': ..., 'version': ...}, 
     with the same formatting rules as getrawtransaction.
     (in particular, each value in vout is a Decimal, in BTC)
     """
     tx_ins = []
     tx_outs = []

     try:
         for inp in tx['vin']:
             next_inp = {
                "outpoint": {
                   "index": int(inp['vout']),
                   "hash": str(inp['txid'])
                }
             }
             if 'sequence' in inp:
                 next_inp['sequence'] = int(inp['sequence'])
             else:
                 next_inp['sequence'] = pybitcoin.UINT_MAX

             if 'scriptSig' in inp:
                 next_inp['script'] = str(inp['scriptSig']['hex'])
             else:
                 next_inp['script'] = ""

             tx_ins.append(next_inp)

         for out in tx['vout']:
         
             assert out['value'] < 1000, "High transaction value\n%s" % simplejson.dumps(tx, indent=4, sort_keys=True)
             next_out = {
                'value': int(Decimal(out['value']) * Decimal(10**8)),
                'script': str(out['scriptPubKey']['hex'])
             }
             tx_outs.append(next_out)

         tx_fields = {
            "locktime": int(tx['locktime']),
            "version": int(tx['version']),
            "ins": tx_ins,
            "outs": tx_outs
         }

         tx_serialized = bitcoin.serialize( tx_fields )
         return str(tx_serialized)

     except KeyError, ke:
         if tx_is_coinbase(tx) and 'hex' in tx.keys():
             tx_serialized = tx['hex']
             return str(tx_serialized)

         import simplejson
         log.error("Key error in :\n%s" % simplejson.dumps(tx, indent=4, sort_keys=True))
         traceback.print_exc()
         raise ke



def tx_get_hash( tx_serialized ):
    """
    Make a transaction hash from a hex tx
    """
    tx_reversed_bin_hash = pybitcoin.bin_double_sha256( binascii.unhexlify(tx_serialized) )
    tx_candidate_hash = binascii.hexlify(tx_reversed_bin_hash[::-1])
    return tx_candidate_hash


def tx_verify( tx, tx_hash ):
    """
    Confirm that a bitcoin transaction has the given hash.
    """
    tx_serialized = tx_serialize( tx )
    tx_candidate_hash = tx_get_hash(tx_serialized)  # bitcoin.txhash( tx_serialized )
    # tx_reversed_bin_hash = pybitcoin.bin_double_sha256( binascii.unhexlify(tx_serialized) )
    # tx_candidate_hash = binascii.hexlify(tx_reversed_bin_hash[::-1])

    if tx_hash != tx_candidate_hash:
        print tx_serialized

    return tx_hash == tx_candidate_hash


def tx_script_to_asm( script_hex ):
    """
    Decode a script into assembler
    """
    if len(script_hex) == 0:
        return ""

    try:
        script_array = bitcoin.deserialize_script( script_hex )
    except:
        log.error("Failed to convert '%s' to assembler" % script_hex)
        raise

    script_tokens = []
    for token in script_array:
        if token is None:
            token = 0

        token_name = None

        if type(token) in [int,long]:
            token_name = OPCODE_NAMES.get(token, None)
            if token_name is None:
                token_name = str(token)
        
        else:
            token_name = token

        script_tokens.append(token_name)

    return " ".join(script_tokens)


def tx_deserialize( tx_hex ):
    """
    Given a serialized transaction, return its inputs, outputs, locktime, and version
    Each input will have:
    * txid: string 
    * vout: int 
    * [optional] sequence: int 
    * [optional] scriptSig: {"asm": ..., "hex": ...}
    
    Each output will have:
    * value: Decimal (in BTC)
    * script_hex: string 

    Return tx, formatted as {'locktime': ..., 'version': ..., 'vin': ..., 'vout': ...}
    """
    
    tx = bitcoin.deserialize( tx_hex )
    inputs = tx["ins"]
    outputs = tx["outs"]
    
    ret_inputs = []
    ret_outputs = []
   
    for inp in inputs:
        ret_inp = {
            "txid": inp["outpoint"]["hash"],
            "vout": int(inp["outpoint"]["index"]),
        }
        
        if "sequence" in inp:
            ret_inp["sequence"] = int(inp["sequence"])
            
        if "script" in inp:
            ret_inp["scriptSig"] = {
                "asm": tx_script_to_asm(inp['script']),
                "hex": inp["script"]
            }
            
        ret_inputs.append( ret_inp )
        
    for i in xrange(0, len(outputs)):
        out = outputs[i]
        
        assert len(out['script']) > 0, "Invalid transaction scriptpubkey:\n%s" % simplejson.dumps(tx, indent=4, sort_keys=True)
        assert out['value'] < 1000 * (10**8), "High transaction value\n%s" % simplejson.dumps(tx, indent=4, sort_keys=True)

        ret_out = {
            "n": i,
            "value": Decimal(out["value"]) / 10**8,
            "scriptPubKey": {
                "hex": out["script"],
                "asm": tx_script_to_asm(out['script'])
            },

            # compat with pybitcoin
            "script_hex": out["script"]
        }
        
        ret_outputs.append( ret_out )
        
    ret = {
        "txid": bitcoin.txhash(tx_hex),
        "hex": tx_hex,
        "size": len(tx_hex) / 2,
        "locktime": tx['locktime'],
        "version": tx['version'],
        "vin": ret_inputs,
        "vout": ret_outputs
    }

    return ret


def block_header_to_hex( block_data, prev_hash ):
    """
    Calculate the hex form of a block's header, given its getblock information from bitcoind.
    """
    header_info = {
       "version": block_data['version'],
       "prevhash": prev_hash,
       "merkle_root": block_data['merkleroot'],
       "timestamp": block_data['time'],
       "bits": int(block_data['bits'], 16),
       "nonce": block_data['nonce'],
       "hash": block_data['hash']
    }

    return bitcoin.serialize_header( header_info )


def block_header_verify( block_data, prev_hash, block_hash ):
    """
    Verify whether or not bitcoind's block header matches the hash we expect.
    """
    serialized_header = block_header_to_hex( block_data, prev_hash )
    candidate_hash_bin_reversed = pybitcoin.bin_double_sha256(binascii.unhexlify(serialized_header))
    candidate_hash = binascii.hexlify( candidate_hash_bin_reversed[::-1] )

    return block_hash == candidate_hash


def block_verify( block_data ):
    """
    Given block data (a dict with 'merkleroot' hex string and 'tx' list of hex strings--i.e.
    a block compatible with bitcoind's getblock JSON RPC method), verify that the
    transactions are consistent.

    Return True on success
    Return False if not.
    """
     
    # verify block data txs 
    m = pybitcoin.MerkleTree( block_data['tx'] )
    root_hash = str(m.root())

    return root_hash == str(block_data['merkleroot'])


def tx_output_parse_scriptPubKey( scriptpubkey ):
    """
    Given the hex representation of a scriptPubKey,
    turn it into a nice, easy-to-read dict like what
    bitcoind would give us.
    """
    script_tokens = bitcoin.deserialize_script( scriptpubkey )
    script_type = None
    reqSigs = None
    addresses = []
    if scriptpubkey.startswith("76a914") and scriptpubkey.endswith("88ac") and len(scriptpubkey) == 50:
        script_type = "pubkeyhash"
        reqSigs = 1
        addresses = [ script_hex_to_address(scriptpubkey) ]

    elif scriptpubkey.startswith("a914") and scriptpubkey.endswith("87") and len(scriptpubkey) == 46:
        script_type = "scripthash"
        reqsigs = 1
        addresses = [ script_hex_to_address(scriptpubkey) ]

    elif script_tokens[-1] == OPCODE_VALUES["OP_CHECKMULTISIG"]:
        script_type = "multisig"

    elif script_tokens[0] == OPCODE_VALUES["OP_RETURN"] and len(script_tokens) == 2:
        script_type = "nulldata"

    elif len(script_tokens) == 2 and script_tokens[-1] == OPCODE_VALUES["OP_CHECKSIG"]:
        script_type = "pubkey"
        reqSigs = 1

    else:
        script_type = "nonstandard"

    ret = {
        "asm": tx_script_to_asm(scriptpubkey),
        "hex": scriptpubkey,
        "type": script_type
    }

    if addresses is not None:
        ret['addresses'] = addresses

    if reqSigs is not None:
        ret['reqSigs'] = reqSigs

    return ret


