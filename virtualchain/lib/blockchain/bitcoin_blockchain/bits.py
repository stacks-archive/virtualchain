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
import re
import copy
import binascii
import simplejson
import keylib
from six import int2byte, b, integer_types
from decimal import *

from .keys import script_hex_to_address, address_reencode, is_singlesig, is_multisig, make_payment_script, \
        btc_script_deserialize, btc_script_serialize

from .opcodes import *
from ....lib import encoding, ecdsalib, hashing, merkle

import traceback
import logging

log = logging.getLogger("virtualchain")

# signature modes
SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 129

# bitcoin constants 
UINT_MAX = 4294967295

def btc_tx_deserialize(_tx):
    """
    Given a hex-encoded transaction, decode it into an object
    with the following structure:
    {
        ins: [
            {
                output: { hash: ..., index: ... }, 
                script: ...,
                sequence: ...,
            }, ...
        ]
        outs: [
            {
                value: ...,
                script: ...
            }, ...
        ],
        version: ..., 
        locktime: ...
    }
    
    Derived from pybitcointools (https://github.com/vbuterin/pybitcointools) written by Vitalik Buterin
    """

    tx = None
    if isinstance(_tx, str) and re.match('^[0-9a-fA-F]*$', _tx):
        # convert from hex to bin, safely
        tx = binascii.unhexlify(_tx)
    else:
        tx = _tx[:]

    # NOTE: need pass-by-reference for methods
    # that modify variables outside of their scope
    # that live in another method's scope
    buf = [0]

    def read_as_int(bytez):
        buf[0] += bytez
        return encoding.decode( tx[ buf[0]-bytez:buf[0] ][::-1], 256 )

    def read_var_int():
        buf[0] += 1
        
        val = encoding.from_byte_to_int( tx[ buf[0]-1 ] )
        if val < 253:
            return val

        return read_as_int(pow(2, val - 252))

    def read_bytes(bytez):
        buf[0] += bytez

        return tx[ buf[0]-bytez:buf[0] ]

    def read_var_string():
        size = read_var_int()
        return read_bytes(size)

    # top-level tx
    obj = {"ins": [], "outs": []}

    # get version
    obj["version"] = read_as_int(4)

    # number of inputs
    ins = read_var_int()

    # all inputs
    for i in range(ins):
        obj["ins"].append({
            "outpoint": {
                "hash": read_bytes(32)[::-1],
                "index": read_as_int(4)
            },
            "script": read_var_string(),
            "sequence": read_as_int(4)
        })

    # number of outputs
    outs = read_var_int()

    # all outputs
    for i in range(outs):
        obj["outs"].append({
            "value": read_as_int(8),
            "script": read_var_string()
        })

    # locktime
    obj["locktime"] = read_as_int(4)

    # hexlify each byte field 
    obj = encoding.json_changebase(obj, lambda x: encoding.safe_hexlify(x))
    return obj


def btc_tx_serialize(_txobj):
    """
    Given a transaction dict returned by btc_tx_deserialize, convert it back into a
    hex-encoded byte string.

    Derived from code written by Vitalik Buterin in pybitcointools (https://github.com/vbuterin/pybitcointools)
    """
    
    # output buffer
    o = []
    txobj = None
    if encoding.json_is_base(_txobj, 16):
        # txobj is built from hex strings already.  deserialize them 
        txobj = encoding.json_changebase(_txobj, lambda x: binascii.unhexlify(x))
    else:
        txobj = copy.deepcopy(_txobj)

    # version
    o.append(encoding.encode(txobj["version"], 256, 4)[::-1])

    # number of inputs
    o.append(encoding.num_to_var_int(len(txobj["ins"])))

    # all inputs
    for inp in txobj["ins"]:
        # input tx hash
        o.append(inp["outpoint"]["hash"][::-1])

        # input tx outpoint
        o.append(encoding.encode(inp["outpoint"]["index"], 256, 4)[::-1])

        # input scriptsig
        script = inp.get('script')
        if not script:
            script = bytes()

        scriptsig = encoding.num_to_var_int(len(script)) + script
        o.append(scriptsig)

        # sequence
        o.append(encoding.encode(inp.get("sequence", UINT_MAX), 256, 4)[::-1])

    # number of outputs
    o.append(encoding.num_to_var_int(len(txobj["outs"])))

    # all outputs
    for out in txobj["outs"]:

        # value
        o.append(encoding.encode(out["value"], 256, 8)[::-1])

        # scriptPubKey
        scriptpubkey = encoding.num_to_var_int(len(out['script'])) + out['script']
        o.append(scriptpubkey)

    # locktime
    o.append(encoding.encode(txobj["locktime"], 256, 4)[::-1])

    # full string
    ret = ''.join( encoding.json_changebase(o, lambda x: encoding.safe_hexlify(x)) )
    return ret


def btc_bitcoind_tx_is_coinbase( tx ):
    """
    Is a transaction a coinbase transaction?
    tx is a bitcoind-given transaction structure
    """
    for inp in tx['vin']:
        if 'coinbase' in inp.keys():
            return True 

    return False


def btc_bitcoind_tx_serialize( tx ):
     """
     Convert a *Bitcoind*-given transaction into its hex string.

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
                 next_inp['sequence'] = UINT_MAX

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

         tx_serialized = btc_tx_serialize( tx_fields )
         return str(tx_serialized)

     except KeyError, ke:
         if btc_bitcoind_tx_is_coinbase(tx) and 'hex' in tx.keys():
             tx_serialized = tx['hex']
             return str(tx_serialized)

         log.error("Key error in :\n%s" % simplejson.dumps(tx, indent=4, sort_keys=True))
         traceback.print_exc()
         raise ke


def btc_tx_get_hash( tx_serialized, hashcode=None ):
    """
    Make a transaction hash from a hex tx
    """
    tx_bin = binascii.unhexlify(tx_serialized)
    if hashcode:
        return binascii.hexlify( hashing.bin_double_sha256(tx_bin + encoding.encode(int(hashcode), 256, 4)[::-1]) )

    else:
        return binascii.hexlify( hashing.bin_double_sha256(tx_bin)[::-1] )


def tx_script_to_asm( script_hex ):
    """
    Decode a script into assembler
    """
    if len(script_hex) == 0:
        return ""

    try:
        script_array = btc_script_deserialize(script_hex)
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


def tx_output_has_data(output):
    """
    High-level API (meant to be usable across blockchains)
    Does this output have user data?
    @output must be an element from the 'outs' list in btc_tx_deserialize()
    """
    return int(output['script'][0:2], 16) == OPCODE_VALUES['OP_RETURN']


def tx_extend(partial_tx_hex, new_inputs, new_outputs):
    """
    High-level API (meant to be usable across blockchains)
    Given an unsigned serialized transaction, add more inputs and outputs to it.
    @new_inputs and @new_outputs will be virtualchain-formatted:
    * new_inputs[i] will have {'outpoint': {'index':..., 'hash':...}, 'script':...}
    * new_outputs[i] will have {'script':..., 'value':... (in fundamental units, e.g. satoshis!)}
    """

    # recover tx
    tx = btc_tx_deserialize(partial_tx_hex)
    tx_inputs, tx_outputs = tx['ins'], tx['outs']
    locktime, version = tx['locktime'], tx['version']

    tx_inputs += new_inputs
    tx_outputs += new_outputs

    new_tx = {
        'ins': tx_inputs,
        'outs': tx_outputs,
        'locktime': locktime,
        'version': version,
    }

    new_unsigned_tx = btc_tx_serialize(new_tx)
    return new_unsigned_tx


def tx_der_encode_integer(r):
    """
    High-level API (meant to be usable across blockchains)
    Return a DER-encoded integer

    Based on code from python-ecdsa (https://github.com/warner/python-ecdsa)
    by Brian Warner.  Subject to the MIT license.
    """
    # borrowed from python-ecdsa
    assert r >= 0  # can't support negative numbers yet
    h = ("%x" % r).encode()
    if len(h) % 2:
        h = b("0") + h
    s = binascii.unhexlify(h)
    num = s[0] if isinstance(s[0], integer_types) else ord(s[0])
    if num <= 0x7f:
        return b("\x02") + int2byte(len(s)) + s
    else:
        # DER integers are two's complement, so if the first byte is
        # 0x80-0xff then we need an extra 0x00 byte to prevent it from
        # looking negative.
        return b("\x02") + int2byte(len(s)+1) + b("\x00") + s


def tx_der_encode_length(l):
    """
    High-level API (meant to be usable across blockchains)
    Return a DER-encoded length field

    Based on code from python-ecdsa (https://github.com/warner/python-ecdsa)
    by Brian Warner.  Subject to the MIT license.
    """
    assert l >= 0
    if l < 0x80:
        return int2byte(l)
    s = ("%x" % l).encode()
    if len(s) % 2:
        s = b("0") + s
    s = binascii.unhexlify(s)
    llen = len(s)
    return int2byte(0x80 | llen) + s


def tx_der_encode_sequence(*encoded_pieces):
    """
    High-level API (meant to be usable across blockchains)
    Return a DER-encoded sequence

    Based on code from python-ecdsa (https://github.com/warner/python-ecdsa)
    by Brian Warner.  Subject to the MIT license.
    """
    # borrowed from python-ecdsa
    total_len = sum([len(p) for p in encoded_pieces])
    return b('\x30') + tx_der_encode_length(total_len) + b('').join(encoded_pieces)


def tx_der_encode_signature(r, s):
    """
    High-level API (meant to be usable across blockchains)
    Return a DER-encoded signature as a 2-item sequence

    Based on code from python-ecdsa (https://github.com/warner/python-ecdsa)
    by Brian Warner.  Subject to the MIT license.
    """
    # borrowed from python-ecdsa
    return tx_der_encode_sequence(tx_der_encode_integer(r), tx_der_encode_integer(s))


def btc_tx_signature_form( txobj, i, script, hashcode=SIGHASH_ALL ):
    """
    Given a transaction (either a hex string or a transaction structure),
    insert the signature according to the given hash code.

    If it's SIGHASH_NONE, then partially sign the inputs but no outputs.
    If it's SIGHASH_SINGLE, then partially sign all inputs and all outputs up to i, and sign fully input i and output i.
    If it's SIGHASH_ANYONECANPAY, then sign only the ith input.
    
    Return the new transaction, whose hash can then be signed with the relevant keys.

    Adapted from https://github.com/vbuterin/pybitcointools, by Vitalik Buterin
    """
    i = int(i)
    hashcode = int(hashcode)
    newtx = copy.deepcopy(txobj)

    # remove all scriptsigs in all inputs, except for the ith input's scriptsig.
    # the other inputs will be 'partially signed', except for SIGHASH_ANYONECANPAY mode.
    for inp in newtx["ins"]:
        inp["script"] = ""

    newtx["ins"][i]["script"] = script

    if hashcode == SIGHASH_NONE:
        # don't care about the outputs with this signature
        newtx["outs"] = []

    elif hashcode == SIGHASH_SINGLE:
        # only signing for this input.
        # all outputs after this input will not be signed.
        # all outputs before this input will be partially signed (but not their values or scripts)
        newtx["outs"] = newtx["outs"][:len(newtx["ins"])]
        for out in newtx["outs"][:len(newtx["ins"]) - 1]:
            out['value'] = 2**64 - 1
            out['script'] = ""

    elif hashcode == SIGHASH_ANYONECANPAY:
        # only going to sign this specific input, and nothing else
        newtx["ins"] = [newtx["ins"][i]]

    return newtx


def btc_tx_apply_multisignatures(tx, i, script, sigs):
    """
    Given the transaction string (hex or bin), the ith input, the multisig scriptsig, and the relevant signatures,
    insert the scriptsig and signatures into the appropriate places.

    tx is a hex-encoded transaction
    script is a hex-encoded redeem script
    sigs is a list of hex-encoded signatures
    """

    # Not pushing empty elements on the top of the stack if passing no
    # script (in case of bare multisig inputs there is no script)
    script_blob = [] if script.__len__() == 0 else [script]

    # deserialize the tx, insert the scriptsig, and re-serialize
    txobj = btc_tx_deserialize(tx)
    txobj["ins"][i]["script"] = btc_script_serialize([None] + sigs + script_blob)
    txstr = btc_tx_serialize(txobj)
    return txstr


def btc_tx_make_input_signature(tx, idx, script, privkey_str, hashcode):
    """
    Sign a single input of a transaction, given the serialized tx,
    the input index, the output's scriptPubkey, and the hashcode.

    privkey_str must be a hex-encoded private key

    Return the hex signature.
    """
    pk = ecdsalib.ecdsa_private_key(str(privkey_str))
    pubk = pk.public_key()
    
    priv = pk.to_hex()
    pub = pubk.to_hex()
    addr = address_reencode( pubk.address() )

    # get the parts of the tx we actually need to sign
    txobj = btc_tx_deserialize(tx)
    signing_txobj = btc_tx_signature_form(txobj, idx, script, hashcode)
    signing_tx = btc_tx_serialize(signing_txobj)

    txhash = btc_tx_get_hash( signing_tx, hashcode )

    # sign using uncompressed private key
    pk_uncompressed_hex, pubk_uncompressed_hex = ecdsalib.get_uncompressed_private_and_public_keys(priv)
    sigb64 = ecdsalib.sign_digest( txhash, priv )

    # sanity check 
    assert ecdsalib.verify_digest( txhash, pubk_uncompressed_hex, sigb64 )

    sig_r, sig_s = ecdsalib.decode_signature(sigb64)
    sig_bin = tx_der_encode_signature(sig_r, sig_s)
    sig = sig_bin.encode('hex') + encoding.encode(hashcode, 16, 2)

    return sig


def btc_tx_sign_multisig(tx, idx, redeem_script, private_keys, hashcode=SIGHASH_ALL):
    """
    Sign a p2sh multisig input.
    Return the signed transaction
    """
    
    from .multisig import parse_multisig_redeemscript
    
    # sign in the right order.  map all possible public keys to their private key 
    privs = {}
    for pk in private_keys:
        pubk = ecdsalib.ecdsa_private_key(pk).public_key().to_hex()

        compressed_pubkey = keylib.key_formatting.compress(pubk)
        uncompressed_pubkey = keylib.key_formatting.decompress(pubk)

        privs[compressed_pubkey] = pk
        privs[uncompressed_pubkey] = pk

    m, public_keys = parse_multisig_redeemscript(str(redeem_script))

    used_keys, sigs = [], []
    for public_key in public_keys:
        if public_key not in privs:
            continue

        if len(used_keys) == m:
            break

        assert public_key not in used_keys, 'Tried to reuse key {}'.format(public_key)

        pk_str = privs[public_key]
        used_keys.append(public_key)

        sig = btc_tx_make_input_signature(tx, idx, redeem_script, pk_str, hashcode)
        sigs.append(sig)

    assert len(used_keys) == m, 'Missing private keys (used {}, required {})'.format(len(used_keys), m)
    return btc_tx_apply_multisignatures(tx, idx, str(redeem_script), sigs)


def btc_tx_sign_singlesig(tx, idx, private_key_info, hashcode=SIGHASH_ALL):
    """
    Sign a p2pkh input
    Return the signed transaction
    """
    pk = ecdsalib.ecdsa_private_key(str(private_key_info))
    pubk = pk.public_key()

    pub = pubk.to_hex()
    addr = address_reencode( pubk.address() )

    script = make_payment_script(addr)
    sig = btc_tx_make_input_signature(tx, idx, script, private_key_info, hashcode)

    # NOTE: sig and pub need to be hex-encoded
    txobj = btc_tx_deserialize(str(tx))
    txobj['ins'][idx]['script'] = btc_script_serialize([sig, pub])
    return btc_tx_serialize(txobj)


def tx_sign_input(blockstack_tx, idx, private_key_info, hashcode=SIGHASH_ALL):
    """
    High-level API call (meant to be implemented across all blockchains)

    Sign a particular input in the given transaction.
    @private_key_info can either be a private key, or it can be a dict with 'redeem_script' and 'private_keys' defined
    """
    if is_singlesig(private_key_info):
        # single private key
        return btc_tx_sign_singlesig(blockstack_tx, idx, private_key_info, hashcode=hashcode)

    elif is_multisig(private_key_info):

        redeem_script = private_key_info['redeem_script']
        private_keys = private_key_info['private_keys']

        redeem_script = str(redeem_script)

        # multisig
        return btc_tx_sign_multisig(blockstack_tx, idx, redeem_script, private_keys, hashcode=hashcode)

    else:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.debug("Invalid private key info: {}".format(private_key_info))

        raise ValueError("Invalid private key info")


def tx_sign_all_unsigned_inputs(private_key_info, unsigned_tx_hex):
    """
    High-level API call (meant to be implemented across all blockchains)
    Sign all unsigned inputs in the given transaction.

    @private_key_info: either a hex private key, or a dict with 'private_keys' and 'redeem_script'
    defined as keys.
    @unsigned_hex_tx: hex transaction with unsigned inputs

    Returns: signed hex transaction
    """
    txobj = btc_tx_deserialize(unsigned_tx_hex)
    inputs = txobj['ins']
    tx_hex = unsigned_tx_hex
    for i, inp in enumerate(inputs):
        if inp['script'] and len(inp['script']) > 0:
            continue

        # tx with index i signed with privkey
        tx_hex = tx_sign_input(str(unsigned_tx_hex), i, private_key_info)
        unsigned_tx_hex = tx_hex

    return tx_hex


def block_header_serialize( inp ):
    """
    Given block header information, serialize it and return the hex hash.

    inp has:
    * version (int)
    * prevhash (str)
    * merkle_root (str)
    * timestamp (int)
    * bits (int)
    * nonce (int)

    Based on code from pybitcointools (https://github.com/vbuterin/pybitcointools)
    by Vitalik Buterin
    """
    
    # concatenate to form header
    o = encoding.encode(inp['version'], 256, 4)[::-1] + \
        inp['prevhash'].decode('hex')[::-1] + \
        inp['merkle_root'].decode('hex')[::-1] + \
        encoding.encode(inp['timestamp'], 256, 4)[::-1] + \
        encoding.encode(inp['bits'], 256, 4)[::-1] + \
        encoding.encode(inp['nonce'], 256, 4)[::-1]

    # get (reversed) hash
    h = hashing.bin_sha256(hashing.bin_sha256(o))[::-1].encode('hex')
    assert h == inp['hash'], (hashing.bin_sha256(o).encode('hex'), inp['hash'])

    return o.encode('hex')


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

    return block_header_serialize(header_info)


def block_header_verify( block_data, prev_hash, block_hash ):
    """
    Verify whether or not bitcoind's block header matches the hash we expect.
    """
    serialized_header = block_header_to_hex( block_data, prev_hash )
    candidate_hash_bin_reversed = hashing.bin_double_sha256(binascii.unhexlify(serialized_header))
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
    m = merkle.MerkleTree( block_data['tx'] )
    root_hash = str(m.root())

    return root_hash == str(block_data['merkleroot'])


def btc_tx_output_parse_script( scriptpubkey ):
    """
    Given the hex representation of a script,
    turn it into a nice, easy-to-read dict.
    The dict will have:
    * asm: the disassembled script as a string
    * hex: the raw hex (given as an argument)
    * type: the type of script

    Optionally, it will have:
    * addresses: a list of addresses the script represents (if applicable)
    * reqSigs: the number of required signatures (if applicable)
    """

    script_type = None
    reqSigs = None
    addresses = []
    
    script_tokens = btc_script_deserialize(scriptpubkey)

    if scriptpubkey.startswith("76a914") and scriptpubkey.endswith("88ac") and len(scriptpubkey) == 50:
        script_type = "pubkeyhash"
        reqSigs = 1
        addr = script_hex_to_address(scriptpubkey)
        assert addr

        addresses = [addr]

    elif scriptpubkey.startswith("a914") and scriptpubkey.endswith("87") and len(scriptpubkey) == 46:
        script_type = "scripthash"
        reqsigs = 1
        addr = script_hex_to_address(scriptpubkey)
        assert addr

        addresses = [addr]

    elif script_tokens[0] == OPCODE_VALUES['OP_RETURN']:
        script_type = "nulldata"

    elif scriptpubkey.endswith("ae"):
        script_type = "multisig"

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


