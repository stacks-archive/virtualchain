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

from .keys import btc_script_hex_to_address, btc_is_singlesig, btc_is_multisig, \
        btc_script_deserialize, btc_script_serialize, btc_is_singlesig_segwit, btc_is_multisig_segwit, btc_get_singlesig_privkey, \
        btc_make_p2sh_p2wpkh_redeem_script, btc_make_p2sh_p2wsh_redeem_script

from .opcodes import *
from ....lib import encoding, ecdsalib, hashing, merkle
from ....lib.config import get_features

import traceback

from ....lib.config import get_logger
log = get_logger('virtualchain')

# signature modes
SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 128

# bitcoin constants 
UINT_MAX = 4294967295


def read_as_int(ptr, buf, bytez):
    ptr[0] += bytez
    if ptr[0] > len(buf):
        raise ValueError("Invalid transaction: tried to parse {} bytes of {} offset in {}".format(bytez, ptr[0] - bytez, buf.encode('hex')))

    ret = encoding.decode( buf[ ptr[0]-bytez:ptr[0] ][::-1], 256 )
    return ret


def read_var_int(ptr, buf):
    ptr[0] += 1
    if ptr[0] > len(buf):
        raise ValueError("Invalid transaction: tried to parse {} byte of {} offset in {}".format(1, ptr[0] - 1, buf.encode('hex')))

    val = encoding.from_byte_to_int( buf[ ptr[0]-1 ] )
    if val < 253:
        return val

    ret = read_as_int(ptr, buf, pow(2, val - 252))
    return ret


def read_bytes(ptr, buf, bytez):
    ptr[0] += bytez
    if ptr[0] > len(buf):
        raise ValueError("Invalid transaction: tried to parse {} bytes of {} offset in {}".format(bytez, ptr[0] - bytez, buf.encode('hex')))

    ret = buf[ ptr[0]-bytez:ptr[0] ]
    return ret


def peek_bytes(ptr, buf, bytez):
    if ptr[0] + bytez > len(buf):
        raise ValueError("Invalid transaction: tried to parse {} bytes of {} offset in {}".format(bytez, ptr[0], buf.encode('hex')))

    ret = buf[ ptr[0]:ptr[0]+bytez ]
    return ret


def read_var_string(ptr, buf):
    size = read_var_int(ptr, buf)
    return read_bytes(ptr, buf, size)


def read_tx_body(ptr, tx):
    """
    Returns {'ins': [...], 'outs': [...]}
    """
    _obj = {"ins": [], "outs": [], 'locktime': None}

    # number of inputs
    ins = read_var_int(ptr, tx)

    # all inputs
    for i in range(ins):
        _obj["ins"].append({
            "outpoint": {
                "hash": read_bytes(ptr, tx, 32)[::-1],
                "index": read_as_int(ptr, tx, 4)
            },
            "script": read_var_string(ptr, tx),
            "sequence": read_as_int(ptr, tx, 4)
        })

    # number of outputs
    outs = read_var_int(ptr, tx)

    # all outputs
    for i in range(outs):
        _obj["outs"].append({
            "value": read_as_int(ptr, tx, 8),
            "script": read_var_string(ptr, tx)
        })

    return _obj


def read_tx_witnesses(ptr, tx, num_witnesses):
    """
    Returns an array of witness scripts.
    Each witness will be a bytestring (i.e. encoding the witness script)
    """
    witnesses = []
    for i in xrange(0, num_witnesses):

        witness_stack_len = read_var_int(ptr, tx)
        witness_stack = []

        for j in xrange(0, witness_stack_len):

            stack_item = read_var_string(ptr, tx)
            witness_stack.append(stack_item)
             
        witness_script = btc_witness_script_serialize(witness_stack).decode('hex')
        witnesses.append(witness_script)

    return witnesses


def make_var_string(string):
    """
    Make a var-string (a var-int with the length, concatenated with the data)
    Return the hex-encoded string
    """
    s = None
    if isinstance(string, str) and re.match('^[0-9a-fA-F]*$', string):
        # convert from hex to bin, safely
        s = binascii.unhexlify(string)
    else:
        s = string[:]

    buf = encoding.num_to_var_int(len(s)) + s
    return buf.encode('hex')


def _btc_witness_serialize_unit(unit):
    """
    Encode one item of a BTC witness script
    Return the encoded item (as a string)

    Returns a byte string with the encoded unit

    Based on code from pybitcointools (https://github.com/vbuterin/pybitcointools)
    by Vitalik Buterin
    """
    
    if isinstance(unit, int):
        # pass literal
        return encoding.from_int_to_byte(unit)

    elif unit is None:
        # None means OP_0
        return b'\x00'

    else:
        # return as a varint-prefixed string
        return make_var_string(unit)


def btc_witness_script_serialize(_stack):
    """
    Given a deserialized witness script stack (i.e. the input-specific witness, as an array of
    Nones, ints, and strings), turn it back into a hex-encoded script
    """
    stack = _stack
    if encoding.json_is_base(_stack, 16):
        # hex-to-bin all hex strings 
        stack = encoding.json_changebase(_stack, lambda x: binascii.unhexlify(x))

    return encoding.safe_hexlify(_btc_witness_serialize_unit(len(stack)) + ''.join(map(lambda stack_unit: _btc_witness_serialize_unit(stack_unit), stack)))


def btc_witness_script_deserialize(_script):
    """
    Given a hex-encoded serialized witness script, turn it into a witness stack
    (i.e. an array of Nones, ints, and strings)
    """

    script = None
    if isinstance(_script, str) and re.match('^[0-9a-fA-F]*$', _script):
        # convert from hex to bin, safely
        script = binascii.unhexlify(_script)
    else:
        script = _script[:]

    # pointer to byte offset in _script (as an array due to Python scoping rules)
    ptr = [0]

    witness_stack_len = read_var_int(ptr, script)
    witness_stack = []

    for _ in xrange(0, witness_stack_len):

        stack_item = read_var_string(ptr, script)
        witness_stack.append(stack_item)

    return witness_stack


def btc_tx_deserialize(_tx, **blockchain_opts):
    """
    Given a hex-encoded transaction, decode it into an object
    with the following structure:
    {
        ins: [
            {
                outpoint: { hash: ..., index: ... }, 
                script: ...,
                sequence: ...,
                witness_script: ...,        # not included if not segwit
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
    Throws an exception if there are remaining bytes
    """

    tx = None
    if isinstance(_tx, str) and re.match('^[0-9a-fA-F]*$', _tx):
        # convert from hex to bin, safely
        tx = binascii.unhexlify(_tx)
    else:
        tx = _tx[:]

    # pointer to byte offset in _tx (as an array due to Python scoping rules)
    ptr = [0]
    
    # top-level tx
    obj = {"ins": [], "outs": [], 'version': None, 'locktime': None}

    # get version
    obj["version"] = read_as_int(ptr, tx, 4)

    # segwit? (bip143)
    # 5th byte will be 0 and 6th byte will be flags (nonzero) if so
    bip143 = peek_bytes(ptr, tx, 2)
    if ord(bip143[0]) == 0 and ord(bip143[1]) != 0:
        # segwit
        # consume marker
        read_bytes(ptr, tx, 2)

        # get the rest of the body
        body = read_tx_body(ptr, tx)
        obj['ins'] = body['ins']
        obj['outs'] = body['outs']
     
        # read witnesses for each input
        witness_scripts = read_tx_witnesses(ptr, tx, len(obj['ins']))
      
        if len(witness_scripts) != len(obj['ins']):
            raise ValueError('Invald number of witnesses in {}'.format(_tx))

        for i in xrange(0, len(witness_scripts)):
            obj['ins'][i]['witness_script'] = witness_scripts[i]
        
    else:
        # non-segwit
        body = read_tx_body(ptr, tx)
        obj['ins'] = body['ins']
        obj['outs'] = body['outs']

    # locktime
    obj["locktime"] = read_as_int(ptr, tx, 4)

    if not ptr[0] == len(tx):
        # log.warning('Did not parse entire tx ({} bytes remaining)'.format(len(tx) - ptr[0]))
        raise ValueError('Did not parse entire tx ({} bytes remaining)'.format(len(tx) - ptr[0]))

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

    # do we have any witness scripts?
    have_witness = False
    for inp in txobj['ins']:
        if inp.has_key('witness_script') and len(inp['witness_script']) > 0:
            have_witness = True
            break

    if have_witness:
        # add segwit marker 
        o.append('\x00\x01')
    
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
        o.append(encoding.encode(inp.get("sequence", UINT_MAX - 1), 256, 4)[::-1])

    # number of outputs
    o.append(encoding.num_to_var_int(len(txobj["outs"])))

    # all outputs
    for out in txobj["outs"]:
        # value
        o.append(encoding.encode(out["value"], 256, 8)[::-1])

        # scriptPubKey
        scriptpubkey = encoding.num_to_var_int(len(out['script'])) + out['script']
        o.append(scriptpubkey)

    # add witnesses 
    if have_witness:
        for inp in txobj['ins']:
            witness_script = inp.get('witness_script')
            if not witness_script:
                witness_script = '\x00'

            o.append(witness_script)

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

             if 'txinwitness' in inp:
                 next_inp['witness_script'] = btc_witness_script_serialize(inp['txinwitness'])

             tx_ins.append(next_inp)

         for out in tx['vout']:
         
             assert out['value'] < 1000, "High transaction value\n%s" % simplejson.dumps(tx, indent=4, sort_keys=True)
             next_out = {
                'value': int(Decimal(out['value'] * 10**8)),
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

         log.error("Key error in:\n%s" % simplejson.dumps(tx, indent=4, sort_keys=True))
         traceback.print_exc()
         raise ke


def btc_tx_is_segwit( tx_serialized ):
    """
    Is this serialized (hex-encoded) transaction a segwit transaction?
    """
    marker_offset = 4       # 5th byte is the marker byte
    flag_offset = 5         # 6th byte is the flag byte
    
    marker_byte_string = tx_serialized[2*marker_offset:2*(marker_offset+1)]
    flag_byte_string = tx_serialized[2*flag_offset:2*(flag_offset+1)]

    if marker_byte_string == '00' and flag_byte_string != '00':
        # segwit (per BIP144)
        return True
    else:
        return False


def btc_tx_witness_strip( tx_serialized ):
    """
    Strip the witness information from a serialized transaction
    """
    if not btc_tx_is_segwit(tx_serialized):
        # already strippped
        return tx_serialized
     
    tx = btc_tx_deserialize(tx_serialized)
    for inp in tx['ins']:
        del inp['witness_script']

    tx_stripped = btc_tx_serialize(tx)
    return tx_stripped


def btc_tx_get_hash( tx_serialized, hashcode=None ):
    """
    Make a transaction hash (txid) from a hex tx, optionally along with a sighash.
    This DOES NOT WORK for segwit transactions
    """
    if btc_tx_is_segwit(tx_serialized):
        raise ValueError('Segwit transaction: {}'.format(tx_serialized))

    tx_bin = binascii.unhexlify(tx_serialized)
    if hashcode:
        return binascii.hexlify( hashing.bin_double_sha256(tx_bin + encoding.encode(int(hashcode), 256, 4)[::-1]) )

    else:
        return binascii.hexlify( hashing.bin_double_sha256(tx_bin)[::-1] )


def btc_tx_script_to_asm( script_hex ):
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


def btc_tx_output_has_data(output, **blockchain_opts):
    """
    Does this output have user data?
    @output must be an element from the 'outs' list in btc_tx_deserialize()
    """
    return btc_tx_output_script_has_data(output['script'], **blockchain_opts)


def btc_tx_output_script_has_data(output_script, **blockchain_opts):
    """
    Does a btc output script have data? i.e. is it an OP_RETURN?
    The script must be hex-encoded
    """
    if len(output_script) < 2:
        return False

    return int(output_script[0:2], 16) == OPCODE_VALUES['OP_RETURN']


def btc_tx_extend(partial_tx_hex, new_inputs, new_outputs, **blockchain_opts):
    """
    Given an unsigned serialized transaction, add more inputs and outputs to it.
    @new_inputs and @new_outputs will be virtualchain-formatted:
    * new_inputs[i] will have {'outpoint': {'index':..., 'hash':...}, 'script':..., 'witness_script': ...}
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


def btc_tx_der_encode_integer(r):
    """
    Return a DER-encoded integer

    Based on code from python-ecdsa (https://github.com/warner/python-ecdsa)
    by Brian Warner.  Subject to the MIT license.
    """
    # borrowed from python-ecdsa
    if r < 0:
        raise ValueError('cannot support negative numbers')

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


def btc_tx_der_encode_length(l):
    """
    Return a DER-encoded length field

    Based on code from python-ecdsa (https://github.com/warner/python-ecdsa)
    by Brian Warner.  Subject to the MIT license.
    """
    if l < 0:
        raise ValueError("length cannot be negative")

    if l < 0x80:
        return int2byte(l)
    s = ("%x" % l).encode()
    if len(s) % 2:
        s = b("0") + s
    s = binascii.unhexlify(s)
    llen = len(s)
    return int2byte(0x80 | llen) + s


def btc_tx_der_encode_sequence(*encoded_pieces):
    """
    Return a DER-encoded sequence

    Based on code from python-ecdsa (https://github.com/warner/python-ecdsa)
    by Brian Warner.  Subject to the MIT license.
    """
    # borrowed from python-ecdsa
    total_len = sum([len(p) for p in encoded_pieces])
    return b('\x30') + btc_tx_der_encode_length(total_len) + b('').join(encoded_pieces)


def btc_tx_der_encode_signature(r, s):
    """
    Return a DER-encoded signature as a 2-item sequence

    Based on code from python-ecdsa (https://github.com/warner/python-ecdsa)
    by Brian Warner.  Subject to the MIT license.
    """
    # borrowed from python-ecdsa
    return btc_tx_der_encode_sequence(btc_tx_der_encode_integer(r), btc_tx_der_encode_integer(s))


def btc_tx_sighash( tx, idx, script, hashcode=SIGHASH_ALL):
    """
    Calculate the sighash of a non-segwit transaction.

    If it's SIGHASH_NONE, then digest the inputs but no outputs 
    If it's SIGHASH_SINGLE, then digest all inputs and all outputs up to i (excluding values and scripts), and fully digest the ith input and output
    If it's (something) | SIGHASH_ANYONECANPAY, then only digest the ith input.
    
    Return the double-sha256 digest of the relevant fields.

    THIS DOES NOT WORK WITH SEGWIT OUTPUTS

    Adapted from https://github.com/vbuterin/pybitcointools, by Vitalik Buterin
    """

    txobj = btc_tx_deserialize(tx)

    idx = int(idx)
    hashcode = int(hashcode)
    newtx = copy.deepcopy(txobj)

    # remove all scriptsigs in all inputs, except for the ith input's scriptsig.
    # the other inputs will be 'partially signed', except for SIGHASH_ANYONECANPAY mode.
    for i in xrange(0, len(newtx['ins'])):
        newtx['ins'][i]["script"] = ''
        if i == idx:
            if newtx['ins'][i].has_key('witness_script') and newtx['ins'][i]['witness_script']:
                raise ValueError('this method does not handle segwit inputs')

        if newtx['ins'][i].has_key('witness_script'):
            del newtx['ins'][i]['witness_script']

    newtx["ins"][idx]["script"] = script

    if (hashcode & 0x1f) == SIGHASH_NONE:
        # don't care about the outputs with this signature
        newtx["outs"] = []
        for inp in newtx['ins']:
            inp['sequence'] = 0

    elif (hashcode & 0x1f) == SIGHASH_SINGLE:
        # only signing for this input.
        # all outputs after this input will not be signed.
        # all outputs before this input will be partially signed (but not their values or scripts)
        if len(newtx['ins']) > len(newtx['outs']):
            raise ValueError('invalid hash code: {} inputs but {} outputs'.format(len(newtx['ins']), len(newtx['outs'])))

        newtx["outs"] = newtx["outs"][:len(newtx["ins"])]
        for out in newtx["outs"][:len(newtx["ins"]) - 1]:
            out['value'] = 2**64 - 1
            out['script'] = ""

    elif (hashcode & SIGHASH_ANYONECANPAY) != 0:
        # only going to sign this specific input, and nothing else
        newtx["ins"] = [newtx["ins"][idx]]
   
    signing_tx = btc_tx_serialize(newtx)
    sighash = btc_tx_get_hash( signing_tx, hashcode )
    return sighash


def btc_tx_sighash_segwit(tx, i, prevout_amount, prevout_script, hashcode=SIGHASH_ALL):
    """
    Calculate the sighash for a segwit transaction, according to bip143
    """
    txobj = btc_tx_deserialize(tx)

    hash_prevouts = encoding.encode(0, 256, 32)
    hash_sequence = encoding.encode(0, 256, 32)
    hash_outputs = encoding.encode(0, 256, 32)

    if (hashcode & SIGHASH_ANYONECANPAY) == 0:
        prevouts = ''
        for inp in txobj['ins']:
            prevouts += hashing.reverse_hash(inp['outpoint']['hash'])
            prevouts += encoding.encode(inp['outpoint']['index'], 256, 4)[::-1].encode('hex')

        hash_prevouts = hashing.bin_double_sha256(prevouts.decode('hex'))

        # print 'prevouts: {}'.format(prevouts)

    if (hashcode & SIGHASH_ANYONECANPAY) == 0 and (hashcode & 0x1f) != SIGHASH_SINGLE and (hashcode & 0x1f) != SIGHASH_NONE:
        sequences = ''
        for inp in txobj['ins']:
            sequences += encoding.encode(inp['sequence'], 256, 4)[::-1].encode('hex')

        hash_sequence = hashing.bin_double_sha256(sequences.decode('hex'))

        # print 'sequences: {}'.format(sequences)

    if (hashcode & 0x1f) != SIGHASH_SINGLE and (hashcode & 0x1f) != SIGHASH_NONE:
        outputs = ''
        for out in txobj['outs']:
            outputs += encoding.encode(out['value'], 256, 8)[::-1].encode('hex')
            outputs += make_var_string(out['script'])

        hash_outputs = hashing.bin_double_sha256(outputs.decode('hex'))

        # print 'outputs: {}'.format(outputs)

    elif (hashcode & 0x1f) == SIGHASH_SINGLE and i < len(txobj['outs']):
        outputs = ''
        outputs += encoding.encode(txobj['outs'][i]['value'], 256, 8)[::-1].encode('hex')
        outputs += make_var_string(txobj['outs'][i]['script'])

        hash_outputs = hashing.bin_double_sha256(outputs.decode('hex'))

        # print 'outputs: {}'.format(outputs)

    # print 'hash_prevouts: {}'.format(hash_prevouts.encode('hex'))
    # print 'hash_sequence: {}'.format(hash_sequence.encode('hex'))
    # print 'hash_outputs: {}'.format(hash_outputs.encode('hex'))
    # print 'prevout_script: {}'.format(prevout_script)
    # print 'prevout_amount: {}'.format(prevout_amount)

    sighash_preimage = ''
    sighash_preimage += encoding.encode(txobj['version'], 256, 4)[::-1].encode('hex')
    sighash_preimage += hash_prevouts.encode('hex')
    sighash_preimage += hash_sequence.encode('hex')

    # this input's prevout, script, amount, and sequence
    sighash_preimage += hashing.reverse_hash(txobj['ins'][i]['outpoint']['hash'])
    sighash_preimage += encoding.encode(txobj['ins'][i]['outpoint']['index'], 256, 4)[::-1].encode('hex')
    sighash_preimage += make_var_string(prevout_script)
    sighash_preimage += encoding.encode(prevout_amount, 256, 8)[::-1].encode('hex')
    sighash_preimage += encoding.encode(txobj['ins'][i]['sequence'], 256, 4)[::-1].encode('hex')

    sighash_preimage += hash_outputs.encode('hex')
    sighash_preimage += encoding.encode(txobj['locktime'], 256, 4)[::-1].encode('hex')
    sighash_preimage += encoding.encode(hashcode, 256, 4)[::-1].encode('hex')

    sighash = hashing.bin_double_sha256(sighash_preimage.decode('hex')).encode('hex')

    # print 'sighash_preimage: {}'.format(sighash_preimage)
    # print 'sighash: {}'.format(sighash)

    return sighash
    

def btc_tx_make_input_signature(tx, idx, prevout_script, privkey_str, hashcode):
    """
    Sign a single input of a transaction, given the serialized tx,
    the input index, the output's scriptPubkey, and the hashcode.

    tx must be a hex-encoded string
    privkey_str must be a hex-encoded private key

    Return the hex signature.

    THIS DOES NOT WORK WITH SEGWIT TRANSACTIONS
    """
    if btc_tx_is_segwit(tx):
        raise ValueError('tried to use the standard sighash to sign a segwit transaction')

    pk = ecdsalib.ecdsa_private_key(str(privkey_str))
    priv = pk.to_hex()

    # get the parts of the tx we actually need to sign
    sighash = btc_tx_sighash(tx, idx, prevout_script, hashcode)
    # print 'non-segwit sighash: {}'.format(sighash)

    # sign using uncompressed private key
    pk_uncompressed_hex, pubk_uncompressed_hex = ecdsalib.get_uncompressed_private_and_public_keys(priv)
    sigb64 = ecdsalib.sign_digest( sighash, priv )

    # sanity check 
    # assert ecdsalib.verify_digest( txhash, pubk_uncompressed_hex, sigb64 )

    sig_r, sig_s = ecdsalib.decode_signature(sigb64)
    sig_bin = btc_tx_der_encode_signature(sig_r, sig_s)
    sig = sig_bin.encode('hex') + encoding.encode(hashcode, 16, 2)

    return sig


def btc_tx_make_input_signature_segwit(tx, idx, prevout_amount, prevout_script, privkey_str, hashcode):
    """
    Sign a single input of a transaction, given the serialized tx,
    the input index, the output's scriptPubkey, and the hashcode.

    tx must be a hex-encoded string
    privkey_str must be a hex-encoded private key

    Return the hex signature.
    """
    # always compressed
    if len(privkey_str) == 64:
        privkey_str += '01'

    pk = ecdsalib.ecdsa_private_key(str(privkey_str))
    pubk = pk.public_key()
    
    priv = pk.to_hex()

    # must always be compressed
    pub = keylib.key_formatting.compress(pubk.to_hex())
    sighash = btc_tx_sighash_segwit(tx, idx, prevout_amount, prevout_script, hashcode=hashcode)
    
    # sign using uncompressed private key
    # pk_uncompressed_hex, pubk_uncompressed_hex = ecdsalib.get_uncompressed_private_and_public_keys(priv)
    sigb64 = ecdsalib.sign_digest( sighash, priv )

    # sanity check 
    # assert ecdsalib.verify_digest( txhash, pubk_uncompressed_hex, sigb64 )

    sig_r, sig_s = ecdsalib.decode_signature(sigb64)
    sig_bin = btc_tx_der_encode_signature(sig_r, sig_s)
    sig = sig_bin.encode('hex') + encoding.encode(hashcode, 16, 2)

    # print 'segwit signature: {}'.format(sig)
    return sig


def btc_tx_sign_multisig(tx, idx, redeem_script, private_keys, hashcode=SIGHASH_ALL):
    """
    Sign a p2sh multisig input (not segwit!).

    @tx must be a hex-encoded tx

    Return the signed transaction
    """
    
    from .multisig import parse_multisig_redeemscript

    # sign in the right order.  map all possible public keys to their private key
    txobj = btc_tx_deserialize(str(tx))

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

        if public_key in used_keys:
            raise ValueError('Tried to reuse key in redeem script: {}'.format(public_key))

        pk_str = privs[public_key]
        used_keys.append(public_key)

        sig = btc_tx_make_input_signature(tx, idx, redeem_script, pk_str, hashcode)
        sigs.append(sig)

    if len(used_keys) != m:
        raise ValueError('Missing private keys (used {}, required {})'.format(len(used_keys), m))

    txobj["ins"][idx]["script"] = btc_script_serialize([None] + sigs + [redeem_script])
    return btc_tx_serialize(txobj)


def btc_tx_sign_multisig_segwit(tx, idx, prevout_amount, witness_script, private_keys, hashcode=SIGHASH_ALL, hashcodes=None, native=False):
    """
    Sign a native p2wsh or p2sh-p2wsh multisig input.

    @tx must be a hex-encoded tx

    Return the signed transaction
    """

    from .multisig import parse_multisig_redeemscript

    if hashcodes is None:
        hashcodes = [hashcode] * len(private_keys)

    txobj = btc_tx_deserialize(str(tx))
    privs = {}
    for pk in private_keys:
        pubk = ecdsalib.ecdsa_private_key(pk).public_key().to_hex()

        compressed_pubkey = keylib.key_formatting.compress(pubk)
        privs[compressed_pubkey] = pk

    m, public_keys = parse_multisig_redeemscript(witness_script)

    used_keys, sigs = [], []
    for i, public_key in enumerate(public_keys):
        if public_key not in privs:
            continue

        if len(used_keys) == m:
            break

        if public_key in used_keys:
            raise ValueError('Tried to reuse key in witness script: {}'.format(public_key))

        pk_str = privs[public_key]
        used_keys.append(public_key)

        sig = btc_tx_make_input_signature_segwit(tx, idx, prevout_amount, witness_script, pk_str, hashcodes[i])
        sigs.append(sig)

        # print ''

    if len(used_keys) != m:
        raise ValueError('Missing private keys (used {}, required {})'.format(len(used_keys), m))
   
    if native: 
        # native p2wsh
        txobj['ins'][idx]['witness_script'] = btc_witness_script_serialize([None] + sigs + [witness_script]) 

        # print 'segwit multisig: native p2wsh: witness script {}'.format(txobj['ins'][idx]['witness_script'])

    else:
        # p2sh-p2wsh
        redeem_script = btc_make_p2sh_p2wsh_redeem_script(witness_script)
        txobj['ins'][idx]['script'] = redeem_script
        txobj['ins'][idx]['witness_script'] = btc_witness_script_serialize([None] + sigs + [witness_script]) 
        
        # print 'segwit multisig: p2sh p2wsh: witness script {}'.format(txobj['ins'][idx]['witness_script'])
        # print 'segwit multisig: p2sh p2wsh: redeem script {}'.format(txobj['ins'][idx]['script'])
    
    return btc_tx_serialize(txobj)


def btc_tx_sign(tx_hex, idx, prevout_script, prevout_amount, private_key_info, scriptsig_type, hashcode=SIGHASH_ALL, hashcodes=None, redeem_script=None, witness_script=None):
    """
    Insert a scriptsig for an input that will later be spent by a p2pkh, p2pk, or p2sh scriptPubkey.

    @private_key_info is either a single private key, or a dict with 'redeem_script' and 'private_keys' defined.

    @redeem_script, if given, must NOT start with the varint encoding its length.
    However, it must otherwise be a hex string

    Return the transaction with the @idx'th scriptSig filled in.
    """
    new_tx = None
    
    # print 'sign input {} as {}'.format(idx, scriptsig_type)

    if scriptsig_type in ['p2pkh', 'p2pk']:
        if not btc_is_singlesig(private_key_info):
            raise ValueError('Need only one private key for {}'.format(scriptsig_type))

        pk = ecdsalib.ecdsa_private_key(str(private_key_info))
        pubk = pk.public_key()
        pub = pubk.to_hex()

        sig = btc_tx_make_input_signature(tx_hex, idx, prevout_script, private_key_info, hashcode)

        # print 'non-segwit sig: {}'.format(sig)
        # print 'non-segwit pubk: {}'.format(pub)

        # NOTE: sig and pub need to be hex-encoded
        txobj = btc_tx_deserialize(str(tx_hex))

        if scriptsig_type == 'p2pkh':
            # scriptSig + scriptPubkey is <signature> <pubkey> OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
            txobj['ins'][idx]['script'] = btc_script_serialize([sig, pub])

        else:
            # p2pk
            # scriptSig + scriptPubkey is <signature> <pubkey> OP_CHECKSIG
            txobj['ins'][idx]['script'] = btc_script_serialize([sig])

        new_tx = btc_tx_serialize(txobj)

    elif scriptsig_type == 'p2wpkh' or scriptsig_type == 'p2sh-p2wpkh':
        # must be a segwit singlesig bundle
        if not btc_is_singlesig_segwit(private_key_info):
            raise ValueError('Keys are not for p2wpkh or p2sh-p2wpkh')

        privkey_str = str(btc_get_singlesig_privkey(private_key_info))
        pk = ecdsalib.ecdsa_private_key(privkey_str)
        pubk = pk.public_key()
        pub = keylib.key_formatting.compress(pubk.to_hex())

        # special bip141 rule: this is always 0x1976a914{20-byte-pubkey-hash}88ac
        prevout_script_sighash = '76a914' + hashing.bin_hash160(pub.decode('hex')).encode('hex') + '88ac'

        sig = btc_tx_make_input_signature_segwit(tx_hex, idx, prevout_amount, prevout_script_sighash, privkey_str, hashcode)

        txobj = btc_tx_deserialize(str(tx_hex))
        txobj['ins'][idx]['witness_script'] = btc_witness_script_serialize([sig, pub])

        if scriptsig_type == 'p2wpkh':
            # native
            # NOTE: sig and pub need to be hex-encoded
            txobj['ins'][idx]['script'] = ''

            if redeem_script:
                # goes in scriptSig 
                txobj['ins'][idx]['script'] = btc_script_serialize([redeem_script])

        else:
            # p2sh-p2wpkh
            redeem_script = btc_make_p2sh_p2wpkh_redeem_script(pub)
            txobj['ins'][idx]['script'] = redeem_script

            # print 'scriptsig {} from {} is {}'.format(pub, privkey_str, txobj['ins'][idx]['script'])

        new_tx = btc_tx_serialize(txobj)

        # print 'scriptsig type: {}'.format(scriptsig_type)
        # print 'segwit scriptsig: {}'.format(txobj['ins'][idx]['script'])
        # print 'segwit witness script: {}'.format(txobj['ins'][idx]['witness_script'])

    elif scriptsig_type == 'p2wsh' or scriptsig_type == 'p2sh-p2wsh':
        # only support p2wsh for multisig purposes at this time
        if not btc_is_multisig_segwit(private_key_info):
            raise ValueError('p2wsh requires a multisig key bundle')

        native = None
        if scriptsig_type == 'p2wsh':
            native = True
        else:
            native = False

        new_tx = btc_tx_sign_multisig_segwit(tx_hex, idx, prevout_amount, private_key_info['redeem_script'], private_key_info['private_keys'], hashcode=hashcode, hashcodes=hashcodes, native=native)
       
        txobj = btc_tx_deserialize(new_tx)

        # print 'segwit scriptsig: {}'.format(txobj['ins'][idx]['script'])
        # print 'segwit witness script: {}'.format(txobj['ins'][idx]['witness_script'])

    elif scriptsig_type == 'p2sh':
    
        if not redeem_script:
            # p2sh multisig
            if not btc_is_multisig(private_key_info):
                raise ValueError('No redeem script given, and not a multisig key bundle')

            new_tx = btc_tx_sign_multisig(tx_hex, idx, private_key_info['redeem_script'], private_key_info['private_keys'], hashcode=hashcode)

        else:
            # NOTE: sig and pub need to be hex-encoded
            txobj = btc_tx_deserialize(str(tx_hex))

            # scriptSig + scriptPubkey is <redeem script> OP_HASH160 <script hash> OP_EQUAL
            txobj['ins'][idx]['script'] = btc_script_serialize([redeem_script]) 
            new_tx = btc_tx_serialize(txobj)

    else:
        raise ValueError("Unknown script type {}".format(scriptsig_type))

    return new_tx


def btc_script_classify(scriptpubkey, private_key_info=None):
    """
    Classify a scriptpubkey, optionally also using the private key info that will generate the corresponding scriptsig/witness
    Return None if not known (nonstandard)
    """
    if scriptpubkey.startswith("76a914") and scriptpubkey.endswith("88ac") and len(scriptpubkey) == 50:
        return 'p2pkh'

    elif scriptpubkey.startswith("a914") and scriptpubkey.endswith("87") and len(scriptpubkey) == 46:
        # maybe p2sh-p2wpkh or p2sh-p2wsh?
        if private_key_info:
            if btc_is_singlesig_segwit(private_key_info):
                return 'p2sh-p2wpkh'
            elif btc_is_multisig_segwit(private_key_info):
                return 'p2sh-p2wsh'

        return 'p2sh'

    elif scriptpubkey.startswith('0014') and len(scriptpubkey) == 44:
        return 'p2wpkh'

    elif scriptpubkey.startswith('0020') and len(scriptpubkey) == 68:
        return 'p2wsh'

    script_tokens = btc_script_deserialize(scriptpubkey)
    if len(script_tokens) == 0:
        return None

    if script_tokens[0] == OPCODE_VALUES['OP_RETURN']:
        return "nulldata"

    elif script_tokens[-1] == OPCODE_VALUES['OP_CHECKMULTISIG']:
        return "multisig"

    elif len(script_tokens) == 2 and script_tokens[-1] == OPCODE_VALUES["OP_CHECKSIG"]:
        return "p2pk"

    return None


def btc_privkey_scriptsig_classify(private_key_info):
    """
    What kind of scriptsig can this private key make?
    """
    if btc_is_singlesig(private_key_info):
        return 'p2pkh'

    if btc_is_multisig(private_key_info):
        return 'p2sh'

    if btc_is_singlesig_segwit(private_key_info):
        return 'p2sh-p2wpkh'

    if btc_is_multisig_segwit(private_key_info):
        return 'p2sh-p2wsh'

    return None


def btc_tx_sign_input(tx, idx, prevout_script, prevout_amount, private_key_info, hashcode=SIGHASH_ALL, hashcodes=None, segwit=None, scriptsig_type=None, redeem_script=None, witness_script=None, **blockchain_opts):
    """
    Sign a particular input in the given transaction.
    @private_key_info can either be a private key, or it can be a dict with 'redeem_script' and 'private_keys' defined

    Returns the tx with the signed input
    """
    if segwit is None:
        segwit = get_features('segwit')
    
    if scriptsig_type is None:
        scriptsig_type = btc_privkey_scriptsig_classify(private_key_info)
    
    if scriptsig_type in ['p2wpkh', 'p2wsh', 'p2sh-p2wpkh', 'p2sh-p2wsh'] and not segwit:
        raise ValueError("Segwit is not enabled, but {} is a segwit scriptsig type".format(prevout_script))

    return btc_tx_sign(tx, idx, prevout_script, prevout_amount, private_key_info, scriptsig_type, hashcode=hashcode, hashcodes=hashcodes, redeem_script=redeem_script, witness_script=witness_script)


def btc_tx_sign_all_unsigned_inputs(private_key_info, prev_outputs, unsigned_tx_hex, scriptsig_type=None, segwit=None, **blockchain_opts):
    """
    Sign all unsigned inputs with a given key.
    Use the given outputs to fund them.

    @private_key_info: either a hex private key, or a dict with 'private_keys' and 'redeem_script'
    defined as keys.
    @prev_outputs: a list of {'out_script': xxx, 'value': xxx} that are in 1-to-1 correspondence with the unsigned inputs in the tx ('value' is in satoshis)
    @unsigned_hex_tx: hex transaction with unsigned inputs

    Returns: signed hex transaction
    """
    if segwit is None:
        segwit = get_features('segwit')
    
    txobj = btc_tx_deserialize(unsigned_tx_hex)
    inputs = txobj['ins']
    
    if scriptsig_type is None:
        scriptsig_type = btc_privkey_scriptsig_classify(private_key_info)

    tx_hex = unsigned_tx_hex
    prevout_index = 0
    
    # import json
    # print ''
    # print 'transaction:\n{}'.format(json.dumps(btc_tx_deserialize(unsigned_tx_hex), indent=4, sort_keys=True))
    # print 'prevouts:\n{}'.format(json.dumps(prev_outputs, indent=4, sort_keys=True))
    # print ''

    for i, inp in enumerate(inputs):
        do_witness_script = segwit
        if inp.has_key('witness_script'):
            do_witness_script = True

        elif segwit:
            # all inputs must receive a witness script, even if it's empty 
            inp['witness_script'] = ''

        if (inp['script'] and len(inp['script']) > 0) or (inp.has_key('witness_script') and len(inp['witness_script']) > 0):
            continue

        if prevout_index >= len(prev_outputs):
            raise ValueError("Not enough prev_outputs ({} given, {} more prev-outputs needed)".format(len(prev_outputs), len(inputs) - prevout_index))

        # tx with index i signed with privkey
        tx_hex = btc_tx_sign_input(str(unsigned_tx_hex), i, prev_outputs[prevout_index]['out_script'], prev_outputs[prevout_index]['value'], private_key_info, segwit=do_witness_script, scriptsig_type=scriptsig_type)
        unsigned_tx_hex = tx_hex
        prevout_index += 1

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
   
    script_type = btc_script_classify(scriptpubkey)
    script_tokens = btc_script_deserialize(scriptpubkey)

    if script_type in ['p2pkh']:
        script_type = "pubkeyhash"
        reqSigs = 1
        addr = btc_script_hex_to_address(scriptpubkey)
        if not addr:
            raise ValueError("Failed to parse scriptpubkey address")

        addresses = [addr]

    elif script_type in ['p2sh', 'p2sh-p2wpkh', 'p2sh-p2wsh']:
        script_type = "scripthash"
        reqSigs = 1
        addr = btc_script_hex_to_address(scriptpubkey)
        if not addr:
            raise ValueError("Failed to parse scriptpubkey address")

        addresses = [addr]

    elif script_type == 'p2pk':
        script_type = "pubkey"
        reqSigs = 1

    elif script_type is None:
        script_type = "nonstandard"

    ret = {
        "asm": btc_tx_script_to_asm(scriptpubkey),
        "hex": scriptpubkey,
        "type": script_type
    }

    if addresses is not None:
        ret['addresses'] = addresses

    if reqSigs is not None:
        ret['reqSigs'] = reqSigs

    # print 'parse script {}: {}'.format(scriptpubkey, ret)

    return ret


