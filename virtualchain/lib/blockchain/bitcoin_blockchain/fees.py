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

import os
import keylib
import logging

from .authproxy import JSONRPCException

from .bits import btc_tx_deserialize, btc_tx_is_segwit, btc_witness_script_serialize

from .keys import btc_is_singlesig, btc_is_multisig, btc_is_singlesig_segwit, btc_is_multisig_segwit, \
        btc_make_p2sh_p2wsh_redeem_script, btc_make_p2sh_p2wpkh_redeem_script

from .multisig import parse_multisig_redeemscript
from ..session import get_bitcoind_client
from ....lib.ecdsalib import ecdsa_private_key
from ....lib.config import get_logger

log = get_logger('virtualchain')

def calculate_tx_fee( tx_hex, fee_per_byte ):
    """
    High-level API call (meant to be blockchain-agnostic)
    What is the fee for the transaction?
    """
    txobj = btc_tx_deserialize(tx_hex)
    tx_num_bytes = len(tx_hex) / 2
    num_virtual_bytes = None

    if btc_tx_is_segwit(tx_hex):
        # segwit--discount witness data 
        witness_len = 0
        for inp in txobj['ins']:
            witness_len += len(inp['witness_script']) / 2 

        # see https://bitcoincore.org/en/segwit_wallet_dev/#transaction-fee-estimation
        tx_num_bytes_original = tx_num_bytes - witness_len
        num_virtual_bytes = 3 * tx_num_bytes_original + tx_num_bytes

    else:
        # non-segwit 
        num_virtual_bytes = tx_num_bytes * 4

    return (fee_per_byte * num_virtual_bytes) / 4


def get_tx_fee_per_byte(bitcoind_opts=None, config_path=None, bitcoind_client=None):
    """
    Get the tx fee per byte from the underlying blockchain
    Return the fee on success
    Return None on error
    """
    if bitcoind_client is None:
        bitcoind_client = get_bitcoind_client(bitcoind_opts=bitcoind_opts, config_path=config_path)

    try:
        # try to confirm in 2-3 blocks
        try:
            fee_info = bitcoind_client.estimatesmartfee(2)
            if 'errors' in fee_info and len(fee_info['errors']) > 0:
                fee = -1
            else:
                fee = fee_info['feerate']

        except JSONRPCException as je:
            fee = bitcoind_client.estimatefee(2)

        if fee < 0:
            # if we're testing, then use our own fee
            if os.environ.get("BLOCKSTACK_TEST") == '1' or os.environ.get("BLOCKSTACK_TESTNET", None) == "1":
                fee = 5500.0 / 10**8

            else:
                log.error("Failed to estimate tx fee")
                return None
        else:
            log.debug("Bitcoin estimatefee(2) is {}".format(fee))

        fee = float(fee)

        # fee is BTC/kb.  Return satoshis/byte
        ret = int(round(fee * 10**8 / 1024.0))
        log.debug("Bitcoin estimatefee(2) is {} ({} satoshi/byte)".format(fee, ret))
        return ret

    except Exception as e:
        if os.environ.get("BLOCKSTACK_DEBUG") == '1':
            log.exception(e)

        log.error("Failed to estimate tx fee per byte")
        return None


def get_tx_fee(tx_hex, config_path=None, bitcoind_opts=None, bitcoind_client=None):
    """
    Get the tx fee for a tx
    Return the fee on success
    Return None on error
    """
    tx_fee_per_byte = get_tx_fee_per_byte(config_path=config_path, bitcoind_opts=bitcoind_opts, bitcoind_client=bitcoind_client)
    if tx_fee_per_byte is None:
        return None

    return calculate_tx_fee(tx_hex, tx_fee_per_byte)


def tx_estimate_signature_len(privkey_info):
    """
    Estimate how long a signature is going to be, given a private key.
    privkey_info is a private key or a multisig/segwit bundle.

    This accounts for both the scriptsig and witness data.  The return
    value is the number of actual *bytes* (not vbytes) that the signature
    will count for in bitcoin (i.e. witness bytes are discounted)
    
    Return the number of bytes on success
    Raise ValueError of the key is not recognized
    """
    if btc_is_singlesig(privkey_info):
        # one signature produces a scriptsig of ~71 bytes (signature) + pubkey + encoding (4)
        log.debug("Single private key makes a ~73 byte signature")
        pubkey = ecdsa_private_key(privkey_info).public_key().to_hex().decode('hex')
        return 71 + len(pubkey) + 4

    elif btc_is_multisig(privkey_info):
        # one signature produces a scriptsig of redeem_script + (num_pubkeys * ~74 bytes) + encoding (~6)
        m, _ = parse_multisig_redeemscript( privkey_info['redeem_script'] )
        siglengths = 74 * m
        scriptlen = len(privkey_info['redeem_script']) / 2
        siglen = 6 + scriptlen + siglengths

        log.debug("Multisig private key makes ~{} byte signature".format(siglen))
        return siglen

    elif btc_is_singlesig_segwit(privkey_info):
        # bitcoin p2sh-p2wpkh script
        # one signature produces (pubkey + signature (~74 bytes)) + scriptsig len
        privkey = privkey_info['private_keys'][0]
        pubkey_hex = keylib.key_formatting.compress(ecdsa_private_key(privkey).public_key().to_hex())
        redeem_script = btc_make_p2sh_p2wpkh_redeem_script(pubkey_hex)
        witness_script = btc_witness_script_serialize(['00' * 74, pubkey_hex])

        scriptsig_len = 6 + len(redeem_script) / 2
        witness_len = len(witness_script) / 2
        siglen = int(round(float(3 * scriptsig_len + (scriptsig_len + witness_len)) / 4))
        
        log.debug("Segwit p2sh-p2wpkh private key makes ~{} byte signature".format(siglen))
        return siglen

    elif btc_is_multisig_segwit(privkey_info):
        # bitcoin p2sh-p2wsh script
        # one signature produces (witness script len + num_pubkeys * ~74) + scriptsig len 
        witness_script = privkey_info['redeem_script']
        m, _ = parse_multisig_redeemscript(witness_script)    
        redeem_script = btc_make_p2sh_p2wsh_redeem_script(witness_script)
        
        siglengths = 74 * m
        scriptsig_len = 6 + len(redeem_script) / 2
        witness_len = len(witness_script) / 2 + siglengths
        siglen = int(round(float(3 * scriptsig_len + (scriptsig_len + witness_len)) / 4))

        log.debug("Segwit p2sh-p2wsh private keys make ~{} byte signature".format(siglen))
        return siglen

    raise ValueError("Unrecognized private key foramt")

