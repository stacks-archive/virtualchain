#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Virtualchain
    ~~~~~
    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org
    
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

import sys 
import pybitcoin

def get_nulldata(tx):
    if not ('vout' in tx):
        return None
    
    outputs = tx['vout']
    
    # go through all the outputs
    for output in outputs:
        
        # make sure the output is valid
        if not ('scriptPubKey' in output):
            continue
        
        # grab the script pubkey
        script_pubkey = output['scriptPubKey']
        
        # get the script parts and script type
        script_parts = str(script_pubkey['asm']).split(' ')
        script_type = str(script_pubkey['type'])
        
        # get the nulldata from the OP_RETURN
        if script_type == 'nulldata' and len(script_parts) == 2:
            
            # make *sure* this is hex (since small OP_RETURNs get turned 
            # into numbers, by virtue of the fact that they look like varints).
            raw_opcode = script_pubkey['hex'][:2]
            
            hex_str = script_parts[1]
            if hex_str != script_pubkey['hex'][4:] and ("0x" + str(raw_opcode) == hex(pybitcoin.transactions.opcodes.OP_RETURN)):
                
                # get the raw hex, and remove the leading OP_RETURN code and length op
                hex_str = script_pubkey['hex'][4:]
                
            return hex_str
        
    return None


def has_nulldata(tx):
    return (get_nulldata(tx) is not None)
