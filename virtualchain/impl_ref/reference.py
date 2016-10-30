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


# example plugin to a virtual chain that defines its behavior.

def get_virtual_chain_name():
   """
   Get the name of the virtual chain we're building.
   """
   print "\nreference implementation of get_virtual_chain_name\n"
   return "virtualchain-test"


def get_virtual_chain_version():
   """
   Get the version string for this virtual chain.
   """
   print "\nreference implementation of get_virtual_chain_version\n"
   return "v0.01-beta"


def get_first_block_id():
   """
   Get the id of the first block to start indexing.
   """ 
   print "\nreference implementation of get_first_block_id\n"
   return 50000


def get_db_state():
   """
   Return an opaque 'state' object that will be preserved across calls
   to the blockchain indexing callbacks.
   """
   print "\nreference implementation of get_db_state\n"
   return None 


def get_opcodes():
   """
   Return the set of opcodes we're looking for.
   """
   print "\nreference implementation of get_opcodes\n"
   return ["a", "b", "c", "d", "e"]


def get_magic_bytes():
   """
   Return the magic byte sequence we're scanning OP_RETURNs for.
   """
   print "\nreference implementation of get_magic_bytes\n"
   return "vv"

def get_op_processing_order():
   """
   Return a sequence of opcodes as a hint to the order in which 
   the indexer should process opcodes.
   """
   print "\nreference implementation of get_op_processing_order\n"
   return None 


def db_parse( block_id, opcode, op_payload, senders, inputs, outputs, fee, db_state=None ):
   """
   Given the block ID, and information from what looks like 
   an OP_RETURN transaction that is part of the virtual chain, parse the 
   transaction's OP_RETURN nulldata into a dict.
   
   Return the dict if this is a valid op.
   Return None if not.
   
   NOTE: the virtual chain indexer reserves all keys that start with 'virtualchain_'
   """
   print "\nreference implementation of db_parse\n"
   return None


def db_scan_block( block_id, op_list, db_state=None ):
   """
   Given the block ID and a tx-ordered list of operations, do any
   block-level initial preprocessing.  This method does not 
   affect the operations (the op_list will be discarded), nor 
   does it return anything.  It is only meant to give the state
   engine implementation information on what is to come in the
   sequence of db_check() calls.
   """
   print "\nreference implementation of db_check_block\n"
   return 


def db_check( block_id, opcode, op, txid, vtxindex, checked, db_state=None ):
   """
   Given the block ID and a parsed operation, check to see if this is a *valid* operation
   for the purposes of this virtual chain's database.
   
   Return True if so; False if not.
   """
   print "\nreference implementation of db_check\n"
   return False
   
   
def db_commit( block_id, opcode, op, txid, vtxindex, db_state=None ):
   """
   Given a block ID and checked opcode, record it as 
   part of the database.  This does *not* need to write 
   the data to persistent storage, since save() will be 
   called once per block processed.

   This method must return either the updated op with the 
   data to pass on to db_serialize, or False if the op
   is to be rejected.
   """
   print "\nreference implementation of db_commit\n"
   return False


def db_save( block_id, filename, db_state=None ):
   """
   Save all persistent state to stable storage.
   
   Return True on success
   Return False on failure.
   """
   print "\nreference implementation of db_save\n"
   return True


def db_continue( block_id, consensus_hash ):
   """
   Signal to the implementation that all state for this block
   has been saved, and that this is now the new consensus hash.

   Return value indicates whether or not we should continue indexing.
   """
   print "\nreference implementation of db_continue\n"
   return True
