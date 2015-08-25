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


import argparse
import logging
import os
import os.path
import sys
import subprocess
import signal
import json
import datetime
import traceback
import httplib
import ssl
import threading
import time
import socket
import binascii
import pybitcoin

from collections import defaultdict 

import config
import workpool
from .blockchain import transactions, session 
from multiprocessing import Pool
from ..impl_ref import reference            # default no-op state engine implementation

from utilitybelt import is_hex

log = session.log

class StateEngine( object ):
    """
    Client to the virtual chain's database of operations, constructed and  
    kept synchronized with records in the underlying blockchain.  If the blockchain 
    is the ledger of all operations to have ever been committed 
    (including invalid and fraudulent ones), then the virtual chain is the subsequence 
    of operations that we're interested in, and the state engine is the logic
    for finding and processing the subsequence of these that are "valid."
    
    The purpose of the state engine is to process records from the blockchain in order 
    to carry out its application's core business logic.  This usually means building up a 
    database over the set of virtual chain records.  Virtual chain data are 
    encoded in transactions data within the underlying cryptocurrency (i.e. OP_RETURNs in Bitcoin).
    Each block in the blockchain must be fed into the database, and the blocks' 
    operations extracted, validated, and accounted for.  As such, at block N,
    the state engine would have a database represents the current state of names and storage at block N.
    
    Because the underlying cryptocurrency blockchain can fork, state engine peers need to 
    determine that they are on the same fork so they will know which virtual chain operations 
    to process.  To do so, the state engine calculates a Merkle tree over its 
    current state (i.e. the set of names) at the current block, and encodes the root
    hash in each operation.  Then, one peer can tell that the other peer's operations
    were calculated on the same blockchain fork simply by ensuring that the operation had
    the right Merkle root hash for that block.  These Merkle root hashes are called
    "consensus hashes."
    
    Processing a block happens in five stages: "parse", "check", "log", "commit", and "snapshot"
    * "Parsing" a block transaction's nulldata (i.e. from an OP_RETURN) means translating 
    the OP_RETURN data into a virtual chain operation.
    * "Checking" an operation means ensuring the operation is valid.
    * "Logging" an operation means staging an operation to be fed into the state engine.
    * "Committing" an operation means feeding it into the state engine.
    * "Snapshotting" means calculating the consensus hash of the state engine, at block N.
    
    Blocks are processed in order.
    """
    
    RESERVED_KEYS = [
       'virtualchain_opcode',
       'virtualchain_outputs',
       'virtualchain_senders',
       'virtualchain_fee',
       'virtualchain_block_number'
    ]
    
    def __init__(self, magic_bytes, opcodes, impl=None, state=None, op_order=None ):
        """
        Construct a state engine client, optionally from locally-cached 
        state and the set of previously-calculated consensus 
        hashes for each block.
        
        This class will be fed a sequence of sets of transactions, grouped by block 
        and ordered by block ID, that each contain an OP_RETURN.  The nulldata 
        assocated with the OP_RETURN will be parsed, checked, logged, and 
        committed by the implementation (impl).  The implementation decides exactly 
        what each of these mean; this class simply feeds it the transactions
        in order.
        
        This class looks for OP_RETURN data that starts with the byte sequence in magic_bytes,
        and then only select those which start with magic_bytes + op, where op is an 
        opcode byte in opcodes.  Magic bytes can be of variable length, but it should
        be specific to this virtual chain.
        
        Expected OP_RETURN data format:
        
         0     M  M+1                      40-M-1
         |-----|--|------------------------|
          magic op payload
        
        
        The caller may supply an optional argument called 'state', which will be 
        passed into each implementation method.  It is meant to preserve implementation-
        specific state--in particular, whatever state the implementation expects to be 
        present.
        
        The caller may also specify the order in which each type of operation is 
        processed, by passing a list of opcodes in op_order.
        """
        
        self.consensus_hashes = {}
        self.pending_ops = defaultdict(list)
        self.magic_bytes = magic_bytes 
        self.opcodes = opcodes
        self.state = state
        self.op_order = op_order
        self.impl = impl
        self.lastblock = self.impl.get_first_block_id()
        
        consensus_snapshots_filename = config.get_snapshots_filename()
        lastblock_filename = config.get_lastblock_filename()
        
        # if we crashed during a commit, try to finish
        rc = self.commit()
        if not rc:
           log.error("Failed to commit partial data.  Rolling back.")
           self.rollback()
        
        # attempt to load the snapshots 
        if os.path.exists( consensus_snapshots_filename ):
           try:
              
              with open(consensus_snapshots_filename, 'r') as f:
                 
                 db_dict = json.loads(f.read())
                 
                 if 'snapshots' in db_dict:
                     self.consensus_hashes = db_dict['snapshots']
                 
           except Exception, e:
              log.error("Failed to read consensus snapshots at '%s'" % consensus_snapshots_filename )
              raise e
             
        # what was the last block processed?
        if os.path.exists( lastblock_filename ):
           try:
              with open(lastblock_filename, 'r') as f:
                 lastblock_str = f.read()
                 self.lastblock = int(lastblock_str)
              
           except Exception, e:
              log.error("Failed to read last block number at '%s'" % lastblock_filename )
              raise e
          
          
    def rollback( self ):
        """
        Roll back a pending write: blow away temporary files.
        """
        
        tmp_db_filename = config.get_db_filename() + ".tmp"
        tmp_snapshot_filename = config.get_snapshots_filename() + ".tmp"
        tmp_lastblock_filename = config.get_lastblock_filename() + ".tmp"
        
        for f in [tmp_db_filename, tmp_snapshot_filename, tmp_lastblock_filename]:
            if os.path.exists( f ):
                
                try:
                    os.unlink( f )
                except:
                    log.error("Failed to unlink '%s'" % f )
                    pass
    
    
    def commit( self ):
        """
        Move all written but uncommitted data into place.
        Return True on success 
        Return False on error (in which case the caller should rollback())
        
        It is safe to call this method repeatedly until it returns True.
        """
        tmp_db_filename = config.get_db_filename() + ".tmp"
        tmp_snapshot_filename = config.get_snapshots_filename() + ".tmp"
        tmp_lastblock_filename = config.get_lastblock_filename() + ".tmp"
        
        if not os.path.exists( tmp_lastblock_filename ) and (os.path.exists(tmp_db_filename) or os.path.exists(tmp_snapshot_filename)):
            # we did not successfully stage the write.
            # rollback 
            log.error("Partial write detected.  Not committing.")
            return False
            
        
        for tmp_filename, filename in zip( [tmp_lastblock_filename, tmp_snapshot_filename, tmp_db_filename], \
                                           [config.get_lastblock_filename(), config.get_snapshots_filename(), config.get_db_filename()] ):
               
            if not os.path.exists( tmp_filename ):
                continue 
            
            # commit our new lastblock, consensus hash set, and state engine data
            try:
               
               # NOTE: rename fails on Windows if the destination exists 
               if sys.platform == 'win32' and os.path.exists( filename ):
                  
                  try:
                     os.unlink( filename )
                  except:
                     pass
               
               os.rename( tmp_filename, filename )
                  
            except Exception, e:
               
               log.exception(e)
               return False 
           
        return True
        
    
    def save( self, block_id ):
        """
        Write out all state to the working directory.
        Calls the implementation's 'db_save' method.
        
        Return True on success 
        Return False on error
        Raise exception if block_id represents a block 
         we've already processed.
        """
        
        if block_id < self.lastblock:
           raise Exception("Already processed up to block %s (got %s)" % (self.lastblock, block_id))
        
        # stage data to temporary files
        tmp_db_filename = config.get_db_filename() + ".tmp"
        tmp_snapshot_filename = config.get_snapshots_filename() + ".tmp"
        tmp_lastblock_filename = config.get_lastblock_filename() + ".tmp"
        
        with open(tmp_snapshot_filename, 'w') as f:
            db_dict = {
               'snapshots': self.consensus_hashes
            }
            f.write(json.dumps(db_dict))
            f.flush()
        
        # put this last...
        with open(tmp_lastblock_filename, "w") as lastblock_f:
            lastblock_f.write("%s" % block_id)
            lastblock_f.flush()
        
        
        rc = self.impl.db_save( block_id, tmp_db_filename, db_state=self.state )
        if not rc:
           # failed to save 
           log.error("Implementation failed to save at block %s to %s" % (block_id, tmp_db_filename))
           
           try:
               os.unlink( tmp_lastblock_filename )
           except:
               pass 
           
           try:
               os.unlink( tmp_snapshot_filename )
           except:
               pass 
           
           return False
        
        rc = self.commit()
        if not rc:
            log.error("Failed to commit data at block %s.  Rolling back." % block_id )
            
            self.rollback()
            return False 
        
        else:
            self.lastblock = block_id
            return True
    
    
    def calculate_consensus_hash( self, merkle_root ):
      """
      Given the Merkle root of the set of records processed, calculate the consensus hash.
      """
      return binascii.hexlify( pybitcoin.hash.bin_hash160(merkle_root, True)[0:16])
 
    
    def snapshot( self, block_id ):
      """
      Take the consensus hash of the current state at the current block.
      Pass in an iterable (i.e. a list, or something that can stream data off of disk)
      that can be used to generate the *ordered* list of records that make up the state.
      """
      
      hashes = []
      for serialized_record in self.impl.db_iterable( block_id, db_state=self.state ):
         
         record_hash = binascii.hexlify( pybitcoin.hash.bin_double_sha256( serialized_record ) )
         hashes.append( record_hash )
      
      if len(hashes) == 0:
         
         hashes.append( binascii.hexlify( pybitcoin.hash.bin_double_sha256( "" ) ) )
         
      merkle_tree = pybitcoin.MerkleTree( hashes )
      root_hash = merkle_tree.root()
      
      consensus_hash = self.calculate_consensus_hash( root_hash )
      self.consensus_hashes[ str(block_id) ] = consensus_hash 
      
      return consensus_hash
   
   
    def force_opcode( self, op, opcode ):
      """
      Set an op's opcode, so virtualchain will accept it as such.
      """
      op['virtualchain_opcode'] = opcode
       
   
    def parse_transaction( self, block_id, tx ):
      """
      Given a block ID and an OP_RETURN transaction, 
      try to parse it into a virtual chain operation.
      
      Use the implementation's 'db_parse' method to do so.
      
      Set the following fields in op:
      * virtualchain_opcode:   the operation code 
      * virtualchain_outputs:  the list of transaction outputs
      * virtualchain_senders:  the list of transaction senders 
      * virtualchain_fee:      the total amount of money sent
      * virtualchain_block_number:  the block ID in which this transaction occurred
      
      Return a dict representing the data on success.
      Return None on error
      """
      
      op_return_hex = tx['nulldata']
      outputs = tx['vout']
      senders = tx['senders']
      fee = tx['fee']
      
      if not is_hex(op_return_hex):
          # not a valid hex string 
          return None
      
      if len(op_return_hex) % 2 != 0:
          # not valid hex string 
          return None
      
      try:
          op_return_bin = binascii.unhexlify( op_return_hex )
      except Exception, e:
          log.error("Failed to parse transaction: %s (OP_RETURN = %s)" % (tx, op_return_hex))
          raise e
      
      if not op_return_bin.startswith( self.magic_bytes ):
         return None
      
      op_code = op_return_bin[ len(self.magic_bytes) ]
      
      if op_code not in self.opcodes:
         return None 
      
      # looks like a valid op.  Try to parse it.
      op_payload = op_return_bin[ len(self.magic_bytes)+1: ]
      
      op = self.impl.db_parse( block_id, op_code, op_payload, senders, outputs, fee, db_state=self.state )
      
      if op is None:
         # not valid 
         return None 
      
      # store it
      op['virtualchain_opcode'] = op_code
      op['virtualchain_outputs'] = outputs 
      op['virtualchain_senders'] = senders 
      op['virtualchain_fee'] = fee
      op['virtualchain_block_number'] = block_id
      
      return op
   
   
    def parse_block( self, block_id, txs ):
      """
      Given the sequence of transactions in a block, turn them into a
      sequence of virtual chain operations.
      """
      
      ops = []
      
      for i in xrange(0,len(txs)):
         
         tx = txs[i]
         
         op = self.parse_transaction( block_id, tx )
         
         if op is not None:
            ops.append( op )
            
      return ops
   
   
    def remove_reserved_keys( self, op ):
       """
       Remove reserved keywords from an op dict,
       which can then safely be passed into the db.
       
       Returns a new op dict, and the reserved fields
       """
       sanitized = {}
       reserved = {}
       
       for k in op.keys():
          if k not in self.RESERVED_KEYS:
             sanitized[k] = op[k]
          else:
             reserved[k] = op[k]
             
       return sanitized, reserved
          
    
    def log_pending_ops( self, block_id, ops ):
       """
       Given a sequence of parsed operations, stage them 
       in preparation for adding them to the state engine.
       This calls the 'db_check' operation in the implementation,
       to verify whether or not the operation should be 
       staged or not.
       
       Return a dict of a sequence of pending ops, grouped by opcode,
       and ordered simply by the order in which they appeared in ops.
       """
       
       pending_ops = defaultdict(list)
       
       for op in ops:
          
          op_sanitized, reserved = self.remove_reserved_keys( op )
          
          rc = self.impl.db_check( block_id, pending_ops, op['virtualchain_opcode'], op_sanitized, db_state=self.state )
          if rc:
            # good to go 
            op_sanitized.update( reserved )
            pending_ops[ op_sanitized['virtualchain_opcode'] ].append( op_sanitized )
          
       return pending_ops
    

    def commit_pending_ops( self, block_id, pending_ops ):
       """
       Given the logged set of pending operations for this block,
       merge them into the implementation's state.
       
       This method calls the implementation's 'db_commit' method to 
       add parsed and checked opcodes.
       """
       
       op_order = self.op_order
       if op_order is None:
          op_order = pending_ops.keys()
       
       for opcode in op_order:
          
          op_list = pending_ops[ opcode ]
          for op in op_list:
             
             op_sanitized, op_reserved = self.remove_reserved_keys( op )
             
             self.impl.db_commit( block_id, opcode, op_sanitized, db_state=self.state )
       
    
    def process_block( self, block_id, txs ):
       """
       Top-level block processing method.
       Feed the block and its OP_RETURN transactions 
       through the implementation, to build up the 
       implementation's state.  Cache the 
       resulting data to disk.
       
       Return the consensus hash for this block.
       Return None on error
       """
       
       ops = self.parse_block( block_id, txs )
       pending_ops = self.log_pending_ops( block_id, ops )
       self.commit_pending_ops( block_id, pending_ops )
       
       consensus_hash = self.snapshot( block_id )
       
       rc = self.save( block_id )
       if not rc:
          log.error("Failed to save (%s, %s): rc = %s" % (block_id, consensus_hash, rc))
          return None 
       
       return consensus_hash


    def build( self, bitcoind_opts, end_block_id ):
       """
       Top-level call to process all blocks in the blockchain.
       Goes and fetches all OP_RETURN nulldata in order,
       and feeds them into the state engine implementation using its
       'db_parse', 'db_check', 'db_commit', and 'db_save'
       methods.
       
       Note that this method can take some time (hours) to complete 
       when called from the first block.
       
       Return True on success 
       Return False on error
       Raise an exception on irrecoverable error--the caller should simply try again.
       """
       
       first_block_id = self.lastblock 
       num_workers, worker_batch_size = config.configure_multiprocessing( bitcoind_opts )
    
       rc = True
       pool = Pool( processes=num_workers )
       
       try:
          
          for block_id in xrange( first_block_id, end_block_id, worker_batch_size * num_workers ):
              
              if not rc:
                  break 
              
              block_ids = range( block_id, min(block_id + worker_batch_size * num_workers, end_block_id) )
                
              # returns: [(block_id, txs)]
              block_ids_and_txs = transactions.get_nulldata_txs_in_blocks( pool, bitcoind_opts, block_ids )
                
              # process in order by block ID
              block_ids_and_txs.sort()
                
              log.info("CONSENSUS(%s): %s" % (first_block_id-1, self.get_consensus_at( first_block_id-1 )) )
                    
              for processed_block_id, txs in block_ids_and_txs:
                    
                  consensus_hash = self.process_block( processed_block_id, txs )
                    
                  log.info("CONSENSUS(%s): %s" % (processed_block_id, self.get_consensus_at( processed_block_id )) )
                    
                  if consensus_hash is None:
                        
                      # fatal error 
                      rc = False
                      log.error("Failed to process block %d" % processed_block_id )
                      break
       
       except:
           pool.close()
           pool.join()
           raise
       
       pool.close()
       pool.join()
       return rc
       
       
    def get_consensus_at( self, block_id ):
       """
       Get the consensus hash at a given block
       """
       return self.consensus_hashes.get( str(block_id), None )
    
    
    def get_current_consensus(self):
       """
       Get the current consensus hash.
       """
       return self.get_consensus_at( str(self.lastblock) )
    
    
    def is_consensus_hash_valid( self, block_id, consensus_hash ):
       """
       Given a block ID and a consensus hash, is 
       the hash still considered to be valid?
       We allow a grace period for which a consensus hash 
       is valid, since a writer might submit a 
       "recently stale" consensus hash under 
       heavy write load.
       """
       
       # search current and previous blocks
       first_block_to_check = block_id - config.BLOCKS_CONSENSUS_HASH_IS_VALID
       for block_number in xrange(first_block_to_check, block_id):
          
         block_number_key = str(block_number)
         
         if block_number_key not in self.consensus_hashes.keys():
            continue
         
         if str(consensus_hash) == str(self.consensus_hashes[block_number_key]):
            return True
         
       return False
      

def get_index_range( bitcoind ):
    """
    Get the range of block numbers that we need to fetch from the blockchain.
    
    Return None if we fail to connect to bitcoind.
    """

    start_block = config.get_first_block_id()
       
    try:
       current_block = int(bitcoind.getblockcount())
        
    except Exception, e:
       # TODO: reconnect on connection error
       log.exception(e)
       return None, None

    # check our last known file
    lastblock_file = config.get_lastblock_filename()
    
    saved_block = 0
    if os.path.isfile(lastblock_file):
         
        with open(lastblock_file, 'r') as fin:
           try:
              saved_block = fin.read()
              saved_block = int(saved_block)
           except:
              saved_block = 0
              try:
                 os.unlink(lastblock_file)
              except OSError, oe:
                 pass 
              
              pass 

    if saved_block == 0:
        pass
    elif saved_block == current_block:
        start_block = saved_block
    elif saved_block < current_block:
        start_block = saved_block + 1

    return start_block, current_block
    
    
