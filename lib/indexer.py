#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    virtualchain
    ~~~~~
    :copyright: (c) 2015 by Openname.org
    :license: MIT, see LICENSE for more details.
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
from utilitybelt import is_valid_int
import pybitcoin
from ConfigParser import SafeConfigParser

import config
import workpool
import blockchain.transactions as transactions
import blockchain.session as session
from multiprocessing import Pool

log = session.log

class VirtualChainDB:
    """
    Client to the virtual chain's database of operations, constructed and  
    kept synchronized with records in the underlying blockchain.  If the blockchain 
    is the ledger of all operations to have ever been committed 
    (including invalid and fraudulent ones), then this databse represents the 
    current state defined by applying all *valid* operations.
    
    Constructing the database is an iterative process.  Virtual chain data are 
    encoded in transactions data within the underlying cryptocurrency (i.e. OP_RETURNs in Bitcoin).
    Each block in the blockchain must be fed into the database, and the blocks' 
    operations extracted, validated, and accounted for.  As such, at block N,
    the virtual chain database represents the current state of names and storage at block N.
    
    Because the underlying cryptocurrency blockchain can fork, virual chain peers need to 
    determine that they are on the smae fork so they will know which virtual chain operations 
    to process.  To do so, the virtual chain database calculates a Merkle tree over its 
    current state (i.e. the set of names) at the current block, and encodes the root
    hash in each operation.  Then, one peer can tell that the other peer's operations
    were calculated on the same blockchain fork simply by ensuring that the operation had
    the right Merkle root hash for that block.  These Merkle root hashes are called
    "consensus hashes."
    
    Processing a block happens in five stages: "parse", "check", "log", "commit", and "snapshot"
    * "Parsing" a block transaction's nulldata (i.e. from an OP_RETURN) means translating 
    the OP_RETURN data into a virtual chain operation.  Relevant methods are in ..parsing.
    * "Checking" an operation means ensuring the operation is consistent with the state of the 
    database constructed thus far.  Relevant methods are in .check.
    * "Logging" an operation means staging an operation to be included in the database,
    at the point of processing block N.  Relevant methods are in .log.
    * "Committing" an operation means adding a logged operation to the current state of the 
    database.
    * "Snapshotting" means calculating the consensus hash of the database at block N.
    """
    
    def __init__(self, magic_bytes, opcodes, state=None, op_order=None ):
        """
        Construct a database client, optionally from locally-cached 
        database state and the set of previously-calculated consensus 
        hashes for each block.
        
        This class will be fed a sequence of sets of transactions, grouped by block 
        and ordered by block ID, that each contain an OP_RETURN.  The nulldata 
        assocated with the OP_RETURN will be parsed, checked, logged, and 
        committed by the implementation.  The implementation decides exactly 
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
        present in the database.
        
        The caller may also specify the order in which each type of operation is 
        processed, by passing a list of opcodes in op_order.
        """
        
        self.consensus_hashes = {}
        self.pending_ops = defaultdict(list)
        self.magic_bytes = magic_bytes 
        self.opcodes = opcodes
        self.state = state
        self.op_order = op_order
        self.lastblock = impl.get_first_block_id()
        
        consensus_snapshots_filename = config.get_snapshots_filename()
        lastblock_filename = config.get_lastblock_filename()
        
        # attempt to load the snapshots 
        if os.path.exists( consensus_snapshots_filename ):
           try:
              with open(consensus_snapshots_filename, 'r') as f:
                 db_dict = json.loads(f.read())
              if 'snapshots' in db_dict:
                 self.consensus_hashes = db_dict['snapshots']
           except Exception, e:
              pass
             
        # what was the last block processed?
        if os.path.exists( lastblock_filename ):
           try:
              with open(lastblock_filename, 'r') as f:
                 lastblock_str = f.read()
                 self.lastblock = int(lastblock_str)
              
           except Exception, e:
              pass 
        
             
    def save_snapshots(self, filename):
        """
        Save the set of consensus hashes to disk, so 
        we don't have to go built them up again from 
        the blockchain.
        
        Return True on success, False if not
        """
        tmp_filename = filename + ".tmp"
        try:
           with open(tmp_filename, 'w') as f:
               db_dict = {
                  'snapshots': self.consensus_hashes
               }
               f.write(json.dumps(db_dict))
               
        except Exception, e:
           traceback.print_exc()
           return False
         
         
        try:
           os.rename( tmp_filename, filename )
        except Exception, e:
           traceback.print_exc()
           try:
              os.unlink( tmp_filename )
           except:
              pass 
           
        return True
    
    
    def save(self, block_id):
        """
        Write out all state to the working directory.
        Calls the implementation's 'db_save' method.
        
        Return True on success 
        Return False on error
        """
        
        tmp_db_filename = config.get_db_filename() + ".tmp"
        tmp_snapshot_filename = config.get_snapshots_filename() + ".tmp"
        tmp_lastblock_filename = config.get_lastblock_filename() + ".tmp"
        
        with open(tmp_snapshot_filename, 'w') as f:
            db_dict = {
               'snapshots': self.consensus_hashes
            }
            f.write(json.dumps(db_dict))
         
        with open(tmp_lastblock_filename, "w") as lastblock_f:
            lastblock_f.write("%s" % block_id)
         
        rc = impl.db_save( tmp_db_filename )
        if not rc:
           # failed to save 
           os.unlink( tmp_lastblock_filename )
           os.unlink( tmp_snapshot_filename )
           return False
        
        for tmp_filename, filename in zip( [tmp_lastblock_filename, tmp_snapshot_filename, tmp_db_filename], \
                                           [config.get_lastblock_filename(), config.get_snapshots_filename(), config.get_lastblock_filename()] ):
               
            # commit our new lastblock, consensus hash set, and database
            try:
               # NOTE: rename fails on Windows if the destination exists 
               if sys.platform == 'win32':
                  os.unlink( filename )
                  
               os.rename( tmp_filename, filename )
            except:
               os.unlink( tmp_lastblock_filename )
               os.unlink( tmp_snapshot_filename )
               os.unlink( tmp_db_filename )
               return False 
      
        # clean up 
        os.unlink( tmp_lastblock_filename )
        os.unlink( tmp_snapshot_filename )
        return True
     
    
    def calculate_consensus_hash( merkle_root ):
      """
      Given the Merkle root of the database, calculate the consensus hash.
      """
      return binascii.hexlify( pybitcoin.hash.bin_hash160(merkle_root, True)[0:16])
 
    
    def snapshot( self, block_id ):
      """
      Take the consensus hash of the current state at the current block.
      Pass in an iterable (i.e. a list, or something that can stream data off of disk)
      that can be used to generate the *ordered* list of records that make up the state.
      """
      
      hashes = []
      for serialized_record in impl.db_iterable():
         
         record_hash = binascii.hexlify( pybitcoin.hash.bin_double_sha256( serialized_record ) )
         hashes.append( record_hash )
      
      if len(hashes) == 0:
         
         hashes.append( binascii.hexlify( pybitcoin.hash.bin_double_sha256( "" ) ) )
         
      merkle_tree = pybitcoin.MerkleTree( hashes )
      root_hash = merkle_tree.root()
      
      consensus_hash = self.calculate_consensus_hash( root_hash )
      self.consensus_hashes[ block_id ] = consensus_hash 
      
      return consensus_hash128 
   
   
    def parse_transaction( self, block_id, tx ):
      """
      Given a block ID and an OP_RETURN transaction, 
      try to parse it into a virtual chain operation.
      
      Use the implementation's 'db_parse' method to do so.
      
      Return a dict representing the data on success.
      Return None on error
      """
      
      op_return_hex = tx['nulldata']
      outputs = tx['vout']
      senders = tx['senders']
      fee = tx['fee']
      
      op_return_bin = unhexlify( op_return_hex )
      
      if not op_return_bin.startswith( self.magic_bytes ):
         return None
      
      op_code = op_return_bin[ len(self.magic_bytes) ]
      
      if op_code not in self.opcodes:
         return None 
      
      # looks like a valid op.  Try to parse it.
      op_payload = op_return_bin[ len(self.magic_bytes)+1: ]
      
      op = impl.db_parse( block_id, op_payload, outputs, senders, fee, state=self.state )
      
      if op is None:
         # not valid 
         return None 
      
      # store it
      op['virtualchain_opcode'] = op_code
      op['virtualchain_outputs'] = outputs 
      op['virtualchain_senders'] = senders 
      op['virtualchain_fee'] = fee
      
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
    
    
    def log_pending_ops( self, block_id, ops ):
       """
       Given a sequence of parsed operations, stage them 
       in preparation for adding them to the database.
       This calls the 'db_check' operation in the implementation,
       to verify whether or not the operation should be 
       staged or not.
       
       Return a dict of a sequence of pending ops, grouped by opcode,
       and ordered simply by the order in which they appeared in ops.
       """
       
       pending_ops = defaultdict(list)
       
       for op in ops:
          rc = impl.db_check( block_id, pending_ops, op['virtualchain_opcode'], op, state=self.state )
          if rc:
            # good to go 
            pending_ops[ op['virtualchain_opcode'] ].append( op )
          

    def commit_pending_ops( self, block_id, pending_ops ):
       """
       Given the logged set of pending operations for this block,
       merge them into the database.
       
       This method calls the implementation's 'db_commit' method to 
       add parsed and checked opcodes to the database.
       """
       
       op_order = self.op_order
       if op_order is None:
          op_order = pending_ops.keys()
       
       for opcode in op_order:
          
          op_list = pending_ops[ opcode ]
          for op in op_list:
             
             impl.db_commit( block_id, opcode, op, state=self.state )
       
    
    def process_block( self, block_id, txs ):
       """
       Top-level block processing method.
       Feed the block and its OP_RETURN transactions 
       through the implementation, to build up the 
       implementation's database state.  Cache the 
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
          return None 
       
       return consensus_hash


    def build( self, bitcoind_opts, end_block_id ):
       """
       Top-level call to process all blocks in the blockchain.
       Goes and fetches all OP_RETURN nulldata in order,
       and constructs the database from them, using the 
       'parse', 'check', 'commit', and periodically the 'save'
       implementation methods.
       
       AFter each batch is fetched, the database 
       will save its work with the implementation's 'save' method.
       This is to allow the daemon to pick up where it left off,
       should it be interrupted in processing a lot of blocks.
       
       Note that this method can take some time (hours) to complete 
       when called from the first block.
       
       Return True on success 
       Return False on error
       """
       
       first_block_id = self.lastblock 
       num_workers, worker_batch_size = config.configure_multiprocessing( bitcoind_opts )

       pool = Pool( processes=num_workers )
       
       for block_id in xrange( first_block_id, end_block_id, worker_batch_size ):
          
          block_ids = range( first_block_id, first_block_id + worker_batch_size )
          
          # returns: [(block_id, txs)]
          block_ids_and_txs = transactions.get_nulldata_txs_in_blocks( workpool, bitcoind_opts, block_ids )
          
          for block_id, txs in block_ids_and_txs:
             
             consensus_hash = self.process_block( block_id, txs )
             if consensus_hash is None:
                
                # fatal error 
                log.error("Failed to process block %d" % block_id )
                return False 
       
          # checkpoint ourselves...
          self.save( block_ids[-1] )
          
       pool.close()
       pool.join()
       return True
       
      

def get_index_range( bitcoind ):
    """
    Get the range of block numbers that we need to fetch from the blockchain.
    
    Return None if we fail to connect to bitcoind.
    """

    start_block = config.get_first_block_id()
       
    try:
       current_block = int(bitcoind.getblockcount())
        
    except Exception, e:
       return None

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
   