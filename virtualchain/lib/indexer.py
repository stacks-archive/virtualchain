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


import argparse
import logging
import os
import os.path
import sys
import subprocess
import signal
import json
import datetime
import httplib
import ssl
import threading
import time
import socket
import binascii
import pybitcoin
import copy
import shutil
import time
import traceback
import cPickle as pickle
import imp
import simplejson

from collections import defaultdict 

import config
import blockchain.transactions as transactions
import blockchain.session as session

from utilitybelt import is_hex

log = session.get_logger("virtualchain")
 
RESERVED_KEYS = [
   'virtualchain_opcode',
   'virtualchain_outputs',
   'virtualchain_senders',
   'virtualchain_fee',
   'virtualchain_block_number',
   'virtualchain_accepted',
   'virtualchain_txid',
   'virtualchain_txindex'
]

class StateEngine( object ):
    """
    Client to the virtual chain's database of operations, constructed and  
    kept synchronized with records in the underlying blockchain.  If the blockchain 
    is the ledger of all operations to have ever been committed 
    (including invalid and fraudulent ones), then the virtual chain is the sequence 
    of operations that we're interested in, and the state engine is the logic
    for finding and processing the subsequence of these that are "valid."
    
    The purpose of the state engine is to process records from the blockchain in order 
    to carry out its application's core business logic.  This usually means building up a 
    database over the set of virtual chain records.  Virtual chain data are 
    encoded in transactions data within the underlying cryptocurrency (i.e. OP_RETURNs in Bitcoin).
    Each block in the blockchain must be fed into the database, and the blocks' 
    operations extracted, validated, and accounted for.  As such, at block N,
    the state engine would have a database represents its current state at block N.
    
    Because the underlying cryptocurrency blockchain can fork, state engine peers need to 
    determine that they are on the same fork so they will know which virtual chain operations 
    to process.  To do so, the state engine calculates a Merkle tree over the operations processed 
    from the current block, as well as the root of the previous such tree for the previous block,
    and encodes the root hash in each operation.  Then, one peer can tell that the other peer's operations
    were calculated on the same blockchain fork simply by ensuring that the operation had
    the right Merkle root hash for that block.  These Merkle root hashes are called
    "consensus hashes."
    
    Processing a block happens in seven stages: "parse", "check", "log", "commit", "serialize", "snapshot", and "save"
    * "Parsing" a block transaction's nulldata (i.e. from an OP_RETURN) means translating 
    the OP_RETURN data into a virtual chain operation.
    * "Checking" an operation means ensuring the operation is valid.
    * "Logging" an operation means staging an operation to be fed into the state engine.
    * "Committing" an operation means feeding it into the state engine.
    * "Serializing" an operation means turning it into a byte string, in preparation for snapshotting.
    * "Snapshotting" means calculating the consensus hash of the state engine, at block N.
    * "Saving" means writing the new state to persistent storage.
    
    Blocks are processed in order, and transactions within a block are processed in the order in which 
    they appear in it.
    """
    

    def __init__(self, magic_bytes, opcodes, opfields, impl=None, state=None, initial_snapshots={}, expected_snapshots={}, backup_frequency=None, backup_max_age=None, read_only=False ):
        """
        Construct a state engine client, optionally from locally-cached 
        state and the set of previously-calculated consensus 
        hashes for each block.
        
        This class will be fed a sequence of sets of transactions, grouped by block 
        and ordered by block ID, that each contain an OP_RETURN.  The nulldata 
        assocated with the OP_RETURN will be parsed, checked, logged, and 
        committed by the implementation (impl).  The implementation decides exactly 
        what each of these mean; this class simply feeds it the transactions
        in the order they appeared on the blockchain.
        
        This class looks for OP_RETURN data that starts with the byte sequence in magic_bytes,
        and then only select those which start with magic_bytes + op, where op is an 
        opcode byte in opcodes.  Magic bytes can be of variable length, but it should
        be specific to this virtual chain.
        
        Expected OP_RETURN data format:
        
         0     M  M+1                      len(OP_RETURN)-M-1
         |-----|--|------------------------|
          magic op payload
        
        The job of the implementation is to translate the above data, plus anything else it 
        can earn from the previously-parsed transactions and from other sources, into a 
        dictionary of (field: value) tuples that constitute an operation.

        @magic_bytes: the `magic` field above.
        @opcodes: the list of possible values for the `op` field.
        @opfields: a dictionary that maps each `op` to a list of field names. 
        
        The caller may supply an optional argument called 'state', which will be 
        passed into each implementation method.  It is meant to preserve implementation-
        specific state--in particular, whatever state the implementation expects to be 
        present.

        If @expected_snapshots is given, then this is a dict that maps block heights
        to their expected consensus hashes.  If the calculated consensus hash does not 
        match the expected consensus hash, the state engine aborts the program.
        """
        
        self.consensus_hashes = initial_snapshots
        self.pending_ops = defaultdict(list)
        self.magic_bytes = magic_bytes 
        self.opcodes = opcodes[:]
        self.opfields = copy.deepcopy(opfields)
        self.state = state
        self.impl = impl
        self.lastblock = self.impl.get_first_block_id() - 1
        self.pool = None
        self.rejected = {}
        self.expected_snapshots = expected_snapshots
        self.backup_frequency = backup_frequency
        self.backup_max_age = backup_max_age
        self.read_only = read_only

        firsttime = True

        consensus_snapshots_filename = config.get_snapshots_filename(impl=impl)
        lastblock_filename = config.get_lastblock_filename(impl=impl)
       
        # if we crashed during a commit, and we're openning read-write, try to finish
        if not read_only:
            rc = self.commit( startup=True )
            if not rc:
               log.error("Failed to commit partial data.  Rolling back and aborting.")
               self.rollback()
               traceback.print_stack()
               os.abort()

        # can be missing all files (i.e. this is the first time), or none of them 
        for fp in [consensus_snapshots_filename, lastblock_filename]:
            if os.path.exists( fp ):
                # starting with existing data
                firsttime = False
        
        # attempt to load the snapshots 
        if os.path.exists( consensus_snapshots_filename ):
           log.debug("consensus snapshots at '%s'" % consensus_snapshots_filename)

           try:
              with open(consensus_snapshots_filename, 'r') as f: 
                 db_dict = json.loads(f.read())
                 assert 'snapshots' in db_dict
                 self.consensus_hashes = db_dict['snapshots']
                 
           except Exception, e:
              log.error("FATAL: Failed to read consensus snapshots at '%s'. Aborting." % consensus_snapshots_filename )
              log.exception(e)
              traceback.print_stack()
              os.abort()
            
        elif firsttime:

            log.debug("consensus snapshots at '%s'" % consensus_snapshots_filename)
            try:
                with open( consensus_snapshots_filename, 'w') as f:
                    f.write( json.dumps( {'snapshots': self.consensus_hashes} ) )
                    f.flush()

            except Exception, e:
                log.error("FATAL: failed to store initial snapshots to %s. Aborting." % consensus_snapshots_filename )
                log.exception(e)
                traceback.print_stack()
                os.abort()

        else:
            log.error("FATAL: No such file or directory: %s" % consensus_snapshots_filename )
            traceback.print_stack()
            os.abort()

        # what was the last block processed?
        if os.path.exists( lastblock_filename ):
           log.debug("lastblock at '%s'" % lastblock_filename)

           self.lastblock = self.get_lastblock( lastblock_filename=lastblock_filename )
           log.debug("Lastblock: %s (%s)" % (self.lastblock, lastblock_filename))
           if self.lastblock is None:
              log.error("FATAL: Failed to read last block number at '%s'.  Aborting." % lastblock_filename )
              log.exception(e)
              traceback.print_stack()
              os.abort()
         
        elif firsttime:
            log.debug("lastblock at '%s'" % lastblock_filename)
            try:
                log.debug("Store lastblock %s to %s" % (self.lastblock, lastblock_filename))
                with open(lastblock_filename, "w") as lastblock_f:
                    lastblock_f.write("%s" % self.lastblock)
                    lastblock_f.flush()

            except Exception, e:
                log.error("FATAL: failed to store initial lastblock to %s.  Aborting." % lastblock_filename)
                log.exception(e)
                traceback.print_stack()
                os.abort()

        else:
            log.error("FATAL: No such file or directory: %s" % lastblock_filename )
            traceback.print_stack()
            os.abort()


    def get_lastblock( self, lastblock_filename=None, impl=None, working_dir=None ):
        """
        What was the last block processed?
        Return the number on success
        Return None on failure to read
        """

        if lastblock_filename is None:
            
            if impl is None:
                impl = self.impl

            lastblock_filename = config.get_lastblock_filename(impl=impl, working_dir=working_dir)
        
        if os.path.exists( lastblock_filename ):
           try:
              with open(lastblock_filename, 'r') as f:
                 lastblock_str = f.read().strip()
                 return int(lastblock_str)
              
           except Exception, e:
              log.error("Failed to read last block number at '%s'" % lastblock_filename )
              return None

        return None

          
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
    
    
    def commit( self, backup=False, startup=False ):
        """
        Move all written but uncommitted data into place.
        Return True on success 
        Return False on error (in which case the caller should rollback())
        
        It is safe to call this method repeatedly until it returns True.
        """

        if self.read_only:
           log.error("FATAL: read-only")
           os.abort()

        tmp_db_filename = config.get_db_filename(impl=self.impl) + ".tmp"
        tmp_snapshot_filename = config.get_snapshots_filename(impl=self.impl) + ".tmp"
        tmp_lastblock_filename = config.get_lastblock_filename(impl=self.impl) + ".tmp"
        
        if not os.path.exists( tmp_lastblock_filename ) and (os.path.exists(tmp_db_filename) or os.path.exists(tmp_snapshot_filename)):
            # we did not successfully stage the write.
            # rollback 
            log.error("Partial write detected.  Not committing.")
            return False
           
        # basic sanity checks: don't overwrite the db if the file is zero bytes, or if we can't load it
        if os.path.exists( tmp_db_filename ):
            db_dir = os.path.dirname( tmp_db_filename )

            try:
                dirfd = os.open(db_dir, os.O_DIRECTORY)
                os.fsync(dirfd)
                os.close( dirfd )
            except Exception, e:
                log.exception(e)
                log.error("FATAL: failed to sync directory %s" % db_dir)
                traceback.print_stack()
                os.abort()

            sb = os.stat( tmp_db_filename )
            if sb.st_size == 0:
                log.error("Partial write detected: tried to overwrite with zero-sized db!  Will rollback.")
                return False

            if startup:
                # make sure we can load this 
                try:
                    with open(tmp_snapshot_filename, "r") as f:
                        db_txt = f.read()

                    db_json = json.loads(db_txt)
                except:
                    log.error("Partial write detected: corrupt partially-committed db!  Will rollback.")
                    return False

        
        backup_time = int(time.time() * 1000000)
       
        listing = []
        listing.append( ("lastblock", tmp_lastblock_filename, config.get_lastblock_filename(impl=self.impl)) )
        listing.append( ("snapshots", tmp_snapshot_filename, config.get_snapshots_filename(impl=self.impl)) )
        listing.append( ("db", tmp_db_filename, config.get_db_filename(impl=self.impl)) )

        for i in xrange(0, len(listing)):
            file_type, tmp_filename, filename = listing[i]
            
            dir_path = os.path.dirname( tmp_filename )
            dirfd = None
            try:
                dirfd = os.open(dir_path, os.O_DIRECTORY)
                os.fsync(dirfd)
            except Exception, e:
                log.exception(e)
                log.error("FATAL: failed to sync directory %s" % dir_path)
                traceback.print_stack()
                os.abort()

            if not os.path.exists( tmp_filename ):
                # no new state written
                os.close( dirfd )
                continue  

            # commit our new lastblock, consensus hash set, and state engine data
            try:
               
               # NOTE: rename fails on Windows if the destination exists 
               if sys.platform == 'win32' and os.path.exists( filename ):
                   log.debug("Clear old '%s' %s" % (file_type, filename))
                   os.unlink( filename )
                   os.fsync( dirfd )

               if not backup:
                   log.debug("Rename '%s': %s --> %s" % (file_type, tmp_filename, filename))
                   os.rename( tmp_filename, filename )
                   os.fsync( dirfd )

               else:
                   log.debug("Rename and back up '%s': %s --> %s" % (file_type, tmp_filename, filename))
                   shutil.copy( tmp_filename, tmp_filename + (".%s" % backup_time))
                   os.rename( tmp_filename, filename )
                   os.fsync( dirfd )
                  
            except Exception, e:
               log.exception(e)
               log.error("Failed to rename '%s' to '%s'" % (tmp_filename, filename))
               os.close( dirfd )
               return False 

            os.close( dirfd )
           
        return True
       

    def set_backup_frequency( self, backup_frequency ):
        self.backup_frequency = backup_frequency 


    def set_backup_max_age( self, backup_max_age ):
        self.backup_max_age = backup_max_age


    @classmethod 
    def get_backup_blocks( cls, impl, working_dir=None ):
        """
        Get the set of block IDs that were backed up
        """
        ret = []
        backup_dir = os.path.join( config.get_working_dir(impl=impl, working_dir=working_dir), "backups" )
        if not os.path.exists(backup_dir):
            return []

        for name in os.listdir( backup_dir ):
            if ".bak." not in name:
                continue 

            suffix = name.split(".bak.")[-1]
            try:
                block_id = int(suffix)
            except:
                continue 

            # must exist...
            backup_paths = cls.get_backup_paths( block_id, impl, working_dir=working_dir )
            for p in backup_paths:
                if not os.path.exists(p):
                    # doesn't exist
                    block_id = None
                    continue

            if block_id is not None:
                # have backup at this block 
                ret.append(block_id)

        return ret

        
    @classmethod
    def get_backup_paths( cls, block_id, impl, working_dir=None ):
        """
        Get the set of backup paths, given the virtualchain implementation module and block number
        """
        backup_dir = os.path.join( config.get_working_dir(impl=impl, working_dir=working_dir), "backups" )
        backup_paths = []
        for p in [config.get_db_filename(impl=impl, working_dir=working_dir), config.get_snapshots_filename(impl=impl, working_dir=working_dir), config.get_lastblock_filename(impl=impl, working_dir=working_dir)]:
            pbase = os.path.basename(p)
            backup_path = os.path.join( backup_dir, pbase + (".bak.%s" % block_id))
            backup_paths.append( backup_path )

        return backup_paths


    @classmethod
    def backup_restore( cls, block_id, impl, working_dir=None ):
        """
        Restore from a backup, given the virutalchain implementation module and block number
        """
        backup_dir = os.path.join( config.get_working_dir(impl=impl, working_dir=working_dir), "backups" )
        backup_paths = cls.get_backup_paths( block_id, impl, working_dir=working_dir )
        for p in backup_paths:
            assert os.path.exists( p ), "No such backup file: %s" % backup_paths

        for p in [config.get_db_filename(impl=impl, working_dir=working_dir), config.get_snapshots_filename(impl=impl, working_dir=working_dir), config.get_lastblock_filename(impl=impl, working_dir=working_dir)]:
            pbase = os.path.basename(p)
            backup_path = os.path.join( backup_dir, pbase + (".bak.%s" % block_id))
            log.debug("Restoring '%s' to '%s'" % (backup_path, p))
            shutil.copy( backup_path, p )
    
        return True


    def make_backups( self, block_id, working_dir=None ):
        """
        If we're doing backups on a regular basis, then 
        carry them out here if it is time to do so.
        This method does nothing otherwise.
        Abort on failure
        """

        # make a backup?
        if self.backup_frequency is not None:
            if (block_id % self.backup_frequency) == 0:

                backup_dir = os.path.join( config.get_working_dir(impl=self.impl, working_dir=working_dir), "backups" )
                if not os.path.exists(backup_dir):
                    try:
                        os.makedirs(backup_dir)
                    except Exception, e:
                        log.exception(e)
                        log.error("FATAL: failed to make backup directory '%s'" % backup_dir)
                        traceback.print_stack()
                        os.abort()
                        

                for p in [config.get_db_filename(impl=self.impl, working_dir=working_dir), config.get_snapshots_filename(impl=self.impl, working_dir=working_dir), config.get_lastblock_filename(impl=self.impl, working_dir=working_dir)]:
                    if os.path.exists(p):
                        try:
                            pbase = os.path.basename(p)
                            backup_path = os.path.join( backup_dir, pbase + (".bak.%s" % (block_id - 1)))

                            if not os.path.exists( backup_path ):
                                shutil.copy( p, backup_path )
                            else:
                                log.error("Will not overwrite '%s'" % backup_path)

                        except Exception, e:
                            log.exception(e)
                            log.error("FATAL: failed to back up '%s'" % p)
                            traceback.print_stack()
                            os.abort()

        return


    def clear_old_backups( self, block_id, working_dir=None ):
        """
        If we limit the number of backups we make, then clean out old ones
        older than block_id - backup_max_age (given in the constructor)

        This method does nothing otherwise.
        """
        
        if self.backup_max_age is None:
            # never delete backups
            return 

        # find old backups 
        backup_dir = os.path.join( config.get_working_dir(impl=self.impl, working_dir=working_dir), "backups" )
        if not os.path.exists(backup_dir):
            return 

        backups = os.listdir( backup_dir )
        for backup_name in backups:
            if backup_name in [".", ".."]:
                continue 

            backup_path = os.path.join(backup_dir, backup_name)
            backup_block = None 

            try:
                backup_block = int(backup_path.split(".")[-1])
            except:
                # not a backup file
                log.info("Skipping non-backup '%s'" % backup_path)

            if not backup_path.endswith( ".bak.%s" % backup_block ):
                # not a backup file 
                log.info("Skipping non-backup '%s'" % backup_path)
                continue
        
            if backup_block + self.backup_max_age < block_id:
                # dead 
                log.info("Removing old backup '%s'" % backup_path)
                try:
                    os.unlink(backup_path)
                except:
                    pass

    
    def save( self, block_id, consensus_hash, pending_ops, backup=False, working_dir=None ):
        """
        Write out all state to the working directory.
        Calls the implementation's 'db_save' method to store any state for this block.
        Calls the implementation's 'db_continue' method at the very end, to signal
        to the implementation that all virtualchain state has been saved.  This method
        can return False, in which case, indexing stops
        
        Return True on success 
        Return False if the implementation wants to exit.
        Aborts on fatal error
        """
        
        if self.read_only:
            log.error("FATAL: read only")
            traceback.print_stack()
            os.abort()

        if block_id < self.lastblock:
            log.error("FATAL: Already processed up to block %s (got %s)" % (self.lastblock, block_id))
            traceback.print_stack()
            os.abort()

        # stage data to temporary files
        tmp_db_filename = (config.get_db_filename(impl=self.impl, working_dir=working_dir) + ".tmp")
        tmp_snapshot_filename = (config.get_snapshots_filename(impl=self.impl, working_dir=working_dir) + ".tmp")
        tmp_lastblock_filename = (config.get_lastblock_filename(impl=self.impl, working_dir=working_dir) + ".tmp")
        
        try:
            with open(tmp_snapshot_filename, 'w') as f:
                db_dict = {
                   'snapshots': self.consensus_hashes
                }
                f.write(json.dumps(db_dict))
                f.flush()
            
            with open(tmp_lastblock_filename, "w") as lastblock_f:
                lastblock_f.write("%s" % block_id)
                lastblock_f.flush()

        except Exception, e:
            # failure to save is fatal 
            log.exception(e)
            log.error("FATAL: Could not stage data for block %s" % block_id)
            traceback.print_stack()
            os.abort()

        rc = self.impl.db_save( block_id, consensus_hash, pending_ops, tmp_db_filename, db_state=self.state )
        if not rc:
            # failed to save 
            # this is a fatal error
            log.error("FATAL: Implementation failed to save at block %s to %s" % (block_id, tmp_db_filename))
            
            try:
                os.unlink( tmp_lastblock_filename )
            except:
                pass 
            
            try:
                os.unlink( tmp_snapshot_filename )
            except:
                pass 
            
            traceback.print_stack()
            os.abort()
       
        rc = self.commit( backup=backup )
        if not rc:
            log.error("Failed to commit data at block %s.  Rolling back and aborting." % block_id )
            
            self.rollback()
            traceback.print_stack()
            os.abort()
        
        else:
            self.lastblock = block_id

            # make new backups 
            self.make_backups( block_id )

            # clear out old backups
            self.clear_old_backups( block_id )
   
        continue_indexing = True
        if hasattr(self.impl, "db_continue"):
            try:
                continue_indexing = self.impl.db_continue( block_id, consensus_hash )
            except Exception, e:
                log.exception(e)
                traceback.print_stack()
                log.error("FATAL: implementation failed db_continue")
                os.abort()

        return continue_indexing

   
    @classmethod
    def calculate_consensus_hash( self, merkle_root ):
        """
        Given the Merkle root of the set of records processed, calculate the consensus hash.
        """
        return binascii.hexlify( pybitcoin.hash.bin_hash160(merkle_root, True)[0:16])

  
    @classmethod 
    def make_ops_snapshot( cls, serialized_ops ):
        """
        Generate a deterministic hash over the sequence of (serialized) operations.
        """
        record_hashes = []
        for serialized_op in serialized_ops:
            record_hash = binascii.hexlify( pybitcoin.hash.bin_double_sha256( serialized_op ) )
            record_hashes.append( record_hash )

        if len(record_hashes) == 0:
            record_hashes.append( binascii.hexlify( pybitcoin.hash.bin_double_sha256( "" ) ) )

        # put records into their own Merkle tree, and mix the root with the consensus hashes.
        record_hashes.sort()
        record_merkle_tree = pybitcoin.MerkleTree( record_hashes )
        record_root_hash = record_merkle_tree.root()

        return record_root_hash


    @classmethod 
    def make_snapshot_from_ops_hash( cls, record_root_hash, prev_consensus_hashes ):
        """
        Generate the consensus hash from the hash over the current ops, and 
        all previous required consensus hashes.
        """

        # mix into previous consensus hashes...
        all_hashes = prev_consensus_hashes[:] + [record_root_hash]
        all_hashes.sort()
        all_hashes_merkle_tree = pybitcoin.MerkleTree( all_hashes )
        root_hash = all_hashes_merkle_tree.root()

        consensus_hash = StateEngine.calculate_consensus_hash( root_hash )
        return consensus_hash 


    @classmethod
    def make_snapshot( cls, serialized_ops, prev_consensus_hashes ):
        """
        Generate a consensus hash, using the tx-ordered list of serialized name 
        operations, and a list of previous consensus hashes that contains
        the (k-1)th, (k-2)th; (k-3)th; ...; (k - (2**i - 1))th consensus hashes, 
        all the way back to the beginning of time (prev_consensus_hashes[i] is the 
        (k - (2**(i+1) - 1))th consensus hash)
        """

        record_root_hash = StateEngine.make_ops_snapshot( serialized_ops )
        log.debug("Snapshot('%s', %s)" % (record_root_hash, prev_consensus_hashes))
        return cls.make_snapshot_from_ops_hash( record_root_hash, prev_consensus_hashes )


    @classmethod
    def serialize_op( cls, opcode, opdata, opfields, verbose=True ):
        """
        Given an opcode (byte), associated data (dict), and the operation
        fields to serialize (opfields), convert it 
        into its canonical serialized form (i.e. in order to 
        generate a consensus hash.

        Return the canonical form on success.
        Return None on error.
        """

        fields = opfields.get( opcode, None )
        if fields is None:
            log.error("BUG: unrecongnized opcode '%s'" % opcode )
            return None 

        all_values = []
        debug_all_values = []
        missing = []
        for field in fields:
           if not opdata.has_key(field):
              missing.append( field )

           field_value = opdata.get(field, None)
           if field_value is None:
              field_value = ""
          
           # netstring format
           debug_all_values.append( str(field) + "=" + str(len(str(field_value))) + ":" + str(field_value) )
           all_values.append( str(len(str(field_value))) + ":" + str(field_value) )

        if len(missing) > 0:
           log.error("Missing fields; dump follows:\n%s" % simplejson.dumps( opdata, indent=4, sort_keys=True ))
           raise Exception("BUG: missing fields '%s'" % (",".join(missing)))

        if verbose:
            log.debug("SERIALIZE: %s:%s" % (opcode, ",".join(debug_all_values) ))

        field_values = ",".join( all_values )

        return opcode + ":" + field_values


    def snapshot( self, block_id, oplist ):
        """
        Given the currnet block ID and the set of operations committed,
        find the consensus hash that represents the state of the virtual chain.
        
        The consensus hash is calculated as a Merkle skip-list.  It incorporates:
        * block K's operations 
        * block K - 1's consensus hash 
        * block K - 2 - 1's consensus hash 
        * block K - 4 - 2 - 1's consensus hash, 
        ...
        * block K - (2**i - 1)'s consensus hash
        
        The purpose of this construction is that it reduces the number of queries 
        a client needs to verify the integrity of previously-processed operations
        to a *sublinear* function of the length of the virtual blockchain.
        
        For example, if there are 15 blocks in the virtual chain, and a client has 
        the consensus hash for block 15 (ch[15]) but wants to verify an operation at block 3, the 
        client would:
        1.    Fetch ops[15], ch[14], ch[12], ch[8], ch[0]
        2.    Verify (1) with ch[15], so ch[8] is trusted.
        3.    Fetch ops[8], ch[7], ch[5], ch[1]
        4.    Verify (3) with ch[8], so ch[5] is trusted
        5.    Fetch ops[5], ch[3]
        6.    Verify (5) and ch[1] from (3) with ch[5], so ch[3] is trusted
        7.    Fetch ops[3], ch[2]
        8.    Verify (7) and ch[0] from (1) with ch[3], so ops[3] is trusted
        9.    Verify op in ops[3]
        """
        
        log.debug("Snapshotting block %s" % (block_id) )
        
        serialized_ops = []
        for opdata in oplist:
            serialized_record = StateEngine.serialize_op( opdata['virtualchain_opcode'], opdata, self.opfields )
            serialized_ops.append( serialized_record )

        previous_consensus_hashes = []
        k = block_id
        i = 1
        while k - (2**i - 1) >= self.impl.get_first_block_id():
            prev_block = k - (2**i - 1)
            prev_ch = self.get_consensus_at( prev_block )
            log.debug("Snapshotting block %s: consensus hash of %s is %s" % (block_id, prev_block, prev_ch))

            if prev_ch is None:
                log.error("BUG: None consensus for %s" % prev_block )
                traceback.print_stack()
                os.abort()

            previous_consensus_hashes.append( prev_ch )
            i += 1

        consensus_hash = StateEngine.make_snapshot( serialized_ops, previous_consensus_hashes )

        self.consensus_hashes[ str(block_id) ] = consensus_hash 
        
        return consensus_hash
   
   
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
        inputs = tx['vin']
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
        
        op = self.impl.db_parse( block_id, tx['txid'], tx['txindex'], op_code, op_payload, senders, inputs, outputs, fee, db_state=self.state )
        
        if op is None:
            # not valid 
            return None 
        
        # store it
        op['virtualchain_opcode'] = op_code
        op['virtualchain_outputs'] = outputs 
        op['virtualchain_senders'] = senders 
        op['virtualchain_fee'] = fee
        op['virtualchain_block_number'] = block_id
        op['virtualchain_accepted'] = False       # not yet accepted
        op['virtualchain_txid'] = tx['txid']
        op['virtualchain_txindex'] = tx['txindex']
        
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
            if str(k) not in RESERVED_KEYS:
                sanitized[str(k)] = copy.deepcopy(op[k])
            else:
                reserved[str(k)] = copy.deepcopy(op[k])
                
        return sanitized, reserved
  

    def sanitize_op( self, op ):
        """
        Remove and return the non-virtualchain-reserved keywords
        from an op.
        """
        return self.remove_reserved_keys( op )[0]


    def log_accept( self, block_id, vtxindex, opcode, op ):
        """
        Log an accepted operation
        """
        log.debug("ACCEPT op %s at (%s, %s) (%s)" % (opcode, block_id, vtxindex, json.dumps(op, sort_keys=True)))


    def log_reject( self, block_id, vtxindex, opcode, op ):
        """
        Log a rejected operation
        """
        log.debug("REJECT op %s (%s)" % (opcode, json.dumps(op, sort_keys=True)))
 

    def process_ops( self, block_id, ops ):
        """
        Given a transaction-ordered sequence of parsed operations,
        check their validity and give them to the state engine to 
        affect state changes.

        It calls 'db_check' to validate each operation, and 'db_commit'
        to add it to the state engine.  Gets back a list of state
        transitions (ops) to snapshot.
        """

        new_ops = defaultdict(list)

        for op in self.opcodes:
            new_ops[op] = []

        # transaction-ordered listing of accepted operations
        new_ops['virtualchain_ordered'] = []
        new_ops['virtualchain_all_ops'] = ops

        to_commit_sanitized = []
        to_commit_reserved = []

        # let the implementation do an initial scan over the blocks 
        initial_scan = []
        for i in xrange(0, len(ops)):

            op_data = ops[i]
            op_sanitized, _ = self.remove_reserved_keys( op_data )
            initial_scan.append( copy.deepcopy( op_sanitized ) )

        # for backwards-compatibility 
        if hasattr(self.impl, "db_scan_block"):
            self.impl.db_scan_block( block_id, initial_scan, db_state=self.state )
        else:
            log.debug("Compat: no db_scan_block")

        # check each operation 
        for i in xrange(0, len(ops)):
            op_data = ops[i]
            op_sanitized, reserved = self.remove_reserved_keys( op_data )
            opcode = reserved['virtualchain_opcode']

            # check this op
            rc = self.impl.db_check( block_id, new_ops, opcode, op_sanitized, reserved['virtualchain_txid'], reserved['virtualchain_txindex'], to_commit_sanitized, db_state=self.state )
            if rc:

                # commit this op
                new_op_list = self.impl.db_commit( block_id, opcode, op_sanitized, reserved['virtualchain_txid'], reserved['virtualchain_txindex'], db_state=self.state )
                if type(new_op_list) != list:
                    new_op_list = [new_op_list]

                for new_op in new_op_list:
                    if new_op is not None:
                        if type(new_op) == dict:

                            # externally-visible state transition 
                            to_commit_sanitized_op = copy.deepcopy( new_op )
                            to_commit_sanitized.append( to_commit_sanitized_op )

                            new_op.update( reserved )
                            new_ops[ opcode ].append( new_op )
                            new_ops['virtualchain_ordered'].append( new_op )

                        else:
                            # internal state transition 
                            continue

            else:
                self.log_reject( block_id, reserved['virtualchain_txindex'], opcode, copy.deepcopy(op_sanitized))

        
        # final commit
        # the implementation has a chance here to feed any extra data into the consensus hash with this call
        # (e.g. to affect internal state transitions that occur as seconary, holistic consequences to the sequence
        # of prior operations for this block).
        final_op = self.impl.db_commit( block_id, 'virtualchain_final', None, None, None, db_state=self.state )
        if final_op is not None:
            final_op['virtualchain_opcode'] = 'final'

            new_ops['virtualchain_final'] = [final_op]
            new_ops['virtualchain_ordered'].append( final_op )
            new_ops['virtualchain_all_ops'].append( final_op )

        return new_ops
    
    
    def process_block( self, block_id, ops, backup=False, expected_snapshots=None ):
        """
        Top-level block processing method.
        Feed the block and its data transactions 
        through the implementation, to build up the 
        implementation's state.  Cache the 
        resulting data to disk.
       
        Return the consensus hash for this block on success.
        Exit on failure.
        """
        
        log.debug("Process block %s (%s virtual transactions)" % (block_id, len(ops)))

        if expected_snapshots is None:
            expected_snapshots = self.expected_snapshots
        
        new_ops = self.process_ops( block_id, ops )
        sanitized_ops = {}  # for save()

        consensus_hash = self.snapshot( block_id, new_ops['virtualchain_ordered'] )

        # sanity check 
        if expected_snapshots.has_key(block_id) and expected_snapshots[block_id] != consensus_hash:
            log.error("FATAL: consensus hash mismatch at height %s: %s != %s" % (block_id, expected_snapshots[block_id], consensus_hash))
            traceback.print_stack()
            os.abort()

        for op in new_ops.keys():

            sanitized_ops[op] = []
            for i in xrange(0, len(new_ops[op])):

                op_sanitized, op_reserved = self.remove_reserved_keys( new_ops[op][i] )
                sanitized_ops[op].append( op_sanitized )

        rc = self.save( block_id, consensus_hash, sanitized_ops, backup=backup )
        if not rc:
            # implementation requests early termination 
            log.debug("Early indexing termination at %s" % block_id)
            return None

        return consensus_hash


    @classmethod
    def build( cls, bitcoind_opts, end_block_id, state_engine, expected_snapshots={}, tx_filter=None ):
        """
        Top-level call to process all blocks in the blockchain.
        Goes and fetches all OP_RETURN nulldata in order,
        and feeds them into the state engine implementation using its
        'db_parse', 'db_check', 'db_commit', and 'db_save'
        methods.
        
        Note that this method can take some time (hours, days) to complete 
        when called from the first block.
        
        Return True on success 
        Return False on error
        Raise an exception on recoverable error--the caller should simply try again.
        Exit on irrecoverable error--do not try to make forward progress
        """
       
        first_block_id = state_engine.lastblock + 1
        if first_block_id >= end_block_id:
            # built 
            log.debug("Up-to-date (%s >= %s)" % (first_block_id, end_block_id))
            return True 

        rc = True
        batch_size = config.BLOCK_BATCH_SIZE

        log.debug("Sync virtualchain state from %s to %s" % (first_block_id, end_block_id) )
        
        for block_id in xrange( first_block_id, end_block_id+1, batch_size ):
            
            if not rc:
                break 
           
            last_block_id = min(block_id + batch_size, end_block_id)
            block_ids_and_txs = transactions.get_virtual_transactions( bitcoind_opts, block_id, last_block_id, spv_last_block=end_block_id - 1, tx_filter=tx_filter )
            if block_ids_and_txs is None:
                raise Exception("Failed to get virtual transactions %s to %s" % (block_id, last_block_id))

            # process in order by block ID
            block_ids_and_txs.sort()
           
            for processed_block_id, txs in block_ids_and_txs:

                if state_engine.get_consensus_at( processed_block_id ) is not None:
                    raise Exception("Already processed block %s (%s)" % (processed_block_id, state_engine.get_consensus_at( processed_block_id )) )

                ops = state_engine.parse_block( processed_block_id, txs )
                consensus_hash = state_engine.process_block( processed_block_id, ops, expected_snapshots=expected_snapshots )
                
                if consensus_hash is None:
                    # request to stop
                    rc = False
                    log.debug("Stopped processing at block %s" % processed_block_id)
                    break

                log.debug("CONSENSUS(%s): %s" % (processed_block_id, state_engine.get_consensus_at( processed_block_id )))

                # sanity check, if given 
                expected_consensus_hash = state_engine.get_expected_consensus_at( processed_block_id )
                if expected_consensus_hash is not None:
                    if str(consensus_hash) != str(expected_consensus_hash):
                        rc = False
                        log.error("FATAL: DIVERGENCE DETECTED AT %s: %s != %s" % (processed_block_id, consensus_hash, expected_consensus_hash))
                        traceback.print_stack()
                        os.abort()
       
            if not rc:
                break
        
        log.debug("Last block is %s" % state_engine.lastblock )
        return rc
    
   
    def get_consensus_at( self, block_id ):
        """
        Get the consensus hash at a given block
        """
        return self.consensus_hashes.get( str(block_id), None )


    def get_expected_consensus_at( self, block_id ):
        """
        Get the expected consensus hash at a given block
        """
        return self.expected_snapshots.get( str(block_id), None )


    def get_block_from_consensus( self, consensus_hash ):
        """
        Get the block number with the given consensus hash.
        Return None if there is no such block.
        """
        # NOTE: not the most efficient thing here...
        for (block_id, ch) in self.consensus_hashes.iteritems():
            if str(ch) == str(consensus_hash):
                return int(block_id)

        return None


    def get_valid_consensus_hashes( self, block_id ):
        """
        Get the list of valid consensus hashes for a given block.
        """
        valid_consensus_hashes = []
        first_block_to_check = block_id - config.BLOCKS_CONSENSUS_HASH_IS_VALID
        for block_number in xrange(first_block_to_check, block_id+1):
            
            block_number_key = str(block_number)
            
            if block_number_key not in self.consensus_hashes.keys():
                continue
            
            valid_consensus_hashes.append( str(self.consensus_hashes[block_number_key]) )
          
        return valid_consensus_hashes
    
    
    def get_current_consensus(self):
        """
        Get the current consensus hash.
        """
        return self.get_consensus_at( str(self.lastblock) )

    def get_current_block( self ):
        """
        Get the last block Id processed.
        """
        return self.lastblock

    def is_consensus_hash_valid( self, block_id, consensus_hash ):
        """
        Given a block ID and a consensus hash, is 
        the hash still considered to be valid?
        We allow a grace period for which a consensus hash 
        is valid, since a writer might submit a 
        "recently stale" consensus hash under 
        heavy write load.
        """
        
        return str(consensus_hash) in self.get_valid_consensus_hashes( block_id )
     

    def get_rejected_ops( self ):
        """
        Get the op --> [operations] dict of rejected
        operations from the last block processed.
        """
        return self.rejected


def get_index_range( bitcoind ):
    """
    Get the range of block numbers that we need to fetch from the blockchain.
    
    Return None, None if we fail to connect to bitcoind.
    """

    start_block = config.get_first_block_id()
       
    try:
       current_block = int(bitcoind.getblockcount())
        
    except Exception, e:
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

