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
import json
import binascii
import copy
import shutil
import time
import traceback
import simplejson
import sqlite3
import random
import subprocess
import tempfile

from .hashing import *
from .merkle import *

from collections import defaultdict 

import config
import blockchain.transactions as transactions
from blockchain.bitcoin_blockchain import get_bitcoin_blockchain_height

log = config.get_logger("virtualchain")

# debug statistics (only available in testnet).
# keyed by block height
STATISTICS = {}

RESERVED_KEYS = [
   'virtualchain_opcode',
   'virtualchain_txid',
   'virtualchain_txindex',
   'virtualchain_txhex',
   'virtualchain_tx_merkle_path',
   'virtualchain_senders',
   'virtualchain_data_hex',
   'virtualchain_fee',
]

CHAINSTATE_FIELDS = [
    'txid',
    'txindex',
    'block_id',
    'vtxindex',
    'opcode',
    'data_hex',
    'senders',
    'tx_hex',
    'tx_merkle_path',
    'fee'
]

VIRTUALCHAIN_DB_SCRIPT = """
-- senders is a JSON-serialized blob describing all transactions that fed into this virtualchain transaction
CREATE TABLE chainstate( txid TEXT NOT NULL,
                         txindex INT NOT NULL,
                         block_id INT NOT NULL,
                         vtxindex INT NOT NULL,
                         opcode TEXT NOT NULL,
                         data_hex TEXT NOT NULL,
                         senders TEXT NOT NULL,
                         tx_hex TEXT NOT NULL,
                         tx_merkle_path TEXT NOT NULL,
                         fee INT NOT NULL,
                         PRIMARY KEY(txid,block_id,vtxindex) );

CREATE TABLE snapshots(block_id INT NOT NULL,
                       timestamp INT NOT NULL,
                       consensus_hash TEXT NOT NULL,
                       ops_hash TEXT,
                       PRIMARY KEY(block_id));
"""


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
   
    # TODO: update this next paragraph

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

    def __init__(self, impl, working_dir, state=None, magic_bytes=None, opcodes=None, opfields=None, expected_snapshots={}, backup_frequency=None, backup_max_age=None, read_only=False ):
        """
        Construct a state engine client, optionally from locally-cached 
        state and the set of previously-calculated consensus 
        hashes for each block.
        
        This class will be fed a sequence of sets of transactions, grouped by block 
        and ordered by block ID, that each contain a data-bearing field.  The data
        will be parsed, checked, logged, and committed by the implementation (impl).
        The implementation decides exactly what each of these mean; this class simply
        feeds it the transactions in the order they appeared on the blockchain.
        
        This class looks for transaction data that starts with the byte sequence in magic_bytes,
        and then only select those which start with magic_bytes + op, where op is an 
        opcode byte in opcodes.  Magic bytes can be of variable length, but it should
        be specific to this virtual chain.
        
        Expected transaction data field format:
        
         0     M  M+1                      len(data_field)-M-1
         |-----|--|------------------------|
          magic op payload
        
        The job of the implementation is to translate the above data, plus anything else it 
        can earn from the previously-parsed transactions and from other sources, into a 
        dictionary of (field: value) tuples that constitute a state transition.

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
        # TODO: check impl
        for elem in ['get_opcodes', 'get_opfields', 'get_magic_bytes', 'get_initial_snapshots', 'get_first_block_id', 'db_save', 'db_parse', 'db_check', 'db_commit', 'get_blockchain', 'get_valid_transaction_window']:
            assert hasattr(impl, elem), 'Implementation is missing "{}"'.format(elem)

        if opcodes is None:
            opcodes = impl.get_opcodes() 

        if opfields is None:
            opfields = impl.get_opfields()

        if magic_bytes is None:
            magic_bytes = impl.get_magic_bytes()

        self.magic_bytes = magic_bytes
        self.opcodes = opcodes[:]
        self.opfields = copy.deepcopy(opfields)
        self.state = state
        self.impl = impl
        self.lastblock = self.impl.get_first_block_id() - 1     # start from the beginning by default; will change with db_setup()
        self.expected_snapshots = expected_snapshots
        self.backup_frequency = backup_frequency
        self.backup_max_age = backup_max_age
        self.read_only = read_only
        self.setup = False
        self.working_dir = working_dir
        
        # caller must call db_setup() next.


    @classmethod
    def db_format_query(cls, query, values):
        """
        Turn a query into a string for printing.
        Useful for debugging.
        """
        return 'CHAINSTATE: ' + "".join( ["%s %s" % (frag, "'%s'" % val if type(val) in [str, unicode] else val) for (frag, val) in zip(query.split("?"), values + ("",))] )


    def db_setup(self):
        """
        Set up the state engine database.
        * If it doesn't exist, then create it.
        * If it does exist, then check that it is in a clean state.  If not, then recover from a known-good backup.

        Return True on success
        Return False if there was an unclean shutdown.  The caller should call db_restore() in this case to continue
        Raise exception on error
        Abort on db error
        """
        if self.db_exists(impl=self.impl, working_dir=self.working_dir):
            # resuming from previous indexing
            # read/write and unclean shutdown?
            if not self.read_only and self.db_is_indexing(self.impl, self.working_dir):
                log.error("Unclean shutdown detected on read/write open")
                return False
        
        else:
            # setting up for the first time
            assert not self.read_only, 'Cannot instantiate database if read_only is True'
            db_con = self.db_create(self.impl, self.working_dir)
            initial_snapshots = self.impl.get_initial_snapshots()
            for block_id in sorted(initial_snapshots.keys()):
                self.db_snapshot_append(db_con, int(block_id), str(initial_snapshots[block_id]), None, int(time.time()))

        self.chainstate_path = config.get_snapshots_filename(self.impl, self.working_dir)
        self.lastblock = self.get_lastblock(self.impl, self.working_dir)
        self.setup = True
        return True


    def db_restore(self, block_number=None):
        """
        Restore the database and clear the indexing lockfile.
        Restore to a given block if given; otherwise use the most recent valid backup.

        Return True on success
        Return False if there is no state to restore
        Raise exception on error
        """
        restored = False
        if block_number is not None:
            # restore a specific backup
            try:
                self.backup_restore(block_number, self.impl, self.working_dir)
                restored = True
            except AssertionError:
                log.error("Failed to restore state from {}".format(block_number))
                return False

        else:
            # find the latest block
            backup_blocks = self.get_backup_blocks(self.impl, self.working_dir)
            for block_number in reversed(sorted(backup_blocks)):
                try:
                    self.backup_restore(block_number, self.impl, self.working_dir)
                    restored = True
                    log.debug("Restored state from {}".format(block_number))
                    break
                except AssertionError:
                    log.debug("Failed to restore state from {}".format(block_number))
                    continue

            if not restored:
                # failed to restore
                log.error("Failed to restore state from {}".format(','.join(backup_blocks)))
                return False

        # woo!
        self.db_set_indexing(False, self.impl, self.working_dir)
        return self.db_setup()

    
    @classmethod
    def db_exists(cls, impl, working_dir):
        """
        Does the chainstate db exist?
        """
        path = config.get_snapshots_filename(impl, working_dir)
        return os.path.exists(path)

    
    @classmethod
    def db_create(cls, impl, working_dir):
        """
        Create a sqlite3 db at the given path.
        Create all the tables and indexes we need.
        Returns a db connection on success
        Raises an exception on error
        """

        global VIRTUALCHAIN_DB_SCRIPT
       
        log.debug("Setup chain state in {}".format(working_dir))

        path = config.get_snapshots_filename(impl, working_dir)
        if os.path.exists( path ):
            raise Exception("Database {} already exists")

        lines = [l + ";" for l in VIRTUALCHAIN_DB_SCRIPT.split(";")]
        con = sqlite3.connect(path, isolation_level=None, timeout=2**30)

        for line in lines:
            con.execute(line)

        con.row_factory = StateEngine.db_row_factory
        return con
    
    @classmethod
    def db_connect(cls, path):
        """
        connect to our chainstate db
        """
        con = sqlite3.connect(path, isolation_level=None, timeout=2**30)
        con.row_factory = StateEngine.db_row_factory
        return con

    
    @classmethod
    def db_open(cls, impl, working_dir):
        """
        Open a connection to our chainstate db
        """
        path = config.get_snapshots_filename(impl, working_dir)
        return cls.db_connect(path)


    @classmethod
    def db_row_factory(cls, cursor, row):
        """
        Row factory to convert rows to a dict
        """
        d = {}
        for idx, col in enumerate( cursor.description ):
            d[col[0]] = row[idx]

        return d

    
    @classmethod
    def db_query_execute(cls, cur, query, values, verbose=True):
        """
        Execute a query.
        Handle db timeouts.
        Abort on failure.
        """
        timeout = 1.0

        if verbose:
            log.debug(cls.db_format_query(query, values))

        while True:
            try:
                ret = cur.execute(query, values)
                return ret
            except sqlite3.OperationalError as oe:
                if oe.message == "database is locked":
                    timeout = timeout * 2 + timeout * random.random()
                    log.error("Query timed out due to lock; retrying in %s: %s" % (timeout, cls.db_format_query( query, values )))
                    time.sleep(timeout)
                
                else:
                    log.exception(oe)
                    log.error("FATAL: failed to execute query (%s, %s)" % (query, values))
                    log.error("\n".join(traceback.format_stack()))
                    os.abort()

            except Exception, e:
                log.exception(e)
                log.error("FATAL: failed to execute query (%s, %s)" % (query, values))
                log.error("\n".join(traceback.format_stack()))
                os.abort()


    @classmethod
    def db_chainstate_append(cls, cur, **fields):
        """
        Insert a row into the chain state.
        Meant to be executed as part of a transaction.

        Return True on success
        Raise an exception if the fields are invalid
        Abort on db error.
        """
        missing = []
        extra = []
        for reqfield in CHAINSTATE_FIELDS:
            if reqfield not in fields:
                missing.append(reqfield)

        for fieldname in fields:
            if fieldname not in CHAINSTATE_FIELDS:
                extra.append(fieldname)

        if len(missing) > 0 or len(extra) > 0:
            raise ValueError("Invalid fields: missing: {}, extra: {}".format(','.join(missing), ','.join(extra)))

        query = 'INSERT INTO chainstate ({}) VALUES ({});'.format(
                ','.join( CHAINSTATE_FIELDS ),
                ','.join( ['?'] * len(CHAINSTATE_FIELDS)))

        args = tuple([fields[fieldname] for fieldname in CHAINSTATE_FIELDS])
        cls.db_query_execute(cur, query, args)
        return True


    @classmethod
    def db_snapshot_append(cls, cur, block_id, consensus_hash, ops_hash, timestamp):
        """
        Append hash info for the last block processed, and the time at which it was done.
        Meant to be executed as part of a transaction.

        Return True on success
        Raise an exception on invalid block number
        Abort on db error
        """
        
        query = 'INSERT INTO snapshots (block_id,consensus_hash,ops_hash,timestamp) VALUES (?,?,?,?);'
        args = (block_id,consensus_hash,ops_hash,timestamp)
        
        cls.db_query_execute(cur, query, args)
        return True

    
    @classmethod
    def db_chainstate_get_block(cls, cur, block_height):
        """
        Get the list of virtualchain transactions accepted at a given block.
        Returns the list of rows, where each row is a dict.
        """
        query = 'SELECT * FROM chainstate WHERE block_id = ? ORDER BY vtxindex;'
        args = (block_height,)

        rows = cls.db_query_execute(cur, query, args, verbose=False)
        ret = []

        for r in rows:
            rowdata = {
                'txid': str(r['txid']),
                'block_id': r['block_id'],
                'txindex': r['txindex'],
                'vtxindex': r['vtxindex'],
                'opcode': str(r['opcode']),
                'data_hex': str(r['data_hex']),
                'senders': simplejson.loads(r['senders']),
                'tx_hex': str(r['tx_hex']),
                'tx_merkle_path': str(r['tx_merkle_path']),
                'fee': r['fee']
            }

            ret.append(rowdata)

        return ret


    @classmethod
    def db_set_indexing(cls, is_indexing, impl, working_dir):
        """
        Set lockfile path as to whether or not the system is indexing.
        NOT THREAD SAFE, USE ONLY FOR CRASH DETECTION.
        """
        indexing_lockfile_path = config.get_lockfile_filename(impl, working_dir)
        if is_indexing:
            # make sure this exists
            with open(indexing_lockfile_path, 'w') as f:
                pass

        else:
            # make sure it does not exist 
            try:
                os.unlink(indexing_lockfile_path)
            except:
                pass


    @classmethod
    def db_is_indexing(cls, impl, working_dir):
        """
        Is the system indexing?
        Return True if so, False if not.
        """
        indexing_lockfile_path = config.get_lockfile_filename(impl, working_dir)
        return os.path.exists(indexing_lockfile_path)

    
    @classmethod
    def get_lastblock(cls, impl, working_dir):
        """
        What was the last block processed?
        Return the number on success
        Return None on failure to read
        """
        if not cls.db_exists(impl, working_dir):
            return None

        con = cls.db_open(impl, working_dir)
        query = 'SELECT MAX(block_id) FROM snapshots;'
        
        rows = cls.db_query_execute(con, query, (), verbose=False)
        ret = None
        for r in rows:
            ret = r['MAX(block_id)']

        con.close()
        return ret
   

    @classmethod
    def get_consensus_hashes(cls, impl, working_dir, start_block_height=None, end_block_height=None, db_con=None, completeness_check=True):
        """
        Read all consensus hashes into memory.  They're write-once read-many,
        so no need to worry about cache-coherency.
        """
        if (start_block_height is None and end_block_height is not None) or (start_block_height is not None and end_block_height is None):
            raise ValueError("Need either both or neither start/end block height")

        we_opened = False
        if db_con is not None:
            con = db_con

        else:
            assert impl and working_dir, 'Need impl and working_dir if db_con is not given'
            con = cls.db_open(impl, working_dir)
            we_opened = True

        range_query = ''
        range_args = ()

        if start_block_height and end_block_height:
            range_query += ' WHERE block_id >= ? AND block_id < ?'
            range_args += (start_block_height,end_block_height)

        query = 'SELECT block_id,consensus_hash FROM snapshots' + range_query + ';'
        args = range_args

        rows = cls.db_query_execute(con, query, range_args, verbose=False)
        ret = {}
        block_min = None
        block_max = None

        for r in rows:
            block_id = int(r['block_id'])
            ret[block_id] = r['consensus_hash']

            if block_min is None or block_min > block_id:
                block_min = block_id

            if block_max is None or block_max < block_id:
                block_max = block_id

        if we_opened:
            con.close()
       
        if completeness_check:
            # sanity check
            for i in range(block_min,block_max+1):
                ch = ret.get(i, None)

                assert ch is not None, 'Missing consensus hash for {}'.format(i)
                assert isinstance(ret[i], (str,unicode)), 'consensus hash for {} is type {}'.format(i, type(ret[i]))

        return ret
   

    @classmethod
    def get_ops_hashes(cls, impl, working_dir, start_block_height=None, end_block_height=None):
        """
        Read all consensus hashes into memory.  They're write-once read-many,
        so no need to worry about cache-coherency.
        """
        if (start_block_height is None and end_block_height is not None) or (start_block_height is not None and end_block_height is None):
            raise ValueError("Need either both or neither start/end block height")

        con = cls.db_open(impl, working_dir)
        range_query = ' WHERE ops_hash IS NOT NULL'
        range_args = ()

        if start_block_height and end_block_height:
            range_query += ' AND block_id >= ? AND block_id < ?'
            range_args += (start_block_height,end_block_height)

        query = 'SELECT block_id,ops_hash FROM snapshots' + range_query + ';'
        args = range_args

        rows = cls.db_query_execute(con, query, range_args, verbose=False)
        ret = {}
        block_min = None
        block_max = None

        for r in rows:
            ret[r['block_id']] = r['ops_hash']

            if block_min is None or block_min > r['block_id']:
                block_min = r['block_id']

            if block_max is None or block_max < r['block_id']:
                block_max = r['block_id']

        con.close()
        
        # sanity check
        if block_min is not None and block_max is not None:
            for i in range(block_min,block_max+1):
                oh = ret.get(i, None)

                assert oh is not None, 'Missing ops hash for {}'.format(i)
                assert isinstance(ret[i], (str,unicode)), 'ops hash for {} is type {}'.format(i, type(ret[i]))

        return ret


    def set_backup_frequency( self, backup_frequency ):
        """
        Set how many blocks between backups
        """
        self.backup_frequency = backup_frequency 


    def set_backup_max_age( self, backup_max_age ):
        """
        Set how old backups can be (in blocks)
        """
        self.backup_max_age = backup_max_age


    @classmethod
    def get_state_paths(cls, impl, working_dir):
        """
        Get the set of state paths that point to the current chain and state info.
        Returns a list of paths.
        """
        return [config.get_db_filename(impl, working_dir), config.get_snapshots_filename(impl, working_dir)]


    @classmethod 
    def get_backup_blocks(cls, impl, working_dir):
        """
        Get the set of block IDs that were backed up
        """
        ret = []
        backup_dir = config.get_backups_directory(impl, working_dir)
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
            backup_paths = cls.get_backup_paths(block_id, impl, working_dir)
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
    def get_backup_paths(cls, block_id, impl, working_dir):
        """
        Get the set of backup paths, given the virtualchain implementation module and block number
        """
        backup_dir = config.get_backups_directory(impl, working_dir)
        backup_paths = []
        for p in cls.get_state_paths(impl, working_dir):
            pbase = os.path.basename(p)
            backup_path = os.path.join( backup_dir, pbase + (".bak.%s" % block_id))
            backup_paths.append( backup_path )

        return backup_paths


    @classmethod
    def backup_restore(cls, block_id, impl, working_dir):
        """
        Restore from a backup, given the virutalchain implementation module and block number.
        NOT THREAD SAFE.  DO NOT CALL WHILE INDEXING.
        
        Return True on success
        Raise exception on error, i.e. if a backup file is missing
        """
        backup_dir = config.get_backups_directory(impl, working_dir)
        backup_paths = cls.get_backup_paths(block_id, impl, working_dir)
        for p in backup_paths:
            assert os.path.exists(p), "No such backup file: {}".format(p)

        for p in cls.get_state_paths(impl, working_dir):
            pbase = os.path.basename(p)
            backup_path = os.path.join(backup_dir, pbase + (".bak.{}".format(block_id)))
            log.debug("Restoring '{}' to '{}'".format(backup_path, p))
            shutil.copy(backup_path, p)
    
        return True


    def make_backups(self, block_id):
        """
        If we're doing backups on a regular basis, then 
        carry them out here if it is time to do so.
        This method does nothing otherwise.

        Return None on success
        Abort on failure
        """
        assert self.setup, "Not set up yet.  Call .db_setup() first!"

        # make a backup?
        if self.backup_frequency is not None:
            if (block_id % self.backup_frequency) == 0:

                backup_dir = config.get_backups_directory(self.impl, self.working_dir)
                if not os.path.exists(backup_dir):
                    try:
                        os.makedirs(backup_dir)
                    except Exception, e:
                        log.exception(e)
                        log.error("FATAL: failed to make backup directory '%s'" % backup_dir)
                        traceback.print_stack()
                        os.abort()

                for p in self.get_state_paths(self.impl, self.working_dir):
                    if os.path.exists(p):
                        try:
                            pbase = os.path.basename(p)
                            backup_path = os.path.join(backup_dir, pbase + (".bak.{}".format(block_id - 1)))

                            if not os.path.exists(backup_path):
                                rc = sqlite3_backup(p, backup_path)
                                if not rc:
                                    log.warning("Failed to back up as an SQLite db.  Falling back to /bin/cp")
                                    shutil.copy(p, backup_path)
                            else:
                                log.error("Will not overwrite '%s'" % backup_path)

                        except Exception, e:
                            log.exception(e)
                            log.error("FATAL: failed to back up '%s'" % p)
                            traceback.print_stack()
                            os.abort()

        return


    def clear_old_backups(self, block_id):
        """
        If we limit the number of backups we make, then clean out old ones
        older than block_id - backup_max_age (given in the constructor)
        This method does nothing otherwise.

        Return None on success
        Raise exception on error
        """
        assert self.setup, "Not set up yet.  Call .db_setup() first!"

        if self.backup_max_age is None:
            # never delete backups
            return 

        # find old backups 
        backup_dir = config.get_backups_directory(self.impl, self.working_dir)
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
   

    def save(self, block_id, consensus_hash, ops_hash, accepted_ops, virtualchain_ops_hints, backup=False):
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
        assert self.setup, "Not set up yet.  Call .db_setup() first!"
        assert len(accepted_ops) == len(virtualchain_ops_hints)

        if self.read_only:
            log.error("FATAL: StateEngine is read only")
            traceback.print_stack()
            os.abort()

        if block_id < self.lastblock:
            log.error("FATAL: Already processed up to block {} (got {})".format(self.lastblock, block_id))
            traceback.print_stack()
            os.abort()
        
        # ask the implementation to save 
        if hasattr(self.impl, 'db_save'):
            rc = False
            try:
                rc = self.impl.db_save(block_id, consensus_hash, ops_hash, accepted_ops, virtualchain_ops_hints, db_state=self.state)
            except Exception as e:
                log.exception(e)
                rc = False

            if not rc:
                log.error("FATAL: Implementation failed to save state at block {}".format(block_id))
                traceback.print_stack()
                os.abort()

        # save new chainstate
        self.lastblock = block_id

        # start a transaction to store the new data
        db_con = self.db_open(self.impl, self.working_dir)
        cur = db_con.cursor()

        self.db_query_execute(cur, "BEGIN", (), verbose=False)
        
        # add chainstate
        for i, (accepted_op, virtualchain_op_hints) in enumerate(zip(accepted_ops, virtualchain_ops_hints)):

            # unpack virtualchain hints
            senders = virtualchain_op_hints['virtualchain_senders']
            data_hex = virtualchain_op_hints['virtualchain_data_hex']
            tx_hex = virtualchain_op_hints['virtualchain_txhex']
            txid = virtualchain_op_hints['virtualchain_txid']
            fee = virtualchain_op_hints['virtualchain_fee']
            opcode = virtualchain_op_hints['virtualchain_opcode']
            txindex = virtualchain_op_hints['virtualchain_txindex']
            vtxindex = i
            merkle_path = virtualchain_op_hints['virtualchain_tx_merkle_path']

            vtx_data = {
                'txid': txid,
                'senders': simplejson.dumps(senders),
                'data_hex': data_hex,
                'tx_hex': tx_hex,
                'tx_merkle_path': merkle_path,
                'fee': fee,
                'opcode': opcode,
                'txindex': txindex,
                'vtxindex': vtxindex,
                'block_id': block_id
            }
            
            self.db_chainstate_append(cur, **vtx_data)
            
        # update snapshot info
        self.db_snapshot_append(cur, block_id, consensus_hash, ops_hash, int(time.time()))
        self.db_query_execute(cur, "END", (), verbose=False)
        db_con.close()

        # make new backups and clear old ones
        self.make_backups(block_id)
        self.clear_old_backups(block_id)
        
        # ask the implementation if we should continue
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
        return bin_hash160(merkle_root, True)[0:16].encode('hex')

  
    @classmethod 
    def make_ops_snapshot( cls, serialized_ops ):
        """
        Generate a deterministic hash over the sequence of (serialized) operations.
        """
        record_hashes = []
        for serialized_op in serialized_ops:
            record_hash = bin_double_sha256( serialized_op ).encode('hex')
            record_hashes.append(record_hash)

        if len(record_hashes) == 0:
            record_hashes.append(bin_double_sha256("").encode('hex'))

        # put records into their own Merkle tree, and mix the root with the consensus hashes.
        record_hashes.sort()
        record_merkle_tree = MerkleTree( record_hashes )
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
        all_hashes_merkle_tree = MerkleTree( all_hashes )
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

        Returns (consensus_hash, ops_hash)
        """
        record_root_hash = StateEngine.make_ops_snapshot( serialized_ops )
        log.debug("Snapshot('{}', {})".format(record_root_hash, prev_consensus_hashes))
        return (cls.make_snapshot_from_ops_hash( record_root_hash, prev_consensus_hashes ), record_root_hash)


    @classmethod
    def serialize_op( cls, opcode, opdata, opfields, verbose=True ):
        """
        Given an opcode (byte), associated data (dict), and the operation
        fields to serialize (opfields), convert it 
        into its canonical serialized form (i.e. in order to 
        generate a consensus hash.

        opdata is allowed to have extra fields.  They will be ignored

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
           log.error("Missing fields; dump follows:\n{}".format(simplejson.dumps( opdata, indent=4, sort_keys=True )))
           raise Exception("BUG: missing fields '{}'".format(",".join(missing)))

        if verbose:
            log.debug("SERIALIZE: {}:{}".format(opcode, ",".join(debug_all_values) ))

        field_values = ",".join( all_values )

        return opcode + ":" + field_values


    def snapshot(self, block_id, oplist):
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

        Returns (consensus hash, ops_hash)
        """
        
        assert self.setup, "Not set up yet.  Call .db_setup() first!"
        log.debug("Snapshotting block {}".format(block_id))
        
        serialized_ops = []
        for opdata in oplist:
            serialized_record = StateEngine.serialize_op(opdata['virtualchain_opcode'], opdata, self.opfields)
            serialized_ops.append( serialized_record )

        previous_consensus_hashes = []
        k = block_id
        i = 1
        while k - (2**i - 1) >= self.impl.get_first_block_id():
            prev_block = k - (2**i - 1)
            prev_ch = self.get_consensus_at(prev_block)
            log.debug("Snapshotting block %s: consensus hash of %s is %s" % (block_id, prev_block, prev_ch))

            if prev_ch is None:
                log.error("BUG: None consensus for %s" % prev_block )
                traceback.print_stack()
                os.abort()

            previous_consensus_hashes.append(prev_ch)
            i += 1

        consensus_hash, ops_hash = StateEngine.make_snapshot(serialized_ops, previous_consensus_hashes) 
        return consensus_hash, ops_hash
   

    @classmethod
    def set_virtualchain_field(cls, opdata, virtualchain_field, value):
        """
        Set a virtualchain field value.
        Used by implementations that generate extra consensus data at the end of a block
        """
        assert virtualchain_field in RESERVED_KEYS, 'Invalid field name {} (choose from {})'.format(virtualchain_field, ','.join(RESERVED_KEYS))
        opdata[virtualchain_field] = value
  

    def parse_transaction(self, block_id, tx):
        """
        Given a block ID and an data-bearing transaction, 
        try to parse it into a virtual chain operation.
        
        Use the implementation's 'db_parse' method to do so.

        Data transactions that do not have the magic bytes or a valid opcode
        will be skipped automatically.  The db_parse method does not need
        to know how to handle them.

        @tx is a dict with
        `txid`: the transaction ID
        `txindex`: the offset in the block where this tx occurs
        `nulldata`: the hex-encoded scratch data from the transaction
        `ins`: the list of transaction inputs
        `outs`: the list of transaction outputs
        `senders`: the list of transaction senders
        `fee`: the transaction fee
        `txhex`: the hex-encoded raw transaction
        
        Return a dict representing the data on success.
        Return None on error
        """
        
        data_hex = tx['nulldata']
        inputs = tx['ins']
        outputs = tx['outs']
        senders = tx['senders']
        fee = tx['fee']
        txhex = tx['hex']
        merkle_path = tx['tx_merkle_path']
        
        if not is_hex(data_hex):
            # should always work; the tx downloader converts the binary string to hex
            # not a valid hex string 
            raise ValueError("Invalid nulldata: not hex-encoded")
        
        if len(data_hex) % 2 != 0:
            # should always work; the tx downloader converts the binary string to hex
            # not valid hex string 
            raise ValueError("Invalid nulldata: not hex-encoded")
        
        data_bin = None
        try:
            # should always work; the tx downloader converts the binary string to hex
            data_bin = data_hex.decode('hex')
        except Exception, e:
            log.error("Failed to parse transaction: %s (data_hex = %s)" % (tx, data_hex))
            raise ValueError("Invalid nulldata: not hex-encoded")
        
        if not data_bin.startswith(self.magic_bytes):
            # not for us
            return None
        
        if len(data_bin) < len(self.magic_bytes) + 1:
            # invalid operation--no opcode
            return None

        # 3rd byte is always the operation code
        op_code = data_bin[len(self.magic_bytes)]
        if op_code not in self.opcodes:
            return None 
        
        # looks like an op.  Try to parse it.
        op_payload = data_bin[len(self.magic_bytes)+1:]
        
        op = self.impl.db_parse(block_id, tx['txid'], tx['txindex'], op_code, op_payload, senders, inputs, outputs, fee, db_state=self.state, raw_tx=txhex)
        if op is None:
            # not valid 
            return None 
        
        # store it
        op['virtualchain_opcode'] = op_code
        op['virtualchain_txid'] = tx['txid']
        op['virtualchain_txindex'] = tx['txindex']
        op['virtualchain_txhex'] = txhex
        op['virtualchain_tx_merkle_path'] = merkle_path
        op['virtualchain_senders'] = senders
        op['virtualchain_fee'] = fee
        op['virtualchain_data_hex'] = op_payload.encode('hex')
        
        return op
   
   
    def parse_block(self, block_id, txs):
        """
        Given the sequence of transactions in a block, turn them into a
        sequence of virtual chain operations.

        Return the list of successfully-parsed virtualchain transactions
        """
        ops = []
        for i in range(0,len(txs)):
            tx = txs[i]
            op = self.parse_transaction(block_id, tx)
            if op is not None:
                ops.append( op )
            
        return ops
   
   
    def remove_reserved_keys(self, op):
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
  

    def sanitize_op(self, op):
        """
        Remove and return the non-virtualchain-reserved keywords
        from an op.
        """
        return self.remove_reserved_keys(op)[0]


    def log_accept(self, block_id, vtxindex, opcode, op_data):
        """
        Log an accepted operation
        """
        log.debug("ACCEPT op {} at ({}, {}) ({})".format(opcode, block_id, vtxindex, json.dumps(op_data, sort_keys=True)))


    def log_reject(self, block_id, vtxindex, opcode, op_data):
        """
        Log a rejected operation
        """
        log.debug("REJECT op {} ({})".format(opcode, json.dumps(op_data, sort_keys=True)))
 

    def process_ops(self, block_id, ops):
        """
        Given a transaction-ordered sequence of parsed operations,
        check their validity and give them to the state engine to 
        affect state changes.

        It calls 'db_check' to validate each operation, and 'db_commit'
        to add it to the state engine.  Gets back a list of state
        transitions (ops) to snapshot.

        Returns a defaultdict with the following fields:
        'virtualchain_ordered':  the list of operations committed by the implementation (where each operation is a dict of fields)
        'virtualchain_all_ops':  this is ops, plus a list containing the "final" operations returned by the implementation in response to the 'virtualchain_final' hint
        'virtualchain_final':  this is the list of final operations returned by the implementation in response to the 'virtualchain_final' hint.

        Aborts on error
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
        # NOTE: these will be different objects in memory from the objects passed into db_check
        initial_scan = []
        for i in xrange(0, len(ops)):

            op_data = ops[i]
            op_sanitized, _ = self.remove_reserved_keys( op_data )
            initial_scan.append( copy.deepcopy( op_sanitized ) )

        # allow the implementation to do a pre-scan of the set of ops 
        # (e.g. in Blockstack, this gets used to find name registration collisions)
        if hasattr(self.impl, "db_scan_block"):
            self.impl.db_scan_block( block_id, initial_scan, db_state=self.state )
        else:
            log.debug("Compat: no db_scan_block")

        # check each operation 
        for i in range(0, len(ops)):
            op_data = ops[i]
            op_sanitized, reserved = self.remove_reserved_keys( op_data )
            opcode = reserved['virtualchain_opcode']

            # check this op
            rc = self.impl.db_check(block_id, new_ops, opcode, op_sanitized, reserved['virtualchain_txid'], reserved['virtualchain_txindex'], to_commit_sanitized, db_state=self.state)
            if rc:

                # commit this op
                new_op_list = self.impl.db_commit(block_id, opcode, op_sanitized, reserved['virtualchain_txid'], reserved['virtualchain_txindex'], db_state=self.state)
                if type(new_op_list) != list:
                    new_op_list = [new_op_list]

                for new_op in new_op_list:
                    if new_op is not None:
                        if type(new_op) == dict:

                            # externally-visible state transition 
                            to_commit_sanitized_op = copy.deepcopy( new_op )
                            to_commit_sanitized.append( to_commit_sanitized_op )

                            new_op.update( reserved )
                            new_ops[opcode].append( new_op )
                            new_ops['virtualchain_ordered'].append( new_op )

                        else:
                            # internal state transition 
                            continue

            else:
                self.log_reject( block_id, reserved['virtualchain_txindex'], opcode, copy.deepcopy(op_sanitized))

        
        # final commit hint.
        # the implementation has a chance here to feed any extra data into the consensus hash with this call
        # (e.g. to affect internal state transitions that occur as seconary, holistic consequences to the sequence
        # of prior operations for this block).
        final_ops = self.impl.db_commit( block_id, 'virtualchain_final', {'virtualchain_ordered': new_ops['virtualchain_ordered']}, None, None, db_state=self.state )
        if final_ops is not None:
            # make sure each one has all the virtualchain reserved fields
            for i in range(0, len(final_ops)):
                for fieldname in RESERVED_FIELDS:
                    assert fieldname in final_ops[i], 'Extra consensus operation at offset {} is missing {}'.format(i, fieldname)

            new_ops['virtualchain_final'] = final_ops
            new_ops['virtualchain_ordered'] += final_ops
            new_ops['virtualchain_all_ops'] += final_ops

        return new_ops
    
    
    def process_block(self, block_id, ops, backup=False, expected_snapshots=None):
        """
        Top-level block processing method.
        Feed the block and its data transactions 
        through the implementation, to build up the 
        implementation's state.  Cache the 
        resulting data to disk.
       
        Return the (consensus hash, ops hash) for this block on success.
        Exit on failure.
        """
        
        log.debug("Process block {} ({} virtual transactions)".format(block_id, len(ops)))

        if expected_snapshots is None:
            expected_snapshots = self.expected_snapshots
        if expected_snapshots is None:
            expected_snapshots = {}
        
        new_ops = self.process_ops(block_id, ops)
        consensus_hash, ops_hash = self.snapshot(block_id, new_ops['virtualchain_ordered'])

        # sanity check against a known sequence of consensus hashes
        if block_id in expected_snapshots:
            log.debug("Expecting CONSENSUS({}) == {}".format(block_id, expected_snapshots[block_id]))
            if expected_snapshots[block_id] != consensus_hash:
                log.error("FATAL: consensus hash mismatch at height {}: {} != {}".format(block_id, expected_snapshots[block_id], consensus_hash))
                traceback.print_stack()
                os.abort()
        
        # remove virtualchain-reserved keys
        sanitized_ops = []
        virtualchain_ops_hints = []
        for opdata in new_ops['virtualchain_ordered']:
            op_sanitized, op_reserved = self.remove_reserved_keys(opdata)
            sanitized_ops.append(op_sanitized)
            virtualchain_ops_hints.append(op_reserved)

        # save state for this block
        rc = self.save(block_id, consensus_hash, ops_hash, sanitized_ops, virtualchain_ops_hints, backup=backup)
        if not rc:
            # implementation requests early termination 
            log.debug("Early indexing termination at {}".format(block_id))
            return None

        # store statistics if we're in test mode 
        if os.environ.get("BLOCKSTACK_TEST"):
            global STATISTICS
            STATISTICS[block_id] = {
                'consensus_hash': consensus_hash,
                'num_parsed_ops': len(ops),
                'num_processed_ops': len(new_ops['virtualchain_ordered']),
                'ops_hash': ops_hash,
                'backup': backup,
            }

        return consensus_hash

    
    @classmethod
    def get_block_statistics(cls, block_id):
        """
        Get block statistics.
        Only works in test mode.
        """
        if not os.environ.get("BLOCKSTACK_TEST"):
            raise Exception("This method is only available in the test framework")

        global STATISTICS
        return STATISTICS.get(block_id)


    @classmethod
    def build( cls, blockchain_opts, end_block_id, state_engine, expected_snapshots={}, tx_filter=None ):
        """
        Top-level call to process all blocks in the blockchain.
        Goes and fetches all data-bearing transactions in order,
        and feeds them into the state engine implementation.
        
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
            log.debug("Up-to-date ({} >= {})".format(first_block_id, end_block_id))
            return True 

        rc = True
        batch_size = config.BLOCK_BATCH_SIZE
        log.debug("Sync virtualchain state from {} to {}".format(first_block_id, end_block_id))
        
        for block_id in range( first_block_id, end_block_id+1, batch_size ):
            
            if not rc:
                break 
           
            last_block_id = min(block_id + batch_size, end_block_id)

            # get the blocks and transactions from the underlying blockchain
            block_ids_and_txs = transactions.get_virtual_transactions(state_engine.impl.get_blockchain(), blockchain_opts, block_id, last_block_id, tx_filter=tx_filter, spv_last_block=end_block_id - 1)
            if block_ids_and_txs is None:
                raise Exception("Failed to get virtual transactions {} to {}".format(block_id, last_block_id))

            # process in order by block ID
            block_ids_and_txs.sort()
            for processed_block_id, txs in block_ids_and_txs:

                if state_engine.get_consensus_at(processed_block_id) is not None:
                    raise Exception("Already processed block %s (%s)" % (processed_block_id, state_engine.get_consensus_at( processed_block_id )) )
                
                cls.db_set_indexing(True, state_engine.impl, state_engine.working_dir)

                ops = state_engine.parse_block(processed_block_id, txs)
                consensus_hash = state_engine.process_block(processed_block_id, ops, expected_snapshots=expected_snapshots)

                cls.db_set_indexing(False, state_engine.impl, state_engine.working_dir)
                
                if consensus_hash is None:
                    # request to stop
                    rc = False
                    log.debug("Stopped processing at block %s" % processed_block_id)
                    break

                log.debug("CONSENSUS({}): {}".format(processed_block_id, state_engine.get_consensus_at(processed_block_id)))

                # sanity check, if given 
                expected_consensus_hash = state_engine.get_expected_consensus_at( processed_block_id )
                if expected_consensus_hash is not None:
                    if str(consensus_hash) != str(expected_consensus_hash):
                        rc = False
                        log.error("FATAL: DIVERGENCE DETECTED AT {}: {} != {}".format(processed_block_id, consensus_hash, expected_consensus_hash))
                        traceback.print_stack()
                        os.abort()
       
            if not rc:
                break
        
        log.debug("Last block is %s" % state_engine.lastblock )
        return rc
    
   
    def get_consensus_at(self, block_id):
        """
        Get the consensus hash at a given block.
        Return the consensus hash if we have one for this block.
        Return None if we don't
        """
        query = 'SELECT consensus_hash FROM snapshots WHERE block_id = ?;'
        args = (block_id,)

        con = self.db_open(self.impl, self.working_dir)
        rows = self.db_query_execute(con, query, args, verbose=False)
        res = None

        for r in rows:
            res = r['consensus_hash']

        con.close()
        return res


    def get_ops_hash_at(self, block_id):
        """
        Get the ops hash at a given block
        """
        query = 'SELECT ops_hash FROM snapshots WHERE block_id = ?;'
        args = (block_id,)

        con = self.db_open(self.impl, self.working_dir)
        rows = self.db_query_execute(con, query, args, verbose=False)
        res = None

        for r in rows:
            res = r['ops_hash']

        con.close()
        return res


    def get_expected_consensus_at( self, block_id ):
        """
        Get the expected consensus hash at a given block
        """
        return self.expected_snapshots.get(block_id, None)


    def get_block_from_consensus( self, consensus_hash ):
        """
        Get the block number with the given consensus hash.
        Return None if there is no such block.
        """
        query = 'SELECT block_id FROM snapshots WHERE consensus_hash = ?;'
        args = (consensus_hash,)

        con = self.db_open(self.impl, self.working_dir)
        rows = self.db_query_execute(con, query, args, verbose=False)
        res = None

        for r in rows:
            res = r['block_id']

        con.close()
        return res


    def get_valid_consensus_hashes( self, block_id ):
        """
        Get the list of valid consensus hashes for a given block.
        """
        first_block_to_check = block_id - self.impl.get_valid_transaction_window()

        query = 'SELECT consensus_hash FROM snapshots WHERE block_id >= ? AND block_id <= ?;'
        args = (first_block_to_check,block_id)

        valid_consensus_hashes = []
        
        con = self.db_open(self.impl, self.working_dir)
        rows = self.db_query_execute(con, query, args, verbose=False)

        for r in rows:
            assert r['consensus_hash'] is not None
            assert isinstance(r['consensus_hash'], (str,unicode))

            valid_consensus_hashes.append(str(r['consensus_hash']))

        con.close()
        return valid_consensus_hashes
    
    
    def get_current_consensus(self):
        """
        Get the current consensus hash.
        """
        return self.get_consensus_at(self.lastblock)


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
        return str(consensus_hash) in self.get_valid_consensus_hashes(block_id)
    

def get_blockchain_height(blockchain_name, blockchain_client):
    """
    Get the height of the blockchain
    Return the height as a positive int on success
    Raise on error
    """
    if blockchain_name == 'bitcoin':
        return get_bitcoin_blockchain_height(blockchain_client)
    else:
        raise ValueError("Unrecognized blockchain {}".format(blockchain_name))


def get_index_range(blockchain_name, blockchain_client, impl, working_dir):
    """
    Get the range of block numbers that we need to fetch from the blockchain.
    Requires virtualchain to have been configured with setup_virtualchain() if impl=None
    
    Return None, None if we fail to connect to the blockchain
    """

    start_block = config.get_first_block_id(impl)
    try:
        current_block = get_blockchain_height(blockchain_name, blockchain_client)
    except Exception, e:
        log.exception(e)
        return None, None

    saved_block = StateEngine.get_lastblock(impl, working_dir)

    if saved_block is None:
        saved_block = 0
    elif saved_block == current_block:
        start_block = saved_block
    elif saved_block < current_block:
        start_block = saved_block + 1

    return start_block, current_block


def sqlite3_find_tool():
    """
    Find the sqlite3 binary
    Return the path to the binary on success
    Return None on error
    """

    # find sqlite3
    path = os.environ.get("PATH", None)
    if path is None:
        path = "/usr/local/bin:/usr/bin:/bin"

    sqlite3_path = None
    dirs = path.split(":")
    for pathdir in dirs:
        if len(pathdir) == 0:
            continue

        sqlite3_path = os.path.join(pathdir, 'sqlite3')
        if not os.path.exists(sqlite3_path):
            continue

        if not os.path.isfile(sqlite3_path):
            continue

        if not os.access(sqlite3_path, os.X_OK):
            continue

        break

    if sqlite3_path is None:
        log.error("Could not find sqlite3 binary")
        return None

    return sqlite3_path


def sqlite3_backup(src_path, dest_path):
    """
    Back up a sqlite3 database, while ensuring
    that no ongoing queries are being executed.

    Return True on success
    Return False on error.
    """

    # find sqlite3
    sqlite3_path = sqlite3_find_tool()
    if sqlite3_path is None:
        log.error("Failed to find sqlite3 tool")
        return False

    sqlite3_cmd = [sqlite3_path, '{}'.format(src_path), '.backup "{}"'.format(dest_path)]
    rc = None
    backoff = 1.0

    out = None
    err = None

    try:
        while True:
            log.debug("{}".format(" ".join(sqlite3_cmd)))
            p = subprocess.Popen(sqlite3_cmd, shell=False, close_fds=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = p.communicate()
            rc = p.wait()

            if rc != 0:
                if "database is locked" in out.lower() or "database is locked" in err.lower():
                    # try again
                    log.error("Database {} is locked; trying again in {} seconds".format(src_path, backoff))
                    time.sleep(backoff)
                    backoff += 2 * backoff + random.random() * random.randint(0, int(backoff))
                    continue

                elif 'is not a database' in out.lower() or 'is not a database' in err.lower():
                    # not a valid sqlite3 file
                    log.error("File {} is not a SQLite database".format(src_path))
                    return False
 
            else:
                break

    except Exception, e:
        log.exception(e)
        return False

    if not os.WIFEXITED(rc):
        # bad exit 
        # failed for some other reason
        log.error("Backup failed: out='{}', err='{}', rc={}".format(out, err, rc))
        return False
    
    if os.WEXITSTATUS(rc) != 0:
        # bad exit
        log.error("Backup failed: out='{}', err='{}', exit={}".format(out, err, os.WEXITSTATUS(rc)))
        return False

    return True


def state_engine_replay_block(existing_state_engine, new_state_engine, block_height, expected_snapshots={}):
    """
    Extract the existing chain state transactions from the existing state engine at a particular block height,
    parse them using the new state engine, and process them using the new state engine.

    Returns the consensus hash of the block on success.
    """
    
    assert new_state_engine.lastblock + 1 == block_height, 'Block height mismatch: {} + 1 != {}'.format(new_state_engine.lastblock, block_height)

    db_con = StateEngine.db_open(existing_state_engine.impl, existing_state_engine.working_dir)
    chainstate_block = existing_state_engine.db_chainstate_get_block(db_con, block_height)
    db_con.close()

    log.debug("{} transactions accepted at block {} in chainstate {}; replaying in {}".format(len(chainstate_block), block_height, existing_state_engine.working_dir, new_state_engine.working_dir))

    parsed_txs = dict([(txdata['txid'], transactions.tx_parse(txdata['tx_hex'], blockchain=existing_state_engine.impl.get_blockchain())) for txdata in chainstate_block])
    txs = [
        {
            'txid': txdata['txid'],
            'txindex': txdata['txindex'],
            'nulldata': '{}{}{}'.format(existing_state_engine.impl.get_magic_bytes().encode('hex'), txdata['opcode'].encode('hex'), txdata['data_hex']),
            'ins': parsed_txs[txdata['txid']]['ins'],
            'outs': parsed_txs[txdata['txid']]['outs'],
            'senders': txdata['senders'],
            'fee': txdata['fee'],
            'hex': txdata['tx_hex'],
            'tx_merkle_path': txdata['tx_merkle_path'],
        }
        for txdata in chainstate_block]

    new_state_engine.db_set_indexing(True, new_state_engine.impl, new_state_engine.working_dir)

    ops = new_state_engine.parse_block(block_height, txs)
    consensus_hash = new_state_engine.process_block(block_height, ops, expected_snapshots=expected_snapshots)

    new_state_engine.db_set_indexing(False, new_state_engine.impl, new_state_engine.working_dir)

    return consensus_hash


def state_engine_replay(consensus_impl, existing_working_dir, new_state_engine, target_block_height, start_block=None, initial_snapshots={}, expected_snapshots={}):
    """
    Given consensus rules, a target block height, and a path to an existing chainstate db, replay the chain state's virtual transactions
    through the consensus rules into a given directory (working_dir).

    Optionally check that the snapshots in @expected_snapshots match up as we verify.
    @expected_snapshots maps str(block_height) to str(consensus hash)

    Return the consensus hash calculated at the target block height
    Return None on verification failure (i.e. we got a different consensus hash than one for the same block in expected_snapshots)
    """
    
    assert hasattr(consensus_impl, 'get_opcodes')
    assert hasattr(consensus_impl, 'get_magic_bytes')
    assert hasattr(consensus_impl, 'get_opfields')
    assert hasattr(consensus_impl, 'get_first_block_id')

    consensus_opcodes = consensus_impl.get_opcodes()
    consensus_magic_bytes = consensus_impl.get_magic_bytes()
    consensus_opfields = consensus_impl.get_opfields()

    existing_state_engine = StateEngine(consensus_impl, existing_working_dir)
    
    # set up existing state engine 
    rc = existing_state_engine.db_setup()
    if not rc:
        # do not touch the existing db
        raise Exception("Existing state in {} is unusable or corrupt".format(os.path.dirname(existing_working_dir)))

    if start_block is None:
        # maybe we're resuming?
        start_block = new_state_engine.get_lastblock(new_state_engine.impl, new_state_engine.working_dir)
        if start_block is None:
            # starting from scratch
            start_block = consensus_impl.get_first_block_id()

    log.debug("Rebuilding database from {} to {}".format(start_block, target_block_height))

    consensus_hashes = {}
    for block_height in range(start_block, target_block_height+1):
        
        # recover virtualchain transactions from the existing db and feed them into the new db
        consensus_hash = state_engine_replay_block(existing_state_engine, new_state_engine, block_height, expected_snapshots=expected_snapshots)

        log.debug("VERIFY CONSENSUS({}): {}".format(block_height, consensus_hash))
        consensus_hashes[block_height] = consensus_hash

        if block_height in expected_snapshots:
            if expected_snapshots[block_height] != consensus_hash:
                log.error("DATABASE IS NOT CONSISTENT AT {}: {} != {}".format(block_height, expected_snapshots[block_height], consensus_hash))
                return None

    # final consensus hash
    return consensus_hashes[target_block_height]


def state_engine_verify(trusted_consensus_hash, consensus_block_height, consensus_impl, untrusted_working_dir, new_state_engine, start_block=None, expected_snapshots={}):
    """
    Verify that a database is consistent with a
    known-good consensus hash.

    This algorithm works by creating a new database,
    parsing the untrusted database, and feeding the untrusted
    operations into the new database block-by-block.  If we
    derive the same consensus hash, then we can trust the
    database.

    Return True if consistent with the given consensus hash at the given consensus block height
    Return False if not
    """
    
    assert hasattr(consensus_impl, 'get_initial_snapshots')

    final_consensus_hash = state_engine_replay(consensus_impl, untrusted_working_dir, new_state_engine, consensus_block_height, \
                                               start_block=start_block, initial_snapshots=consensus_impl.get_initial_snapshots(), expected_snapshots=expected_snapshots)

    # did we reach the consensus hash we expected?
    if final_consensus_hash is not None and final_consensus_hash == trusted_consensus_hash:
        return True

    else:
        log.error("Unverifiable database state stored in '{}': {} != {}".format(untrusted_working_dir, final_consensus_hash, trusted_consensus_hash))
        return False


