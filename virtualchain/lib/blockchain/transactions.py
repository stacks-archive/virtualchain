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

from .nulldata import get_nulldata, has_nulldata
import traceback

import sys 

try:
   from ..config import MULTIPROCESS_RPC_RETRY
   from ..workpool import multiprocess_bitcoind, multiprocess_batch_size, multiprocess_rpc_marshal, multiprocess_bitcoind_opts, Workpool
except:
   # running as worker subprocess
   from virtualchain.lib.config import MULTIPROCESS_RPC_RETRY
   from virtualchain.lib.workpool import multiprocess_bitcoind, multiprocess_batch_size, multiprocess_rpc_marshal, multiprocess_bitcoind_opts, Workpool

import logging
import os
import time
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

from bitcoinrpc.authproxy import JSONRPCException

import session
log = session.get_logger("virtualchain")

def get_bitcoind( bitcoind_or_opts ):
   """
   Given either a bitcoind API endpoint proxy, 
   or a dictionary of options to generate one in a
   process-local context, return a bitcoind API endpoint 
   proxy.
   """ 
   
   if type(bitcoind_or_opts) == types.DictType or bitcoind_or_opts is None:

      # instantiate from options
      if bitcoind_or_opts is None:
          bitcoind_or_opts = multiprocess_bitcoind_opts()

      return multiprocess_bitcoind( bitcoind_or_opts )
   
   else:
      # already an endpoint 
      return bitcoind_or_opts
   
   
def get_bitcoind_opts( bitcoind_or_opts ):
   """
   Given either a bitcoind API endpoint proxy,
   or a dict of options, generate the set of options.
   """
   if bitcoind_or_opts is None:
      return None 
   
   if type(bitcoind_or_opts) == types.DictType:
      return bitcoind_or_opts
   
   else:
      return bitcoind_or_opts.opts 
   

def indexer_rpc_dispatch( method_name, method_args ):
   """
   Worker subprocess: dispatch a method call from the 
   main indexer process and get the result.
   """

   if method_name == "getrawtransaction":

       if len(method_args) != 3:
           log.error("getrawtransaction: Invalid argument list")
           return {"error": "getrawtransaction: Invalid argument list"}

       result = getrawtransaction( method_args[0], method_args[1], verbose=method_args[2] )
 
   elif method_name == "getblockhash":
       
       if len(method_args) != 3:
           log.error("getblockhash: Invalid argument list")
           return {"error": "getblockhash: Invalid argument list"}

       result = getblockhash( method_args[0], method_args[1], reset=method_args[2] )

   elif method_name == "getblock":
       
       if len(method_args) != 2:
           log.error("getblock: Invalid argument list")
           return {"error": "getblock: Invalid argument list"}

       result = getblock( method_args[0], method_args[1] )

   else:

       log.error("Unrecognized method")
       return {"error": "Unrecognized method"}

   return result


def getrawtransaction( bitcoind_or_opts, txid, verbose=0 ):
   """
   Get a raw transaction by txid.
   Only call out to bitcoind if we need to.
   """
   
   exc_to_raise = None
   bitcoind = get_bitcoind( bitcoind_or_opts )

   if bitcoind is None and bitcoind_or_opts is None:
       raise Exception("No bitcoind or opts given")
   
   for i in xrange(0, MULTIPROCESS_RPC_RETRY):
      try:
         
         try:
            
            tx = bitcoind.getrawtransaction( txid, verbose )
            
         except JSONRPCException, je:
            log.error("\n\n[%s] Caught JSONRPCException from bitcoind: %s\n" % (os.getpid(), repr(je.error)))
            exc_to_raise = je
            
            bitcoind = multiprocess_bitcoind( bitcoind.opts, reset=True)
            continue

         except Exception, e:
            log.error("\n\n[%s] Caught Exception from bitcoind: %s" % (os.getpid(), repr(e)))
            exc_to_raise = e
        
            bitcoind = multiprocess_bitcoind( bitcoind.opts, reset=True)
            continue 
            
         return tx 
      
      except Exception, e:
         log.exception(e)
         exc_to_raise = e 
         continue

   if exc_to_raise is not None:
      # tried as many times as we dared, so bail 
      raise exc_to_raise
   
   else:
      raise Exception("Failed after %s attempts" % MULTIPROCESS_RPC_RETRY)



def getrawtransaction_async( workpool, bitcoind_opts, tx_hash, verbose ):
   """
   Get a block transaction, asynchronously, using the pool of processes
   to go get it.
   """

   payload = multiprocess_rpc_marshal( "getrawtransaction", [None, tx_hash, verbose] )

   # log.debug("getrawtransaction_async %s" % tx_hash)
   tx_future = workpool.apply_async( payload )

   return tx_future


def getblockhash( bitcoind_or_opts, block_number, reset ):
   """
   Get a block's hash, given its ID.
   Return None if there are no options
   """
  

   exc_to_raise = None  # exception to raise if we fail
   bitcoind = get_bitcoind( bitcoind_or_opts )
   
   if not reset and bitcoind is None and bitcoind_or_opts is None:
       raise Exception("No bitcoind or opts given")
       
   if reset:
       new_opts = get_bitcoind_opts( bitcoind_or_opts )
       bitcoind = multiprocess_bitcoind( new_opts, reset=True )
   
   for i in xrange(0, MULTIPROCESS_RPC_RETRY):
      try:
         
         try:
         
            block_hash = bitcoind.getblockhash( block_number )
         except JSONRPCException, je:
            log.error("\n\n[%s] Caught JSONRPCException from bitcoind: %s\n" % (os.getpid(), repr(je.error)))
            exc_to_raise = je 
        
            bitcoind = multiprocess_bitcoind( bitcoind.opts, reset=True)
            continue
         
         except Exception, e:
            log.error("\n\n[%s] Caught Exception from bitcoind: %s" % (os.getpid(), repr(e)))
            exc_to_raise = e
            
            bitcoind = multiprocess_bitcoind( bitcoind.opts, reset=True)
            continue 
         
         return block_hash
      
      except Exception, e:
         log.exception(e)
         exc_to_raise = e
         continue
   
   if exc_to_raise is not None:
      raise exc_to_raise
   
   else:
      raise Exception("Failed after %s attempts" % MULTIPROCESS_RPC_RETRY)
   

def getblockhash_async( workpool, bitcoind_opts, block_number, reset=False ):
   """
   Get a block's hash, asynchronously, given its ID
   Return a future to the block hash 
   """
 
   payload = multiprocess_rpc_marshal( "getblockhash", [None, block_number, reset] )

   log.debug("Get block hash for %s" % block_number)
   block_hash_future = workpool.apply_async( payload )
   
   return block_hash_future


def getblock( bitcoind_or_opts, block_hash ):
   """
   Get a block's data, given its hash.
   """
   
   bitcoind = get_bitcoind( bitcoind_or_opts )
   if bitcoind is None and bitcoind_or_opts is None:
       raise Exception("No bitcoind or opts given")
    
   exc_to_raise = None
   bitcoind = get_bitcoind( bitcoind_or_opts )
   attempts = 0
   
   for i in xrange(0, MULTIPROCESS_RPC_RETRY):
      
      try:
         block_data = bitcoind.getblock( block_hash )
         
      except JSONRPCException, je:
         log.error("\n\n[%s] Caught JSONRPCException from bitcoind: %s\n" % (os.getpid(), repr(je.error)))
         exc_to_raise = je
     
         attempts += 1
         
         # probably a transient bitcoind failure
         # exponential backof with jitter
         time.sleep(2**attempts + random.randint( 0, 2**(attempts - 1)) )
         
         bitcoind = multiprocess_bitcoind( bitcoind.opts, reset=True)
         continue
     
      except Exception, e:
         log.error("\n\n[%s] Caught Exception from bitcoind: %s" % (os.getpid(), repr(e)))
         exc_to_raise = e
     
         attempts += 1
         
         # probably a transient network failure
         # exponential backoff with jitter
         time.sleep(2**attempts + random.randint( 0, 2**(attempts - 1)) )
         
         bitcoind = multiprocess_bitcoind( bitcoind.opts, reset=True)
         continue
   
      return block_data 
      
   if exc_to_raise is not None:
      raise exc_to_raise
   
   else:
      raise Exception("Failed after %s attempts" % MULTIPROCESS_RPC_RETRY)
   


def getblock_async( workpool, bitcoind_opts, block_hash ):
   """
   Get a block's data, given its hash.
   Return a future to the data.
   """

   payload = multiprocess_rpc_marshal( "getblock", [None, block_hash] )

   log.debug("Get block %s" % block_hash)
   block_future = workpool.apply_async( payload )
   return block_future 


def get_sender_and_amount_in_from_txn( tx, output_index ):
   """
   Given a transaction, get information about the sender 
   and the money paid.
   
   Return a sender (a dict with a script_pubkey, amount, and list of addresses
   within the script_pubkey), and the amount paid.
   """
   
   # grab the previous tx output (the current input)
   try:
      prev_tx_output = tx['vout'][output_index]
   except Exception, e:
      print >> sys.stderr, "output_index = '%s'" % output_index
      raise e

   # make sure the previous tx output is valid
   if not ('scriptPubKey' in prev_tx_output and 'value' in prev_tx_output):
      return (None, None)

   # extract the script_pubkey
   script_pubkey = prev_tx_output['scriptPubKey']
   
   # build and append the sender to the list of senders
   amount_in = int(prev_tx_output['value']*10**8)
   sender = {
      "script_pubkey": script_pubkey.get('hex'),
      "script_type": script_pubkey.get('type'),
      "amount": amount_in,
      "addresses": script_pubkey.get('addresses')
   }
   
   return sender, amount_in


def get_total_out(outputs):
    total_out = 0
    # analyze the outputs for the total amount out
    for output in outputs:
        amount_out = int(output['value']*10**8)
        total_out += amount_out
    return total_out
 

def process_nulldata_tx_async( workpool, bitcoind_opts, tx ):
    """
    Given a transaction and a block hash, begin fetching each 
    of the transaction's vin's transactions.  The reason being,
    we want to acquire each input's nulldata, and for that, we 
    need the raw transaction data for the input.
    
    However, in order to preserve the (sender, tx) relation, we need to 
    preserve the order in which the input transactions occurred.
    To do so, we tag each future with the index into the transaction's 
    vin list, so once the futures have been finalized, we'll have an 
    ordered list of input transactions that is in the same order as 
    they are in the given transaction's vin.
    
    Returns: [(input_idx, tx_fut, tx_output_index)]
    """
    
    tx_futs = []
    senders = []
    total_in = 0
    
    if not ('vin' in tx and 'vout' in tx and 'txid' in tx):
        return None

    inputs = tx['vin']
    
    for i in xrange(0, len(inputs)):
      input = inputs[i]
      
      # make sure the input is valid
      if not ('txid' in input and 'vout' in input):
         continue
      
      # get the tx data for the specified input
      tx_hash = input['txid']
      tx_output_index = input['vout']
      
      tx_fut = getrawtransaction_async( workpool, bitcoind_opts, tx_hash, 1 )
      tx_futs.append( (i, tx_fut, tx_output_index) )
    
    return tx_futs 


def future_next( fut_records, fut_inspector ):
   """
   Find and return a record in a list of records, whose 
   contained future (obtained by the callable fut_inspector)
   is ready and has data to be gathered.
   
   If no such record exists, then select one and block on it
   until its future has data.
   """
   
   if len(fut_records) == 0:
      return None 
  
   
   for fut_record in fut_records:
      fut = fut_inspector( fut_record )
      if fut is not None:
         if fut.ready():
            fut_records.remove( fut_record )
            return fut_record 
   
   # no ready futures.  wait for one
   i = 0
   while True:
       fut_record = fut_records[i % len(fut_records)]
       i += 1

       fut = fut_inspector( fut_record )
       if fut is not None:

          # block...
          fut.wait( 0.1 )
          fut_records.remove( fut_record )
          return fut_record 
   

def future_get_result( fut, timeout ):
   """
   Get the *unpickled* result of a future
   """
   result = fut.get( timeout )
   return pickle.loads( result )


def get_block_goodput( block_data ):
   """
   Find out how much goodput data is present in a block's data
   """
   if block_data is None:
      return 0
   
   sum( [len(h) for h in block_data] )
   

def bandwidth_record( total_time, block_data ):
   return {
      "time":  total_time,
      "size":  get_block_goodput( block_data )
   }


def tx_is_coinbase( tx ):
    """
    Is a transaction a coinbase transaction?
    """
    for inp in tx['vin']:
        if 'coinbase' in inp.keys():
            return True 

    return False


def tx_to_hex( tx ):
     """
     Convert a bitcoin-given transaction into its hex string.
     Does NOT work on coinbase transactions.
     """
     tx_ins = []
     tx_outs = []
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


def tx_verify( tx, tx_hash ):
    """
    Confirm that a bitcoin transaction has the given hash.
    """
    tx_serialized = tx_to_hex( tx )
    tx_reversed_bin_hash = pybitcoin.bin_double_sha256( binascii.unhexlify(tx_serialized) )
    tx_candidate_hash = binascii.hexlify(tx_reversed_bin_hash[::-1])

    if tx_hash != tx_candidate_hash:
        print tx_serialized

    return tx_hash == tx_candidate_hash


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
    a block returned from bitcoind's getblock JSON RPC method), verify that the
    transactions are consistent.

    Return True on success
    Return False if not.
    """
     
    # verify block data txs 
    m = pybitcoin.MerkleTree( block_data['tx'] )
    root_hash = str(m.root())

    return root_hash == str(block_data['merkleroot'])


def get_nulldata_txs_in_blocks( workpool, bitcoind_opts, blocks_ids, first_block_hash=None ):
   """
   Obtain the set of transactions over a range of blocks that have an OP_RETURN with nulldata.
   Each returned transaction record will contain:
   * vin (list of inputs from bitcoind)
   * vout (list of outputs from bitcoind)
   * txid (transaction ID, as a hex string)
   * txindex (transaction index in the block)
   * senders (a list of {"script_pubkey":, "amount":, "addresses":} dicts in order by input; the "script_pubkey" field is the hex-encoded op script).
   * fee (total amount sent)
   * nulldata (input data to the transaction's script; encodes virtual chain operations)
   
   Farm out the requisite RPCs to a workpool of processes, each 
   of which have their own bitcoind RPC client.
   
   Returns [(block_number, [txs])], where each tx contains the above.
   """
   
   nulldata_tx_map = {}    # {block_number: {"tx": [tx]}}
   block_bandwidth = {}    # {block_number: {"time": time taken to process, "size": number of bytes}}
   nulldata_txs = []
   
   # break work up into slices of blocks, so we don't run out of memory 
   slice_len = multiprocess_batch_size( bitcoind_opts )
   slice_count = 0
   last_block_hash = first_block_hash
   
   while slice_count * slice_len < len(blocks_ids):
      
      block_hashes = {}  # map block ID to block hash 
      block_datas = {}    # map block hashes to block data
      block_hash_futures = []
      block_data_futures = []
      tx_futures = []
      nulldata_tx_futures = []
      all_nulldata_tx_futures = []
      block_times = {}          # {block_number: time taken to process}
      
      block_slice = blocks_ids[ (slice_count * slice_len) : min((slice_count+1) * slice_len, len(blocks_ids)) ]
      if len(block_slice) == 0:
         log.debug("Zero-length block slice")
         break
      
      start_slice_time = time.time()
     
      # get all block hashes 
      for block_number in block_slice:
         
         block_times[block_number] = time.time() 
         
         block_hash_fut = getblockhash_async( workpool, bitcoind_opts, block_number )
         block_hash_futures.append( (block_number, block_hash_fut) ) 
   
      # coalesce all block hashes
      block_hash_time_start = time.time()
      block_hash_time_end = 0
      
      for i in xrange(0, len(block_hash_futures)):
         
         block_number, block_hash_fut = future_next( block_hash_futures, lambda f: f[1] )
         
         # NOTE: interruptable blocking get(), but should not block since future_next found one that's ready
         block_hash = future_get_result( block_hash_fut, 10000000000000000L )
         block_hashes[block_number] = block_hash
       
         # start getting each block's data
         if block_hash is not None:
             block_data_fut = getblock_async( workpool, bitcoind_opts, block_hash )
             block_data_futures.append( (block_number, block_data_fut) )

         else:
             raise Exception("BUG: Block %s: no block hash" % block_number)
     
      block_data_time_start = time.time()
      block_data_time_end = 0
     
      # coalesce block data
      for i in xrange(0, len(block_data_futures)):
         
         block_number, block_data_fut = future_next( block_data_futures, lambda f: f[1] )
         block_hash_time_end = time.time()
         
         # NOTE: interruptable blocking get(), but should not block since future_next found one that's ready
         block_data = future_get_result( block_data_fut, 1000000000000000L )
         
         if 'tx' not in block_data:
             raise Exception("BUG: No tx data in block %s" % block_number)
         
         block_datas[ block_hashes[block_number] ] = block_data
     

      # verify blockchain headers
      for i in xrange(0, len(block_slice)):
          block_id = block_slice[i]
          block_hash = block_hashes[block_id]

          prev_block_hash = None
          if i > 0:
              prev_block_id = block_slice[i-1]
              prev_block_hash = block_hashes[prev_block_id]

          elif last_block_hash is not None:
              prev_block_hash = last_block_hash 

          else:
              continue

          if not block_header_verify( block_datas[block_hash], prev_block_hash, block_hash ):
              serialized_header = block_header_to_hex( block_datas[block_hash], prev_block_hash )
              candidate_hash_reversed = pybitcoin.bin_double_sha256(binascii.unhexlify(serialized_header))
              candidate_hash = binascii.hexlify(candidate_hash_reversed[::-1])
              raise Exception("Hash mismatch on block %s: got invalid block hash (expected %s, got %s)" % (block_id, block_hash, candidate_hash))

      last_block_hash = block_hashes[ block_slice[-1] ]

      for block_number in block_slice:
         
         block_hash = block_hashes[block_number]
         block_data = block_datas[block_hash]
         
         # verify block data txs
         rc = block_verify( block_data )
         if not rc:
             raise Exception("Hash mismatch on block %s: got invalid Merkle root (expected %s)" % (block_hash, block_data['merkleroot']))

         # go get each transaction
         tx_hashes = block_data['tx']
         
         log.debug("Get %s transactions from block %s" % (len(tx_hashes), block_hash))
         
         # can get transactions asynchronously with a workpool (but preserve tx order!)
         if len(tx_hashes) > 0:
           
            for j in xrange(0, len(tx_hashes)):
               
               tx_hash = tx_hashes[j]
               tx_fut = getrawtransaction_async( workpool, bitcoind_opts, tx_hash, 1 )
               tx_futures.append( (block_number, j, tx_fut) )
            
         else:
            
            raise Exception("BUG: Zero-transaction block %s" % block_number)
           
      block_tx_time_start = time.time()
      block_tx_time_end = 0
      
      # coalesce raw transaction queries...
      for i in xrange(0, len(tx_futures)):
         
         block_number, tx_index, tx_fut = future_next( tx_futures, lambda f: f[2] )
         block_data_time_end = time.time()
         
         # NOTE: interruptable blocking get(), but should not block since future_next found one that's ready
         tx = future_get_result( tx_fut, 1000000000000000L )
         
         if not tx_is_coinbase( tx ):

             # verify non-coinbase transaction 
             tx_hash = tx['txid']
             if not tx_verify( tx, tx_hash ):
                 raise Exception("Transaction hash mismatch in %s (index %s) in block %s" % (tx['txid'], tx_index, block_number))

         if tx and has_nulldata(tx):
            
            # go get input transactions for this transaction (since it's the one with nulldata, i.e., a virtual chain operation),
            # but tag each future with the hash of the current tx, so we can reassemble the in-flight inputs back into it. 
            nulldata_tx_futs_and_output_idxs = process_nulldata_tx_async( workpool, bitcoind_opts, tx )
            nulldata_tx_futures.append( (block_number, tx_index, tx, nulldata_tx_futs_and_output_idxs) )
            
         else:
            
            # maybe done with this block
            # NOTE will be called multiple times; we expect the last write to be the total time taken by this block
            total_time = time.time() - block_times[ block_number ]
            block_bandwidth[ block_number ] = bandwidth_record( total_time, None )
             
      block_nulldata_tx_time_start = time.time()
      block_nulldata_tx_time_end = 0
      
      # coalesce queries on the inputs to each nulldata transaction from this block...
      for (block_number, tx_index, tx, nulldata_tx_futs_and_output_idxs) in nulldata_tx_futures:
         
         if ('vin' not in tx) or ('vout' not in tx) or ('txid' not in tx):
            continue 
        
         inputs = tx['vin']
         outputs = tx['vout']
         
         total_in = 0   # total input paid
         senders = []
         ordered_senders = []

         if tx_is_coinbase( tx ):
             # skip coinbase 
             continue
         
         # gather this tx's nulldata-bearing transactions
         for i in xrange(0, len(nulldata_tx_futs_and_output_idxs)):
            
            input_idx, input_tx_fut, tx_output_index = future_next( nulldata_tx_futs_and_output_idxs, lambda f: f[1] )
            
            # NOTE: interruptable blocking get(), but should not block since future_next found one that's ready
            input_tx = future_get_result( input_tx_fut, 1000000000000000L )
            if not input_tx.has_key('txid'):
                # something's wrong 
                log.error("Invalid transaction\n%s" % json.dumps(input_tx, indent=4, sort_keys=True))
                raise ValueError("Invalid transaction")

            input_tx_hash = input_tx['txid']

            # verify (but skip coinbase) 
            if not tx_is_coinbase( input_tx ):
                try:
                    if not tx_verify( input_tx, input_tx_hash ):
                        raise Exception("Input transaction hash mismatch %s from tx %s (index %s)" % (input_tx['txid'], tx['txid'], tx_output_index))
                except:
                    pp = pprint.PrettyPrinter()
                    pp.pprint(input_tx)
                    raise

            sender, amount_in = get_sender_and_amount_in_from_txn( input_tx, tx_output_index )
            
            if sender is None or amount_in is None:
               continue
            
            total_in += amount_in 
            
            # preserve sender order...
            ordered_senders.append( (input_idx, sender) )
         
         # sort on input_idx, so the list of senders matches the given transaction's list of inputs
         ordered_senders.sort()
         senders = [sender for (_, sender) in ordered_senders]

         # sanity check...
         if len(senders) != len(inputs):
             raise Exception("Sender/inputs mismatch: %s != %s\n" % (len(senders), len(inputs)))
         
         total_out = get_total_out( outputs )
         nulldata = get_nulldata( tx )
      
         # extend tx to explicitly record its nulldata (i.e. the virtual chain op),
         # the list of senders (i.e. their script hexs),
         # and the total amount paid
         tx['nulldata'] = nulldata
         tx['senders'] = senders
         tx['fee'] = total_in - total_out
         
         # track the order of nulldata-containing transactions in this block
         if not nulldata_tx_map.has_key( block_number ):
            nulldata_tx_map[ block_number ] = [(tx_index, tx)]
            
         else:
            nulldata_tx_map[ block_number ].append( (tx_index, tx) )
            
         # maybe done with this block
         # NOTE will be called multiple times; we expect the last write to be the total time taken by this block
         total_time = time.time() - block_times[ block_number ]
         block_bandwidth[ block_number ] = bandwidth_record( total_time, None )
            
      # record bandwidth information 
      for block_number in block_slice:
         
         block_data = None
         
         if nulldata_tx_map.has_key( block_number ):
            
            tx_list = nulldata_tx_map[ block_number ]     # [(tx_index, tx)]
            tx_list.sort()                                # sorts on tx_index--preserves order in the block
            
            txs = [ tx for (_, tx) in tx_list ]
            block_data = txs 
            
         if not block_bandwidth.has_key( block_number ):
            
            # done with this block now 
            total_time = time.time() - block_times[ block_number ]
            block_bandwidth[ block_number ] = bandwidth_record( total_time, block_data )
         
         
      block_tx_time_end = time.time()
      block_nulldata_tx_time_end = time.time()
   
      end_slice_time = time.time()
      
      total_processing_time = sum( map( lambda block_id: block_bandwidth[block_id]["time"], block_bandwidth.keys() ) )
      total_data = sum( map( lambda block_id: block_bandwidth[block_id]["size"], block_bandwidth.keys() ) )
      
      block_hash_time = block_hash_time_end - block_hash_time_start 
      block_data_time = block_data_time_end - block_data_time_start
      block_tx_time = block_tx_time_end - block_tx_time_start 
      block_nulldata_tx_time = block_nulldata_tx_time_end - block_nulldata_tx_time_start
      
      # log some stats...
      log.debug("blocks %s-%s (%s):" % (block_slice[0], block_slice[-1], len(block_slice)) )
      log.debug("  Time total:     %s" % total_processing_time )
      log.debug("  Data total:     %s" % total_data )
      log.debug("  Total goodput:  %s" % (total_data / (total_processing_time + 1e-7)))
      log.debug("  block hash time:        %s" % block_hash_time)
      log.debug("  block data time:        %s" % block_data_time)
      log.debug("  block tx time:          %s" % block_tx_time)
      log.debug("  block nulldata tx time: %s" % block_nulldata_tx_time)
      
      # next slice
      slice_count += 1
   
   # get the blockchain-ordered list of nulldata-containing transactions.
   # this is the blockchain-agreed list of all virtual chain operations, as well as the amount paid per transaction and the 
   # principal(s) who created each transaction.
   # convert {block_number: [tx]} to [(block_number, [tx])] where [tx] is ordered by the order in which the transactions occurred in the block
   for block_number in blocks_ids:
      
      txs = []
      
      if block_number in nulldata_tx_map.keys():
         tx_list = nulldata_tx_map[ block_number ]     # [(tx_index, tx)]
         tx_list.sort()                                # sorts on tx_index--preserves order in the block
         
         # preserve index
         for (tx_index, tx) in tx_list:
             tx['txindex'] = tx_index

         txs = [ tx for (_, tx) in tx_list ]

      nulldata_txs.append( (block_number, txs) )
      
   return nulldata_txs

