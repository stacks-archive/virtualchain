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

from ..config import DEBUG, MULTIPROCESS_RPC_RETRY
from ..workpool import multiprocess_bitcoind, multiprocess_batch_size

import logging
import os
import time
import types
import random

from bitcoinrpc.authproxy import JSONRPCException

import session 
log = session.log 

def get_bitcoind( bitcoind_or_opts ):
   """
   Given either a bitcoind API endpoint proxy, 
   or a dictionary of options to generate one in a
   process-local context, return a bitcoind API endpoint 
   proxy.
   """
   
   if type(bitcoind_or_opts) == types.DictType:
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
   

def getrawtransaction( bitcoind_or_opts, txid, verbose=0 ):
   """
   Get a raw transaction by txid.
   Only call out to bitcoind if we need to.
   """
   
   exc_to_raise = None
   bitcoind = get_bitcoind( bitcoind_or_opts )
   
   if bitcoind_or_opts is None:
       raise Exception("No bitcoind or opts given")
   
   for i in xrange(0, MULTIPROCESS_RPC_RETRY):
      try:
         
         try:
            
            tx = bitcoind.getrawtransaction( txid, verbose )
            
         except JSONRPCException, je:
            log.error("\n\n[%s] Caught JSONRPCException from bitcoind: %s\n" % (os.getpid(), repr(je.error)))
            exc_to_raise = je
            
            new_opts = get_bitcoind_opts( bitcoind_or_opts )
            bitcoind = multiprocess_bitcoind( new_opts, reset=True)
            continue

         except Exception, e:
            log.error("\n\n[%s] Caught Exception from bitcoind: %s" % (os.getpid(), repr(e)))
            exc_to_raise = e
        
            new_opts = get_bitcoind_opts( bitcoind_or_opts )
            bitcoind = multiprocess_bitcoind( new_opts, reset=True)
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
   
   tx_result = workpool.apply_async( getrawtransaction, (bitcoind_opts, tx_hash, verbose) )
   return tx_result


def getblockhash( bitcoind_or_opts, block_number, reset ):
   """
   Get a block's hash, given its ID.
   Return None if there are no options
   """
   
   exc_to_raise = None  # exception to raise if we fail
   bitcoind = get_bitcoind( bitcoind_or_opts )
   
   if bitcoind_or_opts is None:
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
        
            new_opts = get_bitcoind_opts( bitcoind_or_opts )
            bitcoind = multiprocess_bitcoind( new_opts, reset=True)
            continue
         
         except Exception, e:
            log.error("\n\n[%s] Caught Exception from bitcoind: %s" % (os.getpid(), repr(e)))
            exc_to_raise = e
            
            new_opts = get_bitcoind_opts( bitcoind_or_opts )
            if new_opts is None:
                raise Exception("No bitcoind or opts given")
            
            bitcoind = multiprocess_bitcoind( new_opts, reset=True)
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
   
   block_hash_future = workpool.apply_async( getblockhash, (bitcoind_opts, block_number, reset) )
   log.debug("getblockhash_async %s" % block_number)
   
   return block_hash_future


def getblock( bitcoind_or_opts, block_hash ):
   """
   Get a block's data, given its hash.
   """
   if bitcoind_or_opts is None:
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
         
         new_opts = get_bitcoind_opts( bitcoind_or_opts )
         bitcoind = multiprocess_bitcoind( new_opts, reset=True)
         continue
     
      except Exception, e:
         log.error("\n\n[%s] Caught Exception from bitcoind: %s" % (os.getpid(), repr(e)))
         exc_to_raise = e
     
         attempts += 1
         
         # probably a transient network failure
         # exponential backoff with jitter
         time.sleep(2**attempts + random.randint( 0, 2**(attempts - 1)) )
         
         new_opts = get_bitcoind_opts( bitcoind_or_opts )
         bitcoind = multiprocess_bitcoind( new_opts, reset=True)
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
   block_future = workpool.apply_async( getblock, (bitcoind_opts, block_hash) )
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
      print "output_index = '%s'" % output_index
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
    
    However, in order to identify a primary sender, we need to 
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
   for fut_record in fut_records:
      fut = fut_inspector( fut_record )
      if fut is not None:
         
         # NOTE: interruptable
         fut.wait( 10000000000000000L )
         
         fut_records.remove( fut_record )
         return fut_record
   
   

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


def get_nulldata_txs_in_blocks( workpool, bitcoind_opts, blocks_ids ):
   """
   Obtain the set of transactions over a range of blocks that have an OP_RETURN with nulldata.
   Each returned transaction record will contain:
   * vin (list of inputs from bitcoind)
   * vout (list of outputs from bitcoind)
   * txid (transaction ID, as a hex string)
   * senders (a list of {"script_pubkey":, "amount":, and "addresses":} dicts; the "script_pubkey" field is the hex-encoded op script).
   * fee (total amount sent)
   * nulldata (input data to the transaction's script; encodes virtual chain operations)
   
   Farm out the requisite RPCs to a workpool of processes, each 
   of which have their own bitcoind RPC client.
   
   Returns [(block_number, [txs])], where each tx contains the above.
   """
   
   nulldata_tx_map = {}    # {block_number: {tx": [tx]}}
   block_bandwidth = {}    # {block_number: {"time": time taken to process, "size": number of bytes}}
   nulldata_txs = []
   
   # break work up into slices of blocks, so we don't run out of memory 
   slice_len = multiprocess_batch_size( bitcoind_opts )
   slice_count = 0
   
   while slice_count * slice_len < len(blocks_ids):
      
      block_hash_futures = []
      block_data_futures = []
      tx_futures = []
      nulldata_tx_futures = []
      all_nulldata_tx_futures = []
      block_times = {}          # {block_number: time taken to process}
      
      block_slice = blocks_ids[ (slice_count * slice_len) : min((slice_count+1) * slice_len, len(blocks_ids)-1) ]
      if len(block_slice) == 0:
         break
      
      start_slice_time = time.time()
      
      # get all block hashes 
      for block_number in block_slice:
         
         block_times[block_number] = time.time() 
         
         # NOTE: force re-connect, since the previous connection will have expired if we take a while to process all nulldata 
         block_hash_fut = getblockhash_async( workpool, bitcoind_opts, block_number, reset=True )
         block_hash_futures.append( (block_number, block_hash_fut) )
   
   
      # coalesce all block hashes, and start getting each block's data
      block_hash_time_start = time.time()
      block_hash_time_end = 0
      
      for i in xrange(0, len(block_hash_futures)):
         
         block_number, block_hash_fut = future_next( block_hash_futures, lambda f: f[1] )
         
         # NOTE: interruptable blocking get(), but should not block since future_next found one that's ready
         block_hash = block_hash_fut.get( 10000000000000000L )
         
         log.debug("getblock_async %s %s" % (block_number, block_hash))
         block_data_fut = getblock_async( workpool, bitcoind_opts, block_hash )
         block_data_futures.append( (block_number, block_data_fut) )
      
      
      block_data_time_start = time.time()
      block_data_time_end = 0
      
      # coalesce block data, and get tx hashes 
      for i in xrange(0, len(block_data_futures)):
         
         block_number, block_data_fut = future_next( block_data_futures, lambda f: f[1] )
         block_hash_time_end = time.time()
         
         # NOTE: interruptable blocking get(), but should not block since future_next found one that's ready
         block_data = block_data_fut.get( 10000000000000000L )
         
         if 'tx' not in block_data:
            log.error("tx not in block data of %s" % block_number)
            return nulldata_txs
         
         tx_hashes = block_data['tx']
         
         log.debug("Get %s transactions from block %d" % (len(tx_hashes), block_number))
         
         # can get transactions asynchronously with a workpool
         # NOTE: tx order matters! remember the order we saw them in
         if len(tx_hashes) > 0:
            
            for j in xrange(0, len(tx_hashes)):
               
               tx_hash = tx_hashes[j]
               tx_fut = getrawtransaction_async( workpool, bitcoind_opts, tx_hash, 1 )
               tx_futures.append( (block_number, j, tx_fut) )
            
         else:
            
            raise Exception("Zero-transaction block %s" % block_number)
            
      block_tx_time_start = time.time()
      block_tx_time_end = 0
      
      # coalesce raw transaction queries...
      for i in xrange(0, len(tx_futures)):
         
         block_number, tx_index, tx_fut = future_next( tx_futures, lambda f: f[2] )
         block_data_time_end = time.time()
         
         # NOTE: interruptable blocking get(), but should not block since future_next found one that's ready
         tx = tx_fut.get( 10000000000000000L )
         
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
         
         outputs = tx['vout']
         
         total_in = 0   # total input paid
         senders = []
         ordered_senders = []
         
         # gather this tx's nulldata queries
         for i in xrange(0, len(nulldata_tx_futs_and_output_idxs)):
            
            input_idx, input_tx_fut, tx_output_index = future_next( nulldata_tx_futs_and_output_idxs, lambda f: f[1] )
            
            # NOTE: interruptable blocking get(), but should not block since future_next found one that's ready
            input_tx = input_tx_fut.get( 10000000000000000L )
            sender, amount_in = get_sender_and_amount_in_from_txn( input_tx, tx_output_index )
            
            if sender is None or amount_in is None:
               continue
            
            total_in += amount_in 
            
            # NOTE: senders isn't commutative--will need to preserve order
            ordered_senders.append( (input_idx, sender) )
         
         # sort on input_idx, so the list of senders matches the given transaction's list of inputs
         ordered_senders.sort()
         senders = [sender for (_, sender) in ordered_senders]
         
         total_out = get_total_out( outputs )
         nulldata = get_nulldata( tx )
      
         # extend tx to explicitly record its nulldata (i.e. the virtual chain op),
         # the list of senders (i.e. their script_pubkey strings and amount paid in),
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
         
         txs = [ tx for (_, tx) in tx_list ]
         
      nulldata_txs.append( (block_number, txs) )
      
   return nulldata_txs

