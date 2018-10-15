#!/usr/bin/python
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
    along with Virtualchain. If not, see <http://www.gnu.org/licenses/>.
"""


import socket
import os
import sys
import time
import logging
import binascii
import simplejson
import requests
from StringIO import StringIO
from decimal import *

from protocoin.clients import *
from protocoin.serializers import *
from protocoin.fields import *

from keys import version_byte as VERSION_BYTE
import bits

from spv import *

from ....lib import hashing, merkle
from ....lib.config import get_features

log = logging.getLogger("virtualchain")

class BlockchainDownloader( BitcoinBasicClient ):
    """
    Fetch all transactions from the blockchain 
    over a given range.
    """

    coin = None
    timeout = 30

    def __init__(self, bitcoind_opts, spv_headers_path, first_block_height, last_block_height, p2p_port=None, sock=None, tx_filter=None ):
        """
        Before calling this, the headers must be synchronized
        @last_block_height is *inclusive*
        """

        if VERSION_BYTE == 0:
            self.coin = "bitcoin"
            if p2p_port is None:
                p2p_port = 8333
        else:
            if os.environ.get("BLOCKSTACK_TESTNET3") == "1":
                # testnet version 3 enabled
                self.coin = "bitcoin_testnet3"

            else:
                # regtest 
                self.coin = "bitcoin_testnet"

            if p2p_port is None:
                p2p_port = 18333

        if not os.path.exists(spv_headers_path):
            raise Exception("No such file or directory: %s" % spv_headers_path)

        if sock is None:
            sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
            sock.settimeout(self.timeout)
            try:
                sock.connect( (bitcoind_opts['bitcoind_server'], p2p_port) )
            except socket.error, e:
                log.error("Failed to connect to %s:%s" % (bitcoind_opts['bitcoind_server'], p2p_port))
                raise
        
        super(BlockchainDownloader, self).__init__(sock)

        self.bitcoind_opts = bitcoind_opts
        self.spv_headers_path = spv_headers_path
        self.first_block_height = first_block_height
        self.last_block_height = last_block_height
        self.finished = False
        self.tx_filter = tx_filter

        self.blocks = {}        # map height to block hash
        self.block_info = {}    # map block hash to block data {'height': ..., 'header': ..., 'txns': ..., 'handled': True|False}
        self.sender_info = {}   # map tx hash to {output_index: {'block_hash': ..., 'txindex': ...}} (i.e. map sender tx to the tx with the input that references it)
        self.num_txs_received = 0
        self.num_blocks_requested = last_block_height - first_block_height + 1
        self.num_blocks_received = 0

        # just for fun
        self.num_txs_processed = 0

        for i in xrange(first_block_height, last_block_height + 1):
            block_header = SPVClient.read_header( spv_headers_path, i, allow_none=True )
            if block_header is None:
                continue

            self.blocks[i] = block_header['hash']
            self.block_info[block_header['hash']] = {
                'height': i,
                'header': block_header,
                'txns': None,
                'handled': False
            }

        log.debug("BlockDownloader: fetch blocks %s-%s" % (first_block_height, last_block_height))

     
    def loop_exit( self ):
        """
        Stop the loop
        """
        self.finished = True
        self.close_stream()

    
    def get_block_info(self):
        """
        Get the retrieved block information.
        Return [(height, [txs])] on success, ordered on height
        Raise if not finished downloading
        """
        if not self.finished:
            raise Exception("Not finished downloading")

        ret = []
        for (block_hash, block_data) in self.block_info.items():
            ret.append( (block_data['height'], block_data['txns']) )

        return ret

    
    def run( self ):
        """
        Interact with the blockchain peer,
        until we get a socket error or we
        exit the loop explicitly.

        The order of operations is:
        * send version
        * receive version
        * send verack
        * send getdata
        * receive blocks
        * for each block:
          * for each transaction with nulldata:
             * for each input:
                * get the transaction that produced the consumed input

        Return True on success
        Return False on error
        """
        
        log.debug("Segwit support: {}".format(get_features('segwit')))

        self.begin()

        try:
            self.loop()
        except socket.error, se:
            if not self.finished:
                # unexpected
                log.exception(se)
                return False

        # fetch remaining sender transactions
        try:
            self.fetch_sender_txs()
        except Exception, e:
            log.exception(e)
            return False

        # should be done now
        try:
            self.block_data_sanity_checks()
        except AssertionError, ae:
            log.exception(ae)
            return False

        return True


    def have_all_block_data(self):
        """
        Have we received all block data?
        """
        if not (self.num_blocks_received == self.num_blocks_requested):
            log.debug("num blocks received = %s, num requested = %s" % (self.num_blocks_received, self.num_blocks_requested))
            return False

        return True


    def fetch_sender_txs(self):
        """
        Fetch all sender txs via JSON-RPC,
        and merge them into our block data.

        Try backing off (up to 5 times) if we fail
        to fetch transactions via JSONRPC

        Return True on success
        Raise on error
        """
        
        # fetch remaining sender transactions
        if len(self.sender_info.keys()) > 0:

            sender_txids = self.sender_info.keys()[:]
            sender_txid_batches = []
            batch_size = 20

            for i in xrange(0, len(sender_txids), batch_size ):
                sender_txid_batches.append( sender_txids[i:i+batch_size] )

            for i in xrange(0, len(sender_txid_batches)):

                sender_txid_batch = sender_txid_batches[i]
                log.debug("Fetch %s TXs via JSON-RPC (%s-%s of %s)" % (len(sender_txid_batch), i * batch_size, i * batch_size + len(sender_txid_batch), len(sender_txids)))

                sender_txs = None

                for j in xrange(0, 5):
                    sender_txs = self.fetch_txs_rpc( self.bitcoind_opts, sender_txid_batch )
                    if sender_txs is None:
                        log.error("Failed to fetch transactions; trying again (%s of %s)" % (j+1, 5))
                        time.sleep(j+1)
                        continue

                    break

                if sender_txs is None:
                    raise Exception("Failed to fetch transactions")
                
                # pair back up with nulldata transactions
                for sender_txid, sender_tx in sender_txs.items():

                    assert sender_txid in self.sender_info.keys(), "Unsolicited sender tx %s" % sender_txid

                    # match sender outputs to the nulldata tx's inputs
                    for nulldata_input_vout_index in self.sender_info[sender_txid].keys():
                        if sender_txid != "0000000000000000000000000000000000000000000000000000000000000000":
                            
                            # regular tx, not coinbase 
                            assert nulldata_input_vout_index < len(sender_tx['outs']), 'Output index {} is out of bounds for {}'.format(nulldata_input_vout_index, sender_txid)

                            # save sender info 
                            self.add_sender_info(sender_txid, nulldata_input_vout_index, sender_tx['outs'][nulldata_input_vout_index])
                        
                        else:

                            # coinbase
                            self.add_sender_info(sender_txid, nulldata_input_vout_index, sender_tx['outs'][0])

                    # update accounting
                    self.num_txs_received += 1

        return True


    def block_data_sanity_checks(self):
        """
        Verify that the data we received makes sense.
        Return True on success
        Raise on error
        """
        assert self.have_all_block_data(), "Still missing block data"
        assert self.num_txs_received == len(self.sender_info.keys()), "Num TXs received: %s; num TXs requested: %s" % (self.num_txs_received, len(self.sender_info.keys()))

        for (block_hash, block_info) in self.block_info.items():
            for tx in block_info['txns']:
                assert None not in tx['senders'], "Missing one or more senders in %s; dump follows\n%s" % (tx['txid'], simplejson.dumps(tx, indent=4, sort_keys=True)) 
                for i in range(0, len(tx['ins'])):
                    inp = tx['ins'][i]
                    sinfo = tx['senders'][i]

                    assert sinfo['txid'] in self.sender_info, 'Surreptitious sender tx {}'.format(sinfo['txid'])
                    assert inp['outpoint']['index'] == sinfo['nulldata_vin_outpoint'], 'Mismatched sender/input index ({}: {} != {}); dump follows\n{}'.format(
                            sinfo['txid'], inp['outpoint']['index'], sinfo['nulldata_vin_outpoint'], simplejson.dumps(tx, indent=4, sort_keys=True))

                    assert inp['outpoint']['hash'] == sinfo['txid'], 'Mismatched sender/input txid ({} != {}); dump follows\n{}'.format(inp['txid'], sinfo['txid'], simplejson.dumps(tx, indent=4, sort_keys=True))

        return True


    def begin(self):
        """
        This method will implement the handshake of the
        Bitcoin protocol. It will send the Version message,
        and block until it receives a VerAck.
        Once we receive the version, we'll send the verack,
        and begin downloading.
        """
        log.debug("handshake (version %s)" % PROTOCOL_VERSION)
        version = Version()
        version.services = 0    # can't send blocks
        log.debug("send Version")
        self.send_message(version)


    def handle_version(self, message_header, message):
        """
        This method will handle the Version message and
        will send a VerAck message when it receives the
        Version message.

        :param message_header: The Version message header
        :param message: The Version message
        """
        log.debug("handle version")
        verack = VerAck()
        log.debug("send VerAck")
        self.send_message(verack)
        self.verack = True

        start_block_height = sorted(self.blocks.keys())[0]
        if start_block_height < 1:
            start_block_height = 1

        # ask for all blocks
        block_hashes = []
        for height in sorted(self.blocks.keys()):
            block_hashes.append( int(self.blocks[height], 16) )

        start_block_height = sorted(self.blocks.keys())[0]
        end_block_height = sorted(self.blocks.keys())[-1]
    
        log.debug("send getdata for %s-%s (%064x-%064x)" % (start_block_height, end_block_height, block_hashes[0], block_hashes[-1]))

        # send off the getdata
        getdata = GetData()
        block_inv_vec = []
        for block_hash in block_hashes:
            block_inv = Inventory()
            block_inv.inv_type = INVENTORY_TYPE["MSG_BLOCK"]
            block_inv.inv_hash = block_hash

            block_inv_vec.append(block_inv)

        getdata.inventory = block_inv_vec
        self.send_message(getdata)


    def handle_ping(self, message_header, message):
        """
        This method will handle the Ping message and then
        will answer every Ping message with a Pong message
        using the nonce received.

        :param message_header: The header of the Ping message
        :param message: The Ping message
        """
        log.debug("handle ping")
        pong = Pong()
        pong.nonce = message.nonce
        log.debug("send pong")
        self.send_message(pong)

    
    def handle_inv(self, message_header, inv_packet ):
        """
        Get the data we just requested.
        Shouldn't happen with newer servers, since they use
        getheaders/headers followed by getdata/blocks
        (older peers use getblocks/inv/getdata/inv exchanges)
        """
        log.debug("handle inv of %s item(s)" % len(inv_packet.inventory))

        reply_inv = []

        for inv_info in inv_packet.inventory:
            inv_hash = "%064x" % inv_info.inv_hash
            if inv_info.inv_type == INVENTORY_TYPE["MSG_BLOCK"]:
                # only ask for the block if we need it
                if inv_hash in self.block_info.keys() and not self.block_info[inv_hash]['handled']:
                    log.debug("Will request block %s" % inv_hash)
                    reply_inv.append( inv_info )
                    inv_hash = None


        if len(reply_inv) > 0:
            getdata = GetData()
            getdata.inventory = reply_inv
            log.debug("send GetData in reply to Inv for %s item(s)" % len(reply_inv))
            self.send_message(getdata)

        else:
            if self.have_all_block_data():
                self.loop_exit()

    
    def add_sender_info( self, sender_txhash, nulldata_vin_outpoint, sender_out_data ):
        """
        Record sender information in our block info.
        @sender_txhash: txid of the sender
        @nulldata_vin_outpoint: the 'vout' index from the nulldata tx input that this transaction funded
        """
        assert sender_txhash in self.sender_info.keys(), "Missing sender info for %s" % sender_txhash
        assert nulldata_vin_outpoint in self.sender_info[sender_txhash], "Missing outpoint %s for sender %s" % (nulldata_vin_outpoint, sender_txhash)

        block_hash = self.sender_info[sender_txhash][nulldata_vin_outpoint]['block_hash']
        relindex = self.sender_info[sender_txhash][nulldata_vin_outpoint]['relindex']
        relinput_index = self.sender_info[sender_txhash][nulldata_vin_outpoint]['relinput']

        value_in_satoshis = sender_out_data['value']
        script_pubkey = sender_out_data['script']
        script_info = bits.btc_tx_output_parse_script(script_pubkey)
        script_type = script_info['type']
        addresses = script_info.get('addresses', [])
        
        sender_info = {
            "value": value_in_satoshis,
            "script_pubkey": script_pubkey,
            "script_type": script_type,
            "addresses": addresses,
            "nulldata_vin_outpoint": nulldata_vin_outpoint,
            "txid": sender_txhash,
        }
        
        # debit this tx's total value
        self.block_info[block_hash]['txns'][relindex]['fee'] += value_in_satoshis

        # remember this sender, but put it in the right place.
        # senders[i] must correspond to tx['vin'][i]
        self.block_info[block_hash]['txns'][relindex]['senders'][relinput_index] = sender_info
        self.block_info[block_hash]['num_senders'] += 1

        return True


    def parse_tx( self, txn, block_header, block_hash, txindex ):
        """
        Given a transaction message and its index in the block,
        go and create a "verbose" transaction structure
        containing all the information in a nice, easy-to-read
        dict (i.e. like what bitcoind would give us).

        Does not work on coinbase transactions.
        Does not include segwit witnesses
        """

        txn_serializer = TxSerializer()
        tx_bin = txn_serializer.serialize(txn)

        txdata = {
            "version": txn.version,
            "locktime": txn.lock_time,
            "hex": binascii.hexlify( tx_bin ),
            "txid": txn.calculate_hash(),
            "size": len( tx_bin ),
            "blockhash": block_hash,
            "blocktime": block_header.get('timestamp', 0),

            # non-standard; added by us for virtualchain
            "txindex": txindex,
            "relindex": None,
            "senders": None,
            "fee": 0,
            "nulldata": None,
            "ins": None,     # library-specific field, to be passed to the state engine
            "outs": None,    # library-specific field, to be passed to the state engine
            "tx_merkle_path": None
        }
        
        # keep these around too, since this is what gets fed into the virtualchain state engine implementation 
        virtualchain_btc_tx_data = bits.btc_tx_deserialize(txdata['hex'])
        txdata['ins'] = virtualchain_btc_tx_data['ins']
        txdata['outs'] = virtualchain_btc_tx_data['outs']

        # we know how many senders there have to be 
        txdata['senders'] = [None] * len(txdata['ins'])

        return txdata


    def make_sender_info( self, block_hash, txn, i, block_height ):
        """
        Make sender information bundle for a particular input of
        a nulldata transaction.

        We'll use it to go find the transaction output that
        funded the ith input of the given tx.
        """

        inp = txn['ins'][i]
        ret = {
            # to be filled in...
            'scriptPubKey': None,
            'addresses': None,

            # for matching the input and sender funded
            "txindex": txn['txindex'],
            "relindex": txn['relindex'],
            "output_index": inp['outpoint']['index'],
            "block_hash": block_hash,
            "relinput": i,
            "block_height": block_height,
        }

        return ret


    def handle_block( self, message_header, block ):
        """
        Got a block.
        * validate it
        * load its transactions
        * ask for each transaction's sender transaction
        """

        if self.have_all_block_data():
            self.loop_exit()
            return

        block_hash = block.calculate_hash()
        
        # is this a solicited block?
        if block_hash not in self.block_info.keys():
            log.error("Ignoring unsolicited block %s" % block_hash)
            return
        
        header = self.block_info[block_hash]['header']
        height = self.block_info[block_hash]['height']
        
        log.debug("handle block %s (%s)" % (height, block_hash))

        # does this block's transaction hashes match the merkle root?
        tx_hashes = [block.txns[i].calculate_hash() for i in range(0, len(block.txns))]
        block_merkle_tree = merkle.MerkleTree(tx_hashes)
        mr = block_merkle_tree.root()

        if mr != header['merkle_root']:
            log.error("Merkle root of %s (%s) mismatch: expected %s, got %s" % (block_hash, height, header['merkle_root'], mr))
            return

        merkle_paths = {}       # map txid to merkle path

        # make sure we have merkle paths for each tx
        for i in range(0, len(block.txns)):
            txid = block.txns[i].calculate_hash()
            merkle_path = block_merkle_tree.path(txid)
            if merkle_path is None:
                log.error("No merkle path for {}".format(txid))
                return 

            merkle_paths[txid] = merkle_path
 
        nulldata_txs = []
        relindex = 0
        for txindex in range(0, len(block.txns)):

            txdata = self.parse_tx( block.txns[txindex], header, block_hash, txindex )

            # if there is no nulldata output, then we don't care about this one.
            has_nulldata = False
            nulldata_payload = None

            for outp in txdata['outs']:
                script_type = bits.btc_script_classify(outp['script'])
                if script_type == 'nulldata':
                    # to be clear, we only care about outputs that take the form
                    # OP_RETURN <string length> <string data>
                    nulldata_script = bits.btc_script_deserialize(outp['script'])
                    if len(nulldata_script) < 2:
                        # malformed OP_RETURN; no data after '6a'
                        nulldata_payload = None
                        has_nulldata = False

                    elif len(nulldata_script) == 2 and isinstance(nulldata_script[1], (str,unicode)):
                        # well-formed OP_RETURN output
                        nulldata_payload = nulldata_script[1]
                        has_nulldata = True
                   
                    else:
                        # this is something like OP_RETURN OP_2 (e.g. "6a52")
                        # there's nothing for us here.
                        nulldata_payload = None
                        has_nulldata = False

            # count all txs processed
            self.num_txs_processed += 1

            if not has_nulldata:
                continue

            # remember nulldata, even if it's empty
            txdata['nulldata'] = nulldata_payload 

            # remember merkle path
            txdata['tx_merkle_path'] = merkle_paths[txdata['txid']]
            
            # calculate total output (part of fee; will be debited when we discover the senders)
            # NOTE: this works because we have out['value'] as type Decimal
            # txdata['fee'] -= sum( int(out['value'] * 10**8) for out in txdata['vout'] )
            txdata['fee'] -= sum(out['value'] for out in txdata['outs'])

            # remember the relative tx index (i.e. the ith nulldata tx)
            txdata['relindex'] = relindex
            
	    # do we actually want this?
            if self.tx_filter is not None:
                if not self.tx_filter( txdata ):
                    continue

            # yup, we want it!
            relindex += 1
            nulldata_txs.append( txdata )


        self.block_info[block_hash]['txns'] = nulldata_txs
        self.block_info[block_hash]['num_txns'] = len(block.txns)
        self.block_info[block_hash]['num_senders'] = 0

        # get each input's transaction
        sender_txhashes = []

        for txn in self.block_info[block_hash]['txns']:
            for i in range(0, len(txn['ins'])):

                # record information about the transaction
                # that created this input (so we can go find
                # it later).
                inp = txn['ins'][i]
                sender_txid = inp['outpoint']['hash']
                inp_sender_outp = inp['outpoint']['index']

                if str(sender_txid) not in sender_txhashes:
                    sender_txhashes.append( str(sender_txid) )

                sinfo = self.make_sender_info( block_hash, txn, i, height )

                if not self.sender_info.has_key(sender_txid):
                    # map outpoint for this input to the tx info
                    self.sender_info[sender_txid] = {}

                # sinfo is the information from the output in 
                # the sender-tx that funded inp
                self.sender_info[sender_txid][inp_sender_outp] = sinfo

        # update accounting...
        self.num_blocks_received += 1
        self.block_info[block_hash]['handled'] = True

        log.debug("Request %s nulldata sender TXs" % len(sender_txhashes))

        if self.have_all_block_data():
            self.loop_exit()

        return


    def fetch_txs_rpc( self, bitcoind_opts, txids ):
        """
        Fetch the given list of transactions
        via the JSON-RPC interface.

        Return a dict of parsed transactions on success,
        keyed by txid.

        Return None on error
        """

        headers = {'content-type': 'application/json'}
        reqs = []
        ret = {}
        for i in xrange(0, len(txids)):
            txid = txids[i]
            if txid == "0000000000000000000000000000000000000000000000000000000000000000":
                # coinbase; we never send these
                ret[txid] = {
                    'version': 1,
                    'locktime': 0,
                    'ins': [],
                    'outs': [
                        {
                            'script': '',
                            'value': 0      # not really 0, but we don't care about coinbases anyway
                        }
                    ],
                }
                continue

            req = {'method': 'getrawtransaction', 'params': [txid, 0], 'jsonrpc': '2.0', 'id': i}
            reqs.append( req )

        proto = "http"
        if bitcoind_opts.has_key('bitcoind_use_https') and bitcoind_opts['bitcoind_use_https']:
            proto = "https"
            
        server_url = "%s://%s:%s@%s:%s" % (proto, bitcoind_opts['bitcoind_user'], bitcoind_opts['bitcoind_passwd'], bitcoind_opts['bitcoind_server'], bitcoind_opts['bitcoind_port'])
        try:
            resp = requests.post( server_url, headers=headers, data=simplejson.dumps(reqs), verify=False )
        except Exception, e:
            log.exception(e)
            log.error("Failed to fetch %s transactions" % len(txids))
            return None

        # get responses
        try:
            resp_json = resp.json()
            assert type(resp_json) in [list]
        except Exception, e:
            log.exception(e)
            log.error("Failed to parse transactions")
            return None

        try:
            for resp in resp_json:
                assert 'result' in resp, "Missing result"

                txhex = resp['result']
                assert txhex is not None, "Invalid RPC response '%s' (for %s)" % (simplejson.dumps(resp), txids[resp['id']])
               
                if bits.btc_tx_is_segwit(txhex) and not get_features('segwit'):
                    # no segwit support yet
                    log.error("FATAL: SegWit transaction detected!  Support for SegWit-formatted transactions is not yet activated")
                    log.error("Please ensure your bitcoind node has `rpcserialversion=0` set.")
                    log.error("Aborting...")
                    os.abort()

                try:

                    tx_bin = txhex.decode('hex')
                    assert tx_bin is not None

                    tx_hash_bin = hashing.bin_double_sha256(tx_bin)[::-1]
                    assert tx_hash_bin is not None

                    tx_hash = tx_hash_bin.encode('hex')
                    assert tx_hash is not None

                except Exception, e:
                    log.error("Failed to calculate txid of %s" % txhex)
                    raise

                # solicited transaction?
                assert tx_hash in txids, "Unsolicited transaction %s" % tx_hash
                
                # unique?
                if tx_hash in ret.keys():
                    continue

                # parse from hex string
                txn_serializer = TxSerializer()
                txn = txn_serializer.deserialize( StringIO( binascii.unhexlify(txhex) ) )

                ret[tx_hash] = self.parse_tx( txn, {}, "", -1 )


        except Exception, e:
            log.exception(e)
            log.error("Failed to receive transactions")
            return None

        return ret


def get_bitcoin_virtual_transactions(blockchain_opts, first_block_height, last_block_height, tx_filter=None, spv_last_block=None, first_block_hash=None, **hints):
    """
    Get the sequence of virtualchain transactions from the blockchain.
    Each transaction returned will be a `nulldata` transaction (i.e. the first output script starts with OP_RETURN).
    * output values will be in satoshis
    * `fee` will be defined, and will be the total amount sent (in satoshis)
    * `txindex` will be defined, and will be the offset in the block where the tx occurs
    * `senders` will be defined as a list, and will contain the following information
        * `script_pubkey`: an output scriptPubKey hex script
        * `units`: a value in satoshis
        * `addresses`: a list of zero or more addresses
      This list corresponds to the list of outputs that funded the given transaction's inputs.
      That is, senders[i] corresponds to the output that funded vin[i], found in transaction vin[i]['txid']
    * `nulldata` will be define as the hex string that encodes the OP_RETURN payload

    @blockchain_opts must be a dict with the following keys:
    * `bitcoind_server`: hostname of the bitcoind peer
    * `bitcoind_port`: RPC port of the bitcoind peer
    * `bitcoind_p2p_port`: p2p port of the bitcoind peer
    * `bitcoind_user`: username to authenticate
    * `bitcoind_passwd`: password for authentication
    * `bitcoind_spv_path`: path on disk to where SPV headers should be stored

    Returns a list of [(block number), [txs]] on success
    Returns None on error
    """

    headers_path = blockchain_opts['bitcoind_spv_path']
    bitcoind_server = "%s:%s" % (blockchain_opts['bitcoind_server'], blockchain_opts['bitcoind_p2p_port'])
    spv_last_block = spv_last_block if spv_last_block is not None else last_block_height - 1

    if headers_path is None:
        log.error("FATAL: bitcoind_spv_path not defined in blockchain options")
        os.abort()

    if not os.path.exists(headers_path):
        log.debug("Will download SPV headers to %s" % headers_path)

    # synchronize SPV headers
    SPVClient.init( headers_path )

    rc = None
    for i in xrange(0, 65536, 1):
        # basically try forever
        try:
            rc = SPVClient.sync_header_chain( headers_path, bitcoind_server, spv_last_block )
            if not rc:
                delay = min( 600, 2**i + ((2**i) * random.random()) )
                log.error("Failed to synchronize SPV headers (%s) up to %s.  Try again in %s seconds" % (headers_path, last_block_height, delay))
                time.sleep( delay )
                continue

            else:
                break

        except SystemExit, s:
            log.error("Aborting on SPV header sync")
            os.abort()

        except Exception, e:
            log.exception(e)
            delay = min( 600, 2**i + ((2**i) * random.random()) )
            log.debug("Try again in %s seconds" % delay)
            time.sleep( delay )
            continue

    downloader = None
    for i in xrange(0, 65536, 1):
        # basically try forever
        try:
            
            # fetch all blocks
            downloader = BlockchainDownloader( blockchain_opts, blockchain_opts['bitcoind_spv_path'], first_block_height, last_block_height - 1, \
                                       p2p_port=blockchain_opts['bitcoind_p2p_port'], tx_filter=tx_filter )

            if first_block_height > last_block_height - 1:
                downloader.loop_exit()
                break

            rc = downloader.run()
            if not rc:
                delay = min( 600, 2**i + ((2**i) * random.random()) )
                log.error("Failed to fetch %s-%s; trying again in %s seconds" % (first_block_height, last_block_height, delay))
                time.sleep( delay )
                continue
            else:
                break

        except SystemExit, s:
            log.error("Aborting on blockchain sync")
            os.abort()

        except Exception, e:
            log.exception(e)
            delay = min( 600, 2**i + ((2**i) * random.random()) )
            log.debug("Try again in %s seconds" % delay)
            time.sleep( delay )
            continue            

    if not rc or downloader is None:
        log.error("Failed to fetch blocks %s-%s" % (first_block_height, last_block_height))
        return None

    # extract
    block_info = downloader.get_block_info()
    return block_info
    

def get_bitcoin_blockchain_height(bitcoind):
    """
    Given a bitcoind client, get the blockchain height
    """
    current_block = int(bitcoind.getblockcount())
    return current_block


if __name__ == "__main__":
    # test synchonize headers 
    try:
        bitcoind_server = sys.argv[1]
        headers_path = sys.argv[2]
        height = int(sys.argv[3])
        start_height = int(sys.argv[4])

    except:
        print >> sys.stderr, "Usage: %s bitcoind_server headers_path blockchain_height block_start_height" % sys.argv[0]
        sys.exit(0)

    log.setLevel(logging.DEBUG)
    SPVClient.init( headers_path )
    rc = SPVClient.sync_header_chain( headers_path, bitcoind_server, height )
    if rc:
        print "Headers are up to date with %s and seem to have sufficient proof-of-work" % height

    host = bitcoind_server
    port = 8333
    if ":" in host:
        host = bitcoind_server.split(":")[0]
        port = int(bitcoind_server.split(":")[1])

    bitcoind_opts = {
        "bitcoind_server": host,
        "bitcoind_port": 8332,
        "bitcoind_user": "blockstack", 
        "bitcoind_passwd": "blockstacksystem",
        "bitcoind_use_https": False
    }

    # test get blocks
    for interval in xrange(start_height, height, 20):

        bd = BlockchainDownloader( bitcoind_opts, headers_path, interval, interval + 19, p2p_port=port )
        bd.run()

        blocks = bd.block_info
        print "%d blocks received" % len(blocks)
        for block_hash, block_info in blocks.items():
            print "block %s (%s): %s txns processed, %s nulldata txns, %s senders processed" % (block_hash, block_info['height'], block_info['num_txns'], len(block_info['txns']), block_info['num_senders'])
           
        # print simplejson.dumps(blocks, indent=4, sort_keys=True)
        

