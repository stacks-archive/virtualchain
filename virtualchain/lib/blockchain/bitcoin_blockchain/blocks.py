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

import protocoin
from protocoin.clients import *
from protocoin.serializers import *
from protocoin.fields import *

from keys import version_byte as VERSION_BYTE
from keys import script_hex_to_address
import opcodes
import pybitcoin
import bitcoin
import bits

from spv import *

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
            block_header = SPVClient.read_header( spv_headers_path, i )
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
                            assert nulldata_input_vout_index < len(sender_tx['vout']), "Ouptut index %s is out of bounds for %s" % (out_index, sender_txid)
                        
                            # save sender info
                            self.add_sender_info( sender_txid, nulldata_input_vout_index, sender_tx['vout'][nulldata_input_vout_index] )
                        
                        else:
                            # coinbase
                            self.add_sender_info( sender_txid, nulldata_input_vout_index, sender_tx['vout'][0] )

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
                for i in xrange(0, len(tx['vin'])):
                    inp = tx['vin'][i]
                    sinfo = tx['senders'][i]
                   
                    assert self.sender_info.has_key(sinfo['txid']), "Surreptitious sender tx %s" % sinfo['txid']
                    assert inp['vout'] == sinfo['nulldata_vin_outpoint'], "Mismatched sender/input index (%s: %s != %s); dump follows\n%s" % \
                                        (sinfo['txid'], inp['vout'], sinfo['nulldata_vin_outpoint'], simplejson.dumps(tx, indent=4, sort_keys=True))

                    assert inp['txid'] == sinfo['txid'], "Mismatched sender/input txid (%s != %s); dump follows\n" % (inp['txid'], sender['txid'], simplejson.dumps(tx, indent=4, sort_keys=True))

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

        value_in = sender_out_data['value']
        script_pubkey = sender_out_data['scriptPubKey']['hex']
        script_type = sender_out_data['scriptPubKey']['type']
        addresses = sender_out_data['scriptPubKey'].get("addresses", [])

        sender_info = {
            "amount": value_in,
            "script_pubkey": script_pubkey,
            "script_type": script_type,
            "addresses": addresses,
            "nulldata_vin_outpoint": nulldata_vin_outpoint,
            "txid": sender_txhash
        }
        
        # debit this tx's total value
        self.block_info[block_hash]['txns'][relindex]['fee'] += int(value_in * 10**8)

        # remember this sender, but put it in the right place.
        # senders[i] must correspond to tx['vin'][i]
        self.block_info[block_hash]['txns'][relindex]['senders'][relinput_index] = sender_info
        self.block_info[block_hash]['num_senders'] += 1

        return True

    
    def parse_tx_input( self, inp ):
        """
        Given a tx input, turn it into an easy-to-read
        dict (i.e. like what bitcoind would give us).
        """
        scriptsig = binascii.hexlify( inp.signature_script )
        prev_txid = "%064x" % inp.previous_output.out_hash

        ret = {
            "vout": inp.previous_output.index,
            "txid": prev_txid,
            "scriptSig": {
                "hex": scriptsig,
                "asm": bits.tx_script_to_asm(scriptsig)
            }
        }
        return ret


    def parse_tx_output( self, i, outp ):
        """
        Given a tx output, turn it into an easy-to-read
        dict (i.e. like what bitcoind would give us).
        """
        scriptpubkey = binascii.hexlify( outp.pk_script )
        script_info = bits.tx_output_parse_scriptPubKey( scriptpubkey )
        return {
            "value": Decimal(outp.value) / Decimal(10**8),
            "n": i,
            "scriptPubKey": script_info
        }


    def parse_tx( self, txn, block_header, block_hash, txindex ):
        """
        Given a transaction message and its index in the block,
        go and create a "verbose" transaction structure
        containing all the information in a nice, easy-to-read
        dict (i.e. like what bitcoind would give us).

        Does not work on coinbase transactions.
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
            "vin": [],
            "vout": [],

            # non-standard; added by us for virtualchain
            "txindex": txindex,
            "relindex": None,
            "senders": None,
            "fee": 0,
            "nulldata": None
        }

        for inp in txn.tx_in:
            input_info = self.parse_tx_input( inp )
            txdata['vin'].append( input_info )

        for i in xrange(0, len(txn.tx_out)):
            outp = txn.tx_out[i]
            output_info = self.parse_tx_output( i, outp )
            txdata['vout'].append( output_info )

        # we know how many senders there have to be 
        txdata['senders'] = [None] * len(txdata['vin'])
        return txdata


    def make_sender_info( self, block_hash, txn, i ):
        """
        Make sender information bundle for a particular input of
        a nulldata transaction.

        We'll use it to go find the transaction output that
        funded the ith input of the given tx.
        """

        inp = txn['vin'][i]
        ret = {
            # to be filled in...
            "amount_in": 0,
            "scriptPubKey": None,
            "addresses": None,

            # for matching the input this sender funded
            "txindex": txn['txindex'],
            "relindex": txn['relindex'],
            "output_index": inp['vout'],
            "block_hash": block_hash,
            "relinput": i
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
        tx_hashes = [block.txns[i].calculate_hash() for i in xrange(0, len(block.txns))]
        mr = pybitcoin.MerkleTree( tx_hashes ).root()

        if mr != header['merkle_root']:
            log.error("Merkle root of %s (%s) mismatch: expected %s, got %s" % (block_hash, height, header['merkle_root'], mr))
            return
 
        nulldata_txs = []
        relindex = 0
        for txindex in xrange(0, len(block.txns)):

            txdata = self.parse_tx( block.txns[txindex], header, block_hash, txindex )

            # if there is no nulldata output, then we don't care about this one.
            has_nulldata = False
            nulldata_payload = None
            for outp in txdata['vout']:
                if outp['scriptPubKey']['type'] == 'nulldata':
                    has_nulldata = True
                    nulldata_payload = bitcoin.deserialize_script(outp['scriptPubKey']['hex'])[1]
                    if type(nulldata_payload) not in [str, unicode]:
                        # this is a malformed OP_RETURN, where the varint that should follow OP_RETURN doesn't have the data behind it.
                        # just take the data after the varint, no matter what it is (i.e. "6a52" will be "")
                        nulldata_payload = outp['scriptPubKey']['hex'][4:]

            # count all txs processed
            self.num_txs_processed += 1

            if not has_nulldata:
                continue

            # remember nulldata
            txdata['nulldata'] = nulldata_payload 
            
            # calculate total output (part of fee; will be debited when we discover the senders)
            txdata['fee'] -= sum( int(out['value'] * 10**8) for out in txdata['vout'] )

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
            for i in xrange(0, len(txn['vin'])):

                # record information about the transaction
                # that created this input (so we can go find
                # it later).
                inp = txn['vin'][i]
                sender_txid = inp['txid']
                inp_sender_outp = inp['vout']

                if str(sender_txid) not in sender_txhashes:
                    sender_txhashes.append( str(sender_txid) )

                sinfo = self.make_sender_info( block_hash, txn, i )

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
                    "version": 1,
                    "locktime": 0,
                    "vin": [],
                    "vout": [
                        {
                            "n": 0xffffffff,
                            "scriptPubKey": {
                                "asm": "",
                                "hex": "",
                                "type": "coinbase"
                            },
                            "value": 0      # not really 0, but we don't care about coinbases anyway 
                        }
                    ],
                    "txid": txid,
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

                try:

                    tx_bin = txhex.decode('hex')
                    assert tx_bin is not None

                    tx_hash_bin = pybitcoin.bin_double_sha256(tx_bin)[::-1]
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
        

