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

from .hashing import bin_double_sha256, bin_to_hex_reversed, hex_to_bin_reversed

def calculate_merkle_pairs(bin_hashes, hash_function=bin_double_sha256):
    """
    Calculate the parents of a row of a merkle tree.
    Takes in a list of binary hashes, returns a binary hash.

    The returned parents list is such that parents[i] == hash(bin_hashes[2*i] + bin_hashes[2*i+1]).
    """
    hashes = list(bin_hashes)

    # if there are an odd number of hashes, double up the last one
    if len(hashes) % 2 == 1:
        hashes.append(hashes[-1])

    new_hashes = []
    for i in range(0, len(hashes), 2):
        new_hashes.append(hash_function(hashes[i] + hashes[i+1]))

    return new_hashes


def verify_merkle_path(merkle_root_hex, serialized_path, leaf_hash_hex, hash_function=bin_double_sha256):
    """
    Verify a merkle path.  The given path is the path from two leaf nodes to the root itself.

    merkle_root_hex is a little-endian, hex-encoded hash.
    serialized_path is the serialized merkle path
    path_hex is a list of little-endian, hex-encoded hashes.

    Return True if the path is consistent with the merkle root.
    Return False if not.
    """
    
    merkle_root = hex_to_bin_reversed(merkle_root_hex)
    leaf_hash = hex_to_bin_reversed(leaf_hash_hex)

    path = MerkleTree.path_deserialize(serialized_path)
    path = [{'order': p['order'], 'hash': hex_to_bin_reversed(p['hash'])} for p in path]

    if len(path) == 0:
        raise ValueError("Empty path")

    cur_hash = leaf_hash
    for i in range(0, len(path)):
        if path[i]['order'] == 'l':
            # left sibling
            cur_hash = hash_function(path[i]['hash'] + cur_hash)
        elif path[i]['order'] == 'r':
            # right sibling
            cur_hash = hash_function(cur_hash + path[i]['hash'])
        elif path[i]['order'] == 'm':
            # merkle root
            assert len(path) == 1
            return cur_hash == path[i]['hash']

    return cur_hash == merkle_root


class MerkleTree(object):
    def __init__(self, hex_hashes, hash_function=bin_double_sha256):
        """
        Make a merkle tree.
        * hashes is a list of hex-encoded hashes.
        * hash_function is a callable that takes a string as input and outputs a hash.

        The Merkle tree hashes will be converted to big-endian.
        """
        if len(hex_hashes) == 0:
            raise ValueError("At least one hash is required.")

        self.rows = []
        
        # convert to binary big-endian
        hashes = [hex_to_bin_reversed(h) for h in hex_hashes]
        
        # build the rows of the merkle tree
        self.rows.append(hashes)
        while len(hashes) > 1:
            hashes = calculate_merkle_pairs(hashes, hash_function=hash_function)
            self.rows.append(hashes)


    def get(self, row_index, column_index):
        """
        Get the hash at a given row and column index.
        Raise ValueError on out-of-bounds
        """
        if row_index + 1 > len(self.rows):
            raise ValueError("There aren't that many rows.")

        row = self.rows[row_index]
        if column_index + 1 > len(row):
            raise ValueError("There aren't that many items in that row.")

        return row[column_index]


    def root(self):
        """
        Returns the hex-encoded root (little-endian)
        """
        # return the merkle root
        bin_merkle_root = self.rows[-1][0]
        return bin_to_hex_reversed(bin_merkle_root)


    @classmethod
    def path_serialize(cls, path):
        """
        Given a list of [{'hash': ..., 'order': ...}], serialize it to a string.
        """
        # make it into a netstring
        path_parts = ['{}-{}'.format(p['order'], p['hash']) for p in path]
        path_ns_parts = ['{}:{},'.format(len(pp), pp) for pp in path_parts]
        path_str = ''.join(path_ns_parts)
        return '{}:{},'.format(len(path_str), path_str)
        

    @classmethod
    def path_deserialize(cls, serialized_path):
        """
        Given a netstring of path parts, go and parse it back into [{'hash': ..., 'order': ...}]
        """
        def _chomp_netstring_payload(s):
            try:
                ns_len_str, ns_body = s.split(':', 1)
                ns_len = int(ns_len_str)
                assert ns_body[ns_len] == ','
                ns_payload = ns_body[:ns_len]
                return ns_payload, ns_body[ns_len+1:]
            except:
                raise ValueError("Invalid netstring '{}'".format(s))

        path_str, extra = _chomp_netstring_payload(serialized_path)
        if len(extra) > 0:
            raise ValueError("Danlging data in '{}'".format(serialized_path))

        path = []
        while True:
            path_part, path_str = _chomp_netstring_payload(path_str)
            try:
                order, hash_hex = path_part.split('-', 1)
                assert order in ['l', 'r', 'm']
                path.append({'order': order, 'hash': hash_hex})
            except:
                raise ValueError("Invalid path entry {}".format(path_part))

            if len(path_str) == 0:
                break

        return path


    def path(self, leaf_hash_hex, serialize=True):
        """
        Get the path (as a list of hashes) from the leaf hash to the root.
        leaf_hash_hex is hex-encoded, little-endian.

        The returned path will be a list of {'hash': hex-encoded little-endian hash, 'order': 'l' or 'r'}

        Raise ValueError if leaf_hash is not present in the tree.
        """
        
        leaf_hash = hex_to_bin_reversed(leaf_hash_hex)

        # sanity check
        found = False
        ri = None       # index into self.rows where leaf_hash occurs.  Note that self.rows[0] is the bottom (leaves) of the Merkle tree.
        for ri, row in enumerate(self.rows):
            found = found or (leaf_hash in row)
            if found:
                break

        if not found:
            raise ValueError("Hash {} is not present in Merkle tree {}".format(leaf_hash, self.root()))

        path = []
        cur_hash = leaf_hash
        for i in range(ri, len(self.rows)-1):
            # find sibling
            sibling = {}
            leaf_index = self.rows[i].index(cur_hash)
            if leaf_index % 2 == 0:
                # append left sibling
                sibling_hash = None
                if leaf_index+1 >= len(self.rows[i]):
                    # double-up the last hash
                    assert leaf_index+1 == len(self.rows[i]), 'leaf_index = {}, i = {}, len(rows[i]) = {}, rows[0] = {}'.format(leaf_index, i, len(self.rows[i]), ','.join(r.encode('hex') for r in self.rows[0]))
                    sibling_hash = self.rows[i][-1]
                else:
                    sibling_hash = self.rows[i][leaf_index+1]

                sibling['hash'] = bin_to_hex_reversed(sibling_hash)
                sibling['order'] = 'r'
            else:
                # append right sibling
                sibling['hash'] = bin_to_hex_reversed(self.rows[i][leaf_index-1])
                sibling['order'] = 'l'

            path.append(sibling)

            # find parent
            cur_hash = self.rows[i+1][leaf_index/2]
        
        if len(path) == 0:
            # single-node merkle tree
            path = [{'hash': bin_to_hex_reversed(self.rows[-1][0]), 'order': 'm'}]

        if not serialize:
            return path
        else:
            return self.path_serialize(path)


if __name__ == "__main__":
    print 'test merkle tree'

    import os

    fixtures = [
        [os.urandom(32) for _ in range(0,32)],
        [os.urandom(32) for _ in range(0,31)],
        [os.urandom(32) for _ in range(0,1)],
        ['abcde' for _ in range(0,32)],
        ['abcde' for _ in range(0,31)],
        ['abcde' for _ in range(0,1)],
        [h.decode('hex') for h in ['02125585a9b812347c21c9f1827463ccb93a5096fb1f846b83652353fbb53418','f5c366f5aa9f21b4823ac167e8a062805f54bf99cb56be3fd1bd500bd5a20609','7358bf608d6ed1010cc86c1be5df4f773e7a2d6f00f3f3284bd742a55ea4a382','952dfe16fb9de054e291ef5d6dbacf381a93dffc12fdea74305fe3723016bf4b','a6c38dd08339595abd473c2351018d6d9ec968a44a53c6f06666141ec52568ae','aa950063768b7de1dbb0ae3bc3d872b3b7c8ac63defa02c7fe5e7cae93d11d23','c8d64f8ac60cbae1dd97cf373a4114097586fee63a8fed2e46add59eba7c8072','6a49bc047d9330cadeee4558da2a4da76aff1419d33f4b3d2800a55f26977fe4','b1eb9cae861e31b7177ce87fc3afde1618f69349dc1bf3e11deb86ea8586cf67','d8335aca79d8a0d20edd653905cc5d7a4a3e1986269d56b5949d08baad0046df','b58bfc1ab8c3557fb5de0014c58469f9ff6b68f407983fbe0b5387bd6485fc86']],
    ]

    for i, data in enumerate(fixtures):
        print '\nfixture {} ({} entries)\n'.format(i, len(data))

        data_hashes = [bin_to_hex_reversed(bin_double_sha256(d)) for d in data]

        mt = MerkleTree(data_hashes)
        mps = []
        for j, dh in enumerate(data_hashes):
            mp = mt.path(dh, serialize=False)
            mp_str = mt.path_serialize(mp)
            recombined_mp = mt.path_deserialize(mp_str)

            assert mp == recombined_mp

            mps.append(mp_str)
            
            print 'dh[{}] = {}'.format(j, dh)
            print 'path from {} to {} is {}'.format(dh, mt.root(), mp)
            print 'path from {} to {} is {}'.format(dh, mt.root(), mp_str)

        for i, mp in enumerate(mps):
            assert verify_merkle_path(mt.root(), mp, data_hashes[i]), 'failed to verify {} to {}'.format(data_hashes[i], mt.root())

        for i, mp in enumerate(mps):
            # corrupt a hash
            mp_obj = mt.path_deserialize(mp)
            mp_obj[-1]['hash'] = mp_obj[-1]['hash'][::-1]
            mp = mt.path_serialize(mp_obj)

            assert not verify_merkle_path(mt.root(), mp, data_hashes[i]), 'failed to verify {} to {}'.format(data_hashes[i], mt.root())
