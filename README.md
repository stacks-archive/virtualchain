# virtualchain

[![Slack](http://slack.blockstack.org/badge.svg)](http://slack.blockstack.org/)

A Python library for creating virtual blockchains on top of a well-known cryptocurrency

## What is a Virtualchain?
![Virtualchains](https://blockstack.org/images/article-diagrams/virtual-blockchain.png)

A *virtual blockchain* or *virtualchain* is a separate layer that sits on top of
a blockchain and introduces new functionality/operations without requiring
changes to the underlying blockchain. The underlying
blockchain nodes are agnostic to the presence of virtualchains. New operations
are defined in the virtualchain layer and are
encoded in valid blockchain transactions as additional
metadata. Blockchain nodes do see the raw transactions,
but the logic to process virtualchain operations only exists
at the virtualchain level.

The rules for accepting or rejecting virtualchain operations
are also defined in the virtualchain. Accepted operations
are processed by the virtualchain to construct a
database that stores information on global state of the
system along with state changes at any given blockchain
block. Virtualchains can be used to build a variety of
state machines. Currently, [blockstack-server](http://github.com/blockstack/blockstack-server) defines only a single
state machine; a global naming system. You can use this python library to create other types of state machines.
