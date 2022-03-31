# Virtualchain

Virtualchain is a on-chain protocol, where additional data can be embedded on an existing blockchain like Bitcoin to construct a virtual blockchain with new features. Virtualchain can add new functionality to Bitcoin without modifying the Bitcoin protocol.

This repository has a virtualchain implementation in Python 2.7 for processing and maintaining virtual blockchains. You can read more about the design and implementation of virtualchain in our [DCCL 2016 paper](https://www.zurich.ibm.com/dccl/papers/nelson_dccl.pdf).

## What is a virtual blockchain?

A *virtual blockchain* is a layer that sits on top of a blockchain that introduces new functionality and operations without requiring changes to the underlying blockchain. The nodes of the underlying blockchain network are not aware of the presence of virtual blockchains. New operations are defined in the virtual blockchain layer and are encoded in the metadata of valid blockchain transactions. Blockchain nodes do see the raw transactions, but the logic for processing the virtual blockchain operations only exists at the virtual blockchain level.

The rules for accepting or rejecting virtual blockchain operations are also defined in the Virtualchain library. Accepted operations are processed by Virtualchain to construct a database that stores information on the global state of the system along with state changes at any given blockchain block.  The resulting Virtualchain processes obtain a [fork\*-consistent](http://www.scs.stanford.edu/~jinyuan/bft2f.pdf) view of the database.

In a sense, a virtual blockchain is a state machine on top of an underlying blockchain, and the Virtualchain library can be used to build a variety of state machines. One such example can be seen in the .id namespace on Bitcoin through Blockstack, which defined a global naming system as a virtual blockchain state machine.  You can use this library to create any type of state machine that you can think of.

One way to think of these state machines is as standalone smart contracts. When defining state machines with the Virtualchain library, programmers have the flexibility and boundless potential at their fingertips that they do when working with a Turing complete smart contract system, and at the same time, once a state machine is defined and operational, developers have the benefits of working with a specialized and operationally-efficient environment.

## How scalable is virtualchain?

The scalability of virtualchain really depends on the scalability of the underlying blockchain. In our implementation on Bitcoin, every virtualchain transaction is a Bitcoin transaction. In 2017, we saw that Bitcoin transaction fees went up to $40-$50 even for low-value virtualchain transactions. Also, embedding a lot of additional data directly in the Bitcoin blockchain is not scalable in general. Lessons from the virtualchain work led to the design of the [Stacks programming layer](https://github.com/stacks-network/stacks), which maintains a separate ledger from Bitcoin and only stores hashes of data at the Bitcoin layer.

## Installation

This package provides the `virtualchain` Python package.  To install from
source, do the following:

```
$ git clone https://github.com/stacks-network/virtualchain
$ cd virtualchain
$ python2 ./setup.py build
$ sudo python2 ./setup.py install
```

This package is also available via `pip`.  Be sure that your `pip` is configured
to install packages for Python 2.7.x.

```
$ pip install virtualchain
```
