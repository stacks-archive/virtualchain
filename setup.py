#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Virtualchain
    ~~~~~
    copyright: (c) 2014-15 by Halfmoon Labs, Inc.
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

from setuptools import setup, find_packages

# to set __version__
exec(open('virtualchain/version.py').read())

setup(
    name='virtualchain',
    version=__version__,
    url='https://github.com/blockstack/virtualchain',
    license='GPLv3',
    author='Blockstack.org',
    author_email='support@blockstack.org',
    description='A library for constructing virtual blockchains within a cryptocurrency\'s blockchain',
    keywords='blockchain bitcoin btc cryptocurrency data',
    packages=find_packages(),
    download_url='https://github.com/blockstack/virtualchain/archive/master.zip',
    zip_safe=False,
    include_package_data=True,
    install_requires=[
        'pybitcoin>=0.9.8',
        'bitcoin>=1.1.42',
        'utilitybelt>=0.2.6',
        'protocoin>=0.2',
        'simplejson>=3.8.2'
    ],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
