#!/usr/bin/python

from setuptools import setup, find_packages

setup(
    name='virtualchain',
    version='0.0.1',
    url='https://github.com/blockstack/virtualchain',
    license='MIT',
    author='Onename',
    author_email='support@onename.com',
    description='A library for constructing virtual blockchains within a cryptocurrency\'s blockchain',
    keywords='blockchain bitcoin btc cryptocurrency data',
    packages=find_packages(),
    download_url='https://github.com/blockstack/blockstore/archive/master.zip',
    zip_safe=False,
    include_package_data=True,
    install_requires=[
        'pybitcoin>=0.8.2',
        'ecdsa>=0.11',
        'pybitcointools>=1.1.15',
        'utilitybelt>=0.2.2'
    ],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
