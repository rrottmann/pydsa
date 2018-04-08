#!/usr/bin/env python

from setuptools import setup

setup(
    name='pydsa',
    version='0.13',
    description='Python DSA library',
    author='Reiner Rottmann',
    author_email='reiner@rottmann.it',
    url='https://github.com/rrottmann/pydsa',
    packages=['pydsa'],
    long_description="""\
    pydsa is a simple implementation of the DSA Signature Algorithm
    """,
    classifiers=[
          'License :: OSI Approved :: MIT License',
          "Programming Language :: Python",
          "Development Status :: 4 - Beta",
          "Intended Audience :: Developers",
          "Topic :: Internet",
    ],
    keywords='crypto, DSA, signature',
    license='MIT License, see LICENSE',
    install_requires=[ 'setuptools']
    )
