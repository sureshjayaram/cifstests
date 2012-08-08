#!/usr/bin/env python

"""
Distutils setup script for cifstests module.
"""

from distutils.core import setup

setup(name='cifstests',
      version='0.1',
      author='Suresh Jayaraman',
      author_email='sjayaraman@suse.com',
      # url
      # download_url
      description='Regression tests for cifs client',
      package_dir={'': 'cifstests'},
      scripts = ['cifstests/testcifs.py']
      keywords='cifs tests regression',
      license='GPLv2',
)
