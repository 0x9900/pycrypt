#!/usr/bin/env python
#

from distutils.core import setup
from pycrypt import __version__ as VERSION

setup(name="pycrypt",
      version=VERSION,
      description="Simple tool to encrypt files.",
      author="Fred C.",
      author_email="github-fred@hidzz.com",
      url="https://github.com/0x9900/pycrypt",
      requires = ['pycrypto', 'keyring' ],
      scripts = [ 'pycrypt.py' ],
      license="BSD"
      )
