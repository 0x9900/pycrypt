#!/usr/bin/env python2.7
#
# Author: Fred Cirera <github-fred@hidzz.com>
# Module: pycrypt.py
#
"""
pycrypt:

"""

from __future__ import print_function

__author__ = "Fred Cirera"
__email__ = "<fred@twitter.com>"
__version__ = '0.1.0'

import argparse
import os
import struct
import sys

from Crypto import Random
from Crypto.Cipher import AES
from hashlib import md5

BLOCK_SIZE = 4096

def parse_arguments():
  """Parse the arguments. Returns an ArgumentParser object."""

  parser = argparse.ArgumentParser(
    prog=os.path.basename(__file__),
    description=__doc__,
    formatter_class=argparse.RawDescriptionHelpFormatter
  )

  parser.add_argument('-v', '--version', action='version', version=__version__,
                      help='Print the version')
  # sub-commands
  commands = parser.add_subparsers(title='Commands',
                                   description='Valid commands are:')

  encrypt_cmd = commands.add_parser('encrypt')
  encrypt_cmd.set_defaults(func=encrypt_file)
  encrypt_cmd.add_argument('-e', '--encryption-key', required=True)
  encrypt_cmd.add_argument('-s', '--source-file', required=True)
  encrypt_cmd.add_argument('-t', '--target-file')

  decrypt_cmd = commands.add_parser('decrypt')
  decrypt_cmd.set_defaults(func=decrypt_file)
  decrypt_cmd.add_argument('-e', '--encryption-key', required=True)
  decrypt_cmd.add_argument('-s', '--source-file', required=True)
  decrypt_cmd.add_argument('-t', '--target-file')

  options = parser.parse_args()
  return options


def encrypt_file(key, filename, target):
  """
  Encrypt a file using Advanced Encryption Standard (AES)
  Note: If you lose the key the file can't be decrypted.

  Args:
    key: encryption key
    filename: filename to encrypt
    target: encrypted filename

  Raise:
    IOError: raised on failed file operations.

  """
  password = md5(key).hexdigest()
  iv = Random.new().read(AES.block_size)
  encryptor = AES.new(password, AES.MODE_CBC, iv)
  filesize = os.path.getsize(filename)

  with open(target, 'w') as fd_out:
    with open(filename, 'rb') as fd_in:
      fd_out.write(struct.pack('<Q', filesize))
      fd_out.write(iv)
      while True:
        chunk = fd_in.read(BLOCK_SIZE)
        if not chunk:
          break
        elif len(chunk) % AES.block_size != 0:
          chunk += ' ' * (AES.block_size - len(chunk) % AES.block_size)
        fd_out.write(encryptor.encrypt(chunk))


def decrypt_file(key, filename, target=None):
  """
  Decrypt a file.

  Args:
    key: decryption key
    filename: encrypted file to decrypt
    target: decrypted file if no file name is specifies the file is
             decryted file on stdout

  Raise:
    IOError: raised on failed file operations.

  """
  password = md5(key).hexdigest()
  with open(filename, 'rb') as infile:
    fsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
    iv = infile.read(AES.block_size)
    decryptor = AES.new(password, AES.MODE_CBC, iv)
    try:
      outfile = open(target, 'wb') if target else sys.stdout
      while True:
        chunk = infile.read(BLOCK_SIZE)
        if not chunk:
          break
        outfile.write(decryptor.decrypt(chunk))
    finally:
      if outfile != sys.stdout:
        outfile.truncate(fsize)
        outfile.close()


def main():
  args = parse_arguments()
  msg = 'Source: "{0.source_file}" Destination: "{0.target_file}"'
  try:
    if not os.path.exists(args.source_file):
      raise IOError('Source file: "{}" not found.'.format(args.source_file))

    if os.path.isdir(args.target_file):
      src_file_name = os.path.basename(args.source_file)
      target_file = os.path.join(args.target_file, src_file_name)
    else:
      target_file = args.target_file

    if os.path.isfile(args.target_file):
      raise IOError('Target file: "{}" already exists.'.format(
        args.target_file))

    print(msg.format(args))
    args.func(args.encryption_key, args.source_file, args.target_file)

  except IOError as error:
    print(error, file=sys.stderr)
    exit(os.EX_OSERR)

if __name__ == '__main__':
  main()
