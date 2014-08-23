#!/usr/bin/env python2.7
#
# Author: Fred C. <github-fred@hidzz.com>
# Module: pycrypt.py
#
"""
pycrypt: Encrypt and decript your files.

"""

from __future__ import print_function

__author__ = "Fred C."
__email__ = "<github-fred@hidzz.com>"
__version__ = '0.1.1'

import argparse
import getpass
import keyring
import os
import struct
import sys

from Crypto import Random
from Crypto.Cipher import AES
from hashlib import md5

BLOCK_SIZE = 4096
PROGRAM_NAME = os.path.basename(__file__)

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
  encrypt_cmd.set_defaults(func='encrypt')
  encrypt_cmd.add_argument('-e', '--encryption-key')
  encrypt_cmd.add_argument('-s', '--source-file', required=True)
  encrypt_cmd.add_argument('-t', '--target-file')

  decrypt_cmd = commands.add_parser('decrypt')
  decrypt_cmd.set_defaults(func='decrypt')
  decrypt_cmd.add_argument('-e', '--encryption-key')
  decrypt_cmd.add_argument('-s', '--source-file', required=True)
  decrypt_cmd.add_argument('-t', '--target-file')

  options = parser.parse_args()
  return options

def get_key(token, program=PROGRAM_NAME):
  """Try to find the encryption key for that token in the keyring. If
  the key cannot be found prompt the user.

  """
  key = keyring.get_password(program, token)
  if key:
    return key

  # the key hasn't been found in the keyring. Request for a new one.
  while True:
    key = getpass.getpass('Encryption key: ')
    if len(key) >= 8:
      break
    parser.error("A minimum of 8 characters encryption key should be provided")

  return key

def save_key(token, key, program=PROGRAM_NAME):
  """Save the key in the keyring"""
  try:
    keyring.set_password(program, token, key)
  except keyring.errors.PasswordSetError as err:
    print(err, file=sys.stderr)

def make_token(filename):
  """Generate a token use saving the key in the keyring.

  TODO: This token is the filename wihout extension. Change this for
  something better.

  """
  return os.path.splitext(os.path.basename(filename))[0]


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

    if args.target_file and os.path.exists(args.target_file):
      raise IOError('Target file: "{}" already exists.'.format(
        args.target_file))

    key = args.encryption_key or get_key(make_token(args.source_file))
    if args.func == 'encrypt':
      encrypt_file(key, args.source_file, args.target_file)
      save_key(make_token(args.source_file), key)
    elif args.func == 'decrypt':
      decrypt_file(key, args.source_file, args.target_file)
  except IOError as error:
    print(error, file=sys.stderr)
    exit(os.EX_OSERR)
  else:
    print(msg.format(args))

if __name__ == '__main__':
  try:
    main()
  except KeyboardInterrupt:
    print("Interrupted by user")
    sys.exit(os.EX_USAGE)
  sys.exit(os.EX_OK)
