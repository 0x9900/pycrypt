pycrypt
=======

Pycrypt is a tool to easily encrypt and decrypt files.

If you forget your key you will not be able to decrypt your encrypted
files.

**note:** *The current version of pycrypt use AES.*

Example:
========

Encrypt a file:
---------------
```shell
 $ ./pycrypt.py encrypt -e 'super secure key' -s foo.txt -t foo.aes
```

Decrypt a file:
---------------
```shell
 $ ./pycrypt.py decrypt -e 'super secure key' -s foo.aes -t bar.txt
```
