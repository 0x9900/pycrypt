pycrypt
=======

Pycrypt is a tool to easily encrypt and decrypt files.

**note:** *The current version of pycrypt use a AES.*

Example:
========

Encrypt a file:

```shell
 $ ./pycrypt.py encrypt -e 'super secure key' -s foo.txt -t foo.aes

Decrypt a file:

```shell
 $ ./pycrypt.py decrypt -e 'super secure key' -s foo.aes -t bar.txt
```
