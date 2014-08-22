pycrypt
=======

Pycrypt is a tool to easily encrypt and decrypt files.

If you forget your key you will not be able to decrypt your encrypted
files.

**note:** *The current version of pycrypt use AES.*

Example:
========

<<<<<<< HEAD
**Encrypt a file:**
=======
Encrypt a file:
---------------
>>>>>>> 0bb38b460f41c680873053cea8674a26c9b3b1d1
```shell
 $ ./pycrypt.py encrypt -e 'super secure key' -s foo.txt -t foo.aes
```

<<<<<<< HEAD
**Decrypt a file:**
=======
Decrypt a file:
---------------
>>>>>>> 0bb38b460f41c680873053cea8674a26c9b3b1d1
```shell
 $ ./pycrypt.py decrypt -e 'super secure key' -s foo.aes -t bar.txt
```
