#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpfwd/license.html
#
from Cryptodome import Random
from Cryptodome.Cipher import AES


class AESCipher(object):
    @staticmethod
    def pad(s, BS=16):
        return s + (BS - len(s) % BS) * bytes((BS - len(s) % BS,))

    @staticmethod
    def unpad(s):
        return s[0:-s[-1]]

    def encrypt(self, key, raw):
        raw = self.pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key.encode('iso-8859-1'), AES.MODE_CBC, iv)
        return iv + cipher.encrypt(raw)

    def decrypt(self, key, enc):
        iv = enc[:16]
        cipher = AES.new(key.encode('iso-8859-1'), AES.MODE_CBC, iv)
        return self.unpad(cipher.decrypt(enc[16:]))

encrypt = AESCipher().encrypt
decrypt = AESCipher().decrypt
