#!/usr/bin/sage
# vim: syntax=python

import os
from Cryptodome.Cipher import AES
from sage.cpython.string import str_to_bytes

class AES128_CTR:
    def __init__(self, key=None, out_len=0):
        self.out_length = out_len
        self.key = key
        self.V   = bytes([0])*16

    def __increment_counter(self):
        int_V = int.from_bytes(self.V, 'big')
        new_V = (int_V + 1) % 2**(8*16) # V = (V+1) mod 2^{blocklen}, which is 16.
        hex_V = int(new_V.hex(), 16) # horrible conversion due to sage
        self.V = hex_V.to_bytes(16, byteorder='big')

    def aes_ctr_gen(self):
        out = b""
        nonce = bytes([0])*8
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
        out = cipher.encrypt(bytes([0])*self.out_length)
        output_bytes = out[:int(self.out_length)]
        return output_bytes
