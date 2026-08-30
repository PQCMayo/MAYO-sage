#!/usr/bin/sage
# vim: syntax=python

from operator import xor
from Cryptodome.Cipher import AES

def aes_128_ctr_iv(key, iv, out_len):
    """
    AES_CTR(seed, iv, l) from the specification: the first l bytes of the
    concatenation of the AES-128 encryptions of the blocks iv ^ 0, iv ^ 1, ...,
    iv ^ (ceil(l/16) - 1), using seed as the key. The block index is xored
    big-endian into the last four bytes of iv.
    (We use operator.xor rather than ^, which sage preparses into **.)
    """
    out_len = int(out_len)
    cipher = AES.new(key, AES.MODE_ECB)

    blocks = b""
    for ctr in range((out_len + 15)//16):
        blocks += bytes(map(xor, iv, int(ctr).to_bytes(16, "big")))

    return cipher.encrypt(blocks)[:out_len]

def aes_128_ctr(key, out_len):
    """
    AES_CTR(seed, l) := AES_CTR(seed, 0^128, l)
    """
    return aes_128_ctr_iv(key, bytes(16), out_len)
