#!/usr/bin/sage
# vim: syntax=python

import sys
import json
import timeit
import time
import os
import unittest
from hashlib import shake_256

try:
    from sagelib.utilities \
    import decode_vec, \
           encode_vec, \
           decode_matrix, \
           encode_matrix, \
           decode_matrices, \
           encode_matrices, \
           bitslice_m_vec, \
           unbitslice_m_vec, \
           partial_encode_matrices, \
           partial_decode_matrices, \
           bitsliced_mul_add
    from sagelib.mayo \
    import setupMayo, \
           Mayo1, \
           Mayo2, \
           Mayo3, \
           Mayo5, \
           printVersion
    from sagelib.aes256_ctr_drbg \
    import AES256_CTR_DRBG
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

def parse_kat_data(data):
    parsed_data = {}
    count_blocks = data.split('\n\n')
    for block in count_blocks[1:-1]:
        block_data = block.split('\n')
        count, seed, mlen, msg, pk, sk, smlen, sm = [line.split(" = ")[-1] for line in block_data]
        parsed_data[count] = {
            "seed": bytes.fromhex(seed),
            "msg": bytes.fromhex(msg),
            "pk": bytes.fromhex(pk),
            "sk": bytes.fromhex(sk),
            "sm": bytes.fromhex(sm),
        }
    return parsed_data

# Generate deterministic vector values. If you want to generate many of them, increase
# count
class TestDeterministicDRBGTestValues(unittest.TestCase):
    def generic_test_mayo_known_answer(self, Mayo, filename):
        with open(filename) as f:
            kat_data = f.read()
            parsed_data = parse_kat_data(kat_data)

            for data in parsed_data.values():
                seed, pk, sk, msg, sm = data.values()

                # Seed DRBG with KAT seed
                Mayo.set_drbg_seed(seed)

                # Assert keygen matches
                _pk, _sk = Mayo.compact_key_gen()
                self.assertEqual(pk, _pk)
                self.assertEqual(sk, _sk)

                epk = mayo_ins.expand_pk(cpk)
                esk = mayo_ins.expand_sk(csk)
                # Assert signature matches

                sig = mayo_ins.sign(msg, esk)
                self.assertEqual(sig, sm)
                #self.assertEqual(ss, _ss)

                # Assert decapsulation matches
                #__ss = Kyber.dec(ct, sk)

    def test_mayo1_known_answer(self):
        return self.generic_test_mayo_known_answer(Mayo1, "KAT/PQCsignKAT_24_MAYO_1.rsp")

if __name__ == "__main__":
    print("Running KAT tests:")

    init = []
    unittest.main()
