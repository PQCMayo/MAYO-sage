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
           encode_matrices
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

class TestDeterministicDRBGTestValues(unittest.TestCase):
    def generic_test_mayo_known_answer(self, Mayo, filename):
        with open(filename) as f:
            kat_data = f.read()
            parsed_data = parse_kat_data(kat_data)

            for data in parsed_data.values():
                seed, msg, pk, sk, sm = data.values()

                # Seed DRBG with KAT seed
                Mayo.set_drbg_seed(seed)

                # Assert keygen matches
                _sk, _pk = Mayo.compact_key_gen()
                self.assertEqual(pk, _pk)
                self.assertEqual(sk, _sk)

                epk = Mayo.expand_pk(_pk)
                esk = Mayo.expand_sk(_sk)

                # Assert signature matches
                sig = Mayo.sign(msg, esk)
                self.assertEqual(sig, sm)

            print("Success for: " + Mayo.name)

    def test_mayo1_known_answer(self):
        return self.generic_test_mayo_known_answer(Mayo1, "KAT/PQCsignKAT_24_MAYO_1.rsp")

    def test_mayo2_known_answer(self):
        return self.generic_test_mayo_known_answer(Mayo2, "KAT/PQCsignKAT_24_MAYO_2.rsp")

    def test_mayo3_known_answer(self):
        return self.generic_test_mayo_known_answer(Mayo3, "KAT/PQCsignKAT_32_MAYO_3.rsp")

    def test_mayo5_known_answer(self):
        return self.generic_test_mayo_known_answer(Mayo5, "KAT/PQCsignKAT_40_MAYO_5.rsp")

if __name__ == "__main__":
    print("Running KAT tests:")
    print("This process is slow")

    init = []
    unittest.main()
