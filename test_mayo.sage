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
    from sagelib.mayo \
    import PrintVersion, \
           decode_vec, \
           encode_vec, \
           decode_matrix, \
           encode_matrix, \
           decode_matrices, \
           encode_matrices, \
           bitslice_m_vec, \
           unbitslice_m_vec, \
           partial_encode_matrices, \
           partial_decode_matrices, \
           bitsliced_mul_add, \
           SetupMAYO, \
           Mayo1, \
           Mayo2
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

bit_slicing = True

def check_decode_encode(mayo_ins):
    F16 = GF(16, names=('x',))
    (x,) = F16._first_ngens(1)
    assert x**4 + x+1 == 0

    seed = mayo_ins.random_bytes(mayo_ins.sk_seed_bytes)
    s = shake_256(seed).digest(int(mayo_ins.O_bytes + mayo_ins.P1_bytes))
    s1 = s[:mayo_ins.O_bytes]

    # check encode_vec and decode_vec
    vec1 = decode_vec(s1, len(s)*2)
    s_check1 = encode_vec(vec1)

    # check encode_mat and decode_mat
    o = decode_matrix(s1, mayo_ins.n-mayo_ins.o, mayo_ins.o)
    s_check2 = encode_matrix(o, mayo_ins.n-mayo_ins.o, mayo_ins.o)

    # check encode_mat and decode_mat triangular
    p = s[mayo_ins.O_bytes:mayo_ins.O_bytes + mayo_ins.P1_bytes]
    p1 = decode_matrices(p, mayo_ins.m, mayo_ins.n-mayo_ins.o, mayo_ins.n-mayo_ins.o, triangular=True)
    p_check = encode_matrices(p1, mayo_ins.m, mayo_ins.n - mayo_ins.o, mayo_ins.n-mayo_ins.o, triangular=True)

    if (bit_slicing == True):
        # check bitslice_m_vec
        vec = decode_vec(s[0:mayo_ins.m//2], mayo_ins.m)
        a,b,c,d = bitslice_m_vec(vec)
        vec_check = unbitslice_m_vec((a,b,c,d), mayo_ins.m)
        assert(vec == vec_check)

        # check partial_encode_matrices
        pp = s[mayo_ins.O_bytes:mayo_ins.O_bytes + mayo_ins.P1_bytes]
        pp1 = partial_decode_matrices(pp, mayo_ins.m, mayo_ins.n-mayo_ins.o, mayo_ins.n-mayo_ins.o, triangular=True)
        pp_check = partial_encode_matrices(pp1, mayo_ins.m, mayo_ins.n - mayo_ins.o, mayo_ins.n-mayo_ins.o, triangular=True)
        assert(pp == pp_check)

        # check bitsliced_mul
        v = vector([F16.random_element() for _ in range(mayo_ins.m)])
        bs = bitslice_m_vec(v)
        a = F16.random_element()
        out = vector([x*a for x in v])
        bs_out = bitsliced_mul_add(bs, a, (0,0,0,0))
        out_check = unbitslice_m_vec(bs_out, mayo_ins.m)
        assert(out == out_check)

        # ignoring possible half bytes@decode_mat
        return s1 == s_check1 and s1[:-1] == s_check2[:-1] and p == p_check and vec == vec_check and pp == pp_check and out == out_check

    return s1 == s_check1 and s1[:-1] == s_check2[:-1] and p == p_check

"""
Takes as input a signed message sm, an expanded
public key pk and outputs 1 (invalid) or 0 (valid)
and the message if the signature was valid
"""
def check_sig(mayo_ins, sm, epk):
    mlen = len(sm) - mayo_ins.sig_bytes
    sig = sm[:mayo_ins.sig_bytes]
    msg = sm[mayo_ins.sig_bytes:]

    valid = mayo_ins.verify(sig, msg, epk)
    if valid:
        return valid, msg
    else:
        return valid, None


path="vectors"

def write_json(new_data, filename='data.json'):
    with open(path + filename,'r+') as file:
        file_data = json.load(file)
        file_data.append(new_data)
        file.seek(0)
        json.dump(file_data, file, indent = 4)

def generic_test(mayo_ins, det):
    if (det == True):
        print("Running Tests for deterministic for: " + mayo_ins.name)
    else:
        print("Running Tests for random for: " + mayo_ins.name)

    print("with: " + mayo_ins.set_name)
    vectors = {}

    if (det == True):
        seed = bytes.fromhex("5d1969a5d103bec1876455194e900a4bf3b0930141b0f0d270311f9d0b121ceaabf767f8616e109701dd1eaca8d8f7a7")
        mayo_ins.set_drbg_seed(seed)
    else:
        mayo_ins.aes = False

    assert (check_decode_encode(mayo_ins)) # Test the encode and decode functionality

    start_time = timeit.default_timer()
    # Generate the public and secret key, and check their size
    csk, cpk = mayo_ins.compact_key_gen()
    assert (len(csk) == mayo_ins.csk_bytes)
    assert (len(cpk) == mayo_ins.cpk_bytes)

    # Expand the public and secret key, and check their size
    epk = mayo_ins.expand_pk(cpk)
    assert len(epk) == mayo_ins.epk_bytes
    esk = mayo_ins.expand_sk(csk)
    assert len(esk) == mayo_ins.esk_bytes
    print("Time taking generating and expanding keys:")
    print(timeit.default_timer() - start_time)

    if (bit_slicing == True):
        start_time = timeit.default_timer()
        # Generate the public and secret key with bitslicing, and check their size
        csk_bs, cpk_bs = mayo_ins.compact_key_gen_bitsliced()
        assert (len(csk_bs) == mayo_ins.csk_bytes)
        assert (len(cpk_bs) == mayo_ins.cpk_bytes)
        if (det == True):
            assert (csk_bs == csk)
            assert (cpk_bs == cpk)

        # Expand the public and secret key with bitslicing, and check their size
        epk_bs = mayo_ins.expand_pk(cpk)
        assert len(epk_bs) == mayo_ins.epk_bytes
        esk_bs = mayo_ins.expand_sk_bitsliced(csk)
        assert len(esk_bs) == mayo_ins.esk_bytes
        assert epk_bs == epk
        assert esk_bs == esk
        print("Time taking generating and expanding keys (bitsliced):")
        print(timeit.default_timer() - start_time)

    start_time = timeit.default_timer()
    # Sign a message with the public key
    msg = b'1234'
    sig = mayo_ins.sign(msg, esk)
    assert (len(sig) == mayo_ins.sig_bytes + len(msg))
    print("Time taking signing:")
    print(timeit.default_timer() - start_time)

    start_time = timeit.default_timer()
    # Verify the signature on the given message
    valid, msg2 = check_sig(mayo_ins, sig, epk)
    assert(valid == True)
    assert(msg2 == msg)
    print("Time taking verifying:")
    print(timeit.default_timer() - start_time)

    if (valid == True and msg2 == msg):
        print("All tests are sucessful for: " + mayo_ins.set_name)
    else:
       print("Test failed for: " + mayo_ins.set_name)
       return

    vector = {}
    vector["identifier"] = mayo_ins.set_name
    vector["secret-key"] = csk.hex()
    vector["public-key"] = cpk.hex()
    vector["message"] = msg.hex()
    vector["signature"] = sig.hex()

    if (det == True):
       write_json(vector, filename='/vectors-det.json')
    else:
       write_json(vector, filename='/vectors.json')

    mayo_ins.aes = False

class TestDeterministicTestValues(unittest.TestCase):
    def generic_deterministic_test(self, mayo_ins, count):
        generic_test(mayo_ins, True)

    def test_mayo_1(self):
        self.generic_deterministic_test(Mayo1, 1)

    def test_mayo_2(self):
        self.generic_deterministic_test(Mayo2, 1)

class TestRandomTestValues(unittest.TestCase):
    def generic_random_test(self, mayo_ins, count):
        for _ in range(count):
            generic_test(mayo_ins, False)

    def test_mayo_1(self):
        self.generic_random_test(Mayo1, 2)

    def test_mayo_2(self):
        self.generic_random_test(Mayo2, 2)

if __name__ == "__main__":
    print("Running all tests for version:")

    init = []
    fp = open(path + "/vectors-det.json", 'wt')
    json.dump(init, fp)
    fp.close()
    fp = open(path + "/vectors.json", 'wt')
    json.dump(init, fp)
    fp.close()

    PrintVersion()
    unittest.main()
