#!/usr/bin/sage
# vim: syntax=python

import sys
import json
import timeit
import time
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
           SetupMAYO
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

def check_decode_encode(mayo_ins):
    seed = mayo_ins.random_bytes(mayo_ins.sk_seed_bytes)
    s = shake_256(seed).digest(int(mayo_ins.O_bytes + mayo_ins.P1_bytes))
    s1 = s[:mayo_ins.O_bytes]

    # check encode_vec and decode_vec
    vec1 = decode_vec(s1, len(s)*2)
    s_check1 = encode_vec(vec1)

    # check encode_mat and decode_mat
    o = decode_matrix(s1, mayo_ins.n-mayo_ins.o, mayo_ins.o, triangular=False)
    s_check2 = encode_matrix(o, mayo_ins.n-mayo_ins.o, mayo_ins.o, triangular=False)

    # check encode_mat and decode_mat triangular
    p = s[mayo_ins.O_bytes:mayo_ins.O_bytes + mayo_ins.P1_bytes]
    p1 = decode_matrices(p, mayo_ins.m, mayo_ins.n-mayo_ins.o, mayo_ins.n-mayo_ins.o, triangular=True)
    p_check = encode_matrices(p1, mayo_ins.m, mayo_ins.n - mayo_ins.o, mayo_ins.n-mayo_ins.o, triangular=True)

    # check bitslice_m_vec
    vec = decode_vec(s[0:mayo_ins.m//2], mayo_ins.m)
    a,b,c,d = bitslice_m_vec(vec)
    vec_check = unbitslice_m_vec((a,b,c,d), mayo_ins.m)

    # check partial_encode_matrices
    pp = s[mayo_ins.O_bytes:mayo_ins.O_bytes + mayo_ins.P1_bytes]
    pp1 = partial_decode_matrices(pp, mayo_ins.m, mayo_ins.n-mayo_ins.o, mayo_ins.n-mayo_ins.o, triangular=True)
    pp_check = partial_encode_matrices(pp1, mayo_ins.m, mayo_ins.n - mayo_ins.o, mayo_ins.n-mayo_ins.o, triangular=True)

    # ignoring possible half bytes@decode_mat
    return s1 == s_check1 and s1[:-1] == s_check2[:-1] and p == p_check and vec == vec_check and pp == pp_check

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

def main(path="vectors"):
    print("Running Tests for:")
    PrintVersion()
    mayo_params = "mayo_1"
    mayo_ins = SetupMAYO(mayo_params)
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
      print("All tests are sucessful.")
    else:
      print("Tests failed.")
      return

    vectors = {}
    vectors["identifier"] = mayo_params
    vectors["secret-key"] = csk.hex()
    vectors["public-key"] = cpk.hex()
    vectors["message"] = msg.hex()
    vectors["signature"] = sig.hex()

    fp = open(path + "/vectors.json", 'wt')
    json.dump(vectors, fp, sort_keys=True, indent=2)
    fp.write("\n")
    fp.close()

if __name__ == "__main__":
    main()
