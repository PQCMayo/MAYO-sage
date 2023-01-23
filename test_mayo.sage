#!/usr/bin/sage
# vim: syntax=python

import sys
import json
from hashlib import shake_256

try:
    from sagelib.mayo \
    import PrintVersion, \
           decode_vec, \
           encode_vec, \
           decode_mat, \
           encode_mat, \
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
    o = decode_mat(s1, 1, mayo_ins.n-mayo_ins.o, mayo_ins.o, triangular=False)[0]
    s_check2 = encode_mat([o], 1, mayo_ins.n-mayo_ins.o, mayo_ins.o, triangular=False)

    # check encode_mat and decode_mat triangular
    p = s[mayo_ins.O_bytes:mayo_ins.O_bytes + mayo_ins.P1_bytes]
    p1 = decode_mat(p, mayo_ins.m, mayo_ins.n-mayo_ins.o, mayo_ins.n-mayo_ins.o, triangular=True)
    p_check = encode_mat(p1, mayo_ins.m, mayo_ins.n - mayo_ins.o, mayo_ins.n-mayo_ins.o, triangular=True)

    # ignoring possible half bytes@decode_mat
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

def main():
    print("Running Tests for:")
    PrintVersion()
    mayo_ins = SetupMAYO("mayo_1")
    assert (check_decode_encode(mayo_ins)) # Test the encode and decode functionality

    # Generate the public and secret key, and check their size
    csk, cpk = mayo_ins.compact_key_gen()
    assert (len(csk) == mayo_ins.csk_bytes)
    assert (len(cpk) == mayo_ins.cpk_bytes)

    # Expand the public and secret key, and check their size
    epk = mayo_ins.expand_pk(cpk)
    assert len(epk) == mayo_ins.epk_bytes
    esk = mayo_ins.expand_sk(csk)
    assert len(esk) == mayo_ins.esk_bytes

    # Sign a message with the public key
    msg = b'1234'
    sig = mayo_ins.sign(msg, esk)
    assert (len(sig) == mayo_ins.sig_bytes + len(msg))

    # Verify the signature on the given message
    valid, msg2 = check_sig(mayo_ins, sig, epk)
    assert(valid == True)
    assert(msg2 == msg)

    if (valid == True and msg2 == msg):
      print("All tests are sucessful.")
    else:
      print("Tests failed.")

if __name__ == "__main__":
    main()
