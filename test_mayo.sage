#!/usr/bin/sage
# vim: syntax=python

import sys
import json

try:
    from sagelib.mayo \
    import PrintVersion, \
           SetupMAYO
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

def main():
    print("Running Tests")
    PrintVersion()
    mayo_ins = SetupMAYO("mayo_1")
    assert (mayo_ins.check_decode_encode()) # Test the encode and decode functionality

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
    valid, msg2 = mayo_ins.open(sig, epk)
    assert(valid == True)
    assert(msg2 == msg)

    if (valid == True and msg2 == msg):
      print("All tests are sucessful.")
    else:
      print("Tests failed.")

if __name__ == "__main__":
    main()
