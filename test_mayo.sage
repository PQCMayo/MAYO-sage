#!/usr/bin/sage
# vim: syntax=python

import sys
import json

try:
    from sagelib.mayo \
    import PrintVersion
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

def main():
	PrintVersion()

if __name__ == "__main__":
    main()
