#!/usr/bin/sage
# vim: syntax=python

# Test if the parameter sets are valid.
#
# Run with `--mds` to also verify exhaustively that every whipping schedule is
# MDS. That check computes a determinant over K for each of the C(2k,k)-1 pairs
# of equally sized row and column subsets, which is 2.7 million of them for
# k = 12, so it runs for hours and is off by default. The MDS property of these
# schedules was established when they were sampled; see
# sample_whipping_schedule.sage in the submission package, which checks it more
# cheaply using Jacobi complementary minors.

import sys

try:
    from sagelib.mayo \
    import DEFAULT_PARAMETERS, \
           Mayo
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + str(e))

from itertools import combinations

check_mds = "--mds" in sys.argv

K16 = GF(16, names=('x',))
(x,) = K16._first_ngens(1)
assert x**4 + x + 1 == 0  # Z2[x]/(x^4 + x + 1)
print("Field with 16 elements is correct")

for params in DEFAULT_PARAMETERS.values():
    mayo = Mayo(params)
    n, m, o, k = mayo.n, mayo.m, mayo.o, mayo.k
    print()
    print(f"{mayo.name}: (n, m, o, k) = ({n}, {m}, {o}, {k})")

    # the conditions on k from the specification
    assert k < n - o
    assert k*o >= m
    assert k*(k+1)//2 <= m
    print("  k is admissible")

    # f is irreducible of degree m, so K = F16[z]/(f) is a field
    f = mayo.f
    assert f.degree() == m
    assert f.is_irreducible()
    print(f"  f_{m} is irreducible")

    # the whipping schedule is symmetric and its upper diagonal entries are the
    # exponents 0, ..., k(k+1)/2 - 1, each occurring exactly once
    Z = mayo.Z
    assert all(Z[i][j] == Z[j][i] for i in range(k) for j in range(k))
    assert sorted(Z[i][j] for i in range(k) for j in range(i, k)) == list(range(k*(k+1)//2))
    print("  the whipping schedule is a symmetric permutation of the exponents")

    # {E_ij} is multiplication by Z[i][j] = z^Z[i][j] in K, so the k*m x k*m
    # matrix over F16 it assembles has full rank iff Z is invertible over K
    theta = mayo.fx.gen()
    ZK = matrix(mayo.fx, k, k, [theta**Z[i][j] for i in range(k) for j in range(k)])
    assert ZK.is_invertible()

    CM = companion_matrix(f)
    BM = matrix(K16, k*m, k*m)
    for i in range(k):
        for j in range(k):
            BM[i*m:(i+1)*m, j*m:(j+1)*m] = CM**Z[i][j]
    assert BM.rank() == k*m
    print(f"  the {k*m} x {k*m} matrix of the E_ij has full rank")

    if check_mds:
        # MDS: every square submatrix of Z has full rank over K
        for size in range(1, k+1):
            for rows in combinations(range(k), size):
                for cols in combinations(range(k), size):
                    assert ZK[list(rows), list(cols)].det() != 0, (rows, cols)
            print(f"    every {size} x {size} submatrix of Z is invertible")
    else:
        print("  (skipping the exhaustive MDS check, run with --mds to enable it)")

print()
print("Parameters are correct")
