
# test if the parameter sets are good

K = GF(16);
x = K.gen()
assert(x**4 + x + 1 == 0)
Kz = PolynomialRing(K,'z')
Kz.inject_variables()

# irreducible polynomials for m = 64, 96, and 128 
F64 = z**64 + x**3*z**3 + x*z**2 + x**3
F96 = z**96 + x*z**3 + x*z + x
F128 = z**128 + x*z**4 + x**2*z**3 + x**3*z + x**2

assert (F64).is_irreducible()
assert (F96).is_irreducible()
assert (F128).is_irreducible()


for m,k in [(64, 1), (64, 2), (64, 4), (64, 8), (96, 10), (128, 11)]:
    if m == 64:
        F = F64
    if m == 96:
        F = F96
    if m == 128:
        F = F128

    CM = companion_matrix(F)

    BM = matrix(K, k*m, k*m)
    l = k*(k+1)/2-1
    for i in range(k):
        for j in range(k-1,i-1,-1):
            BM[ i*m:(i+1)*m, j*m:(j+1)*m ] = CM**l;
            BM[ j*m:(j+1)*m, i*m:(i+1)*m ] = CM**l;
            l -= 1

    assert(l+1 < m)
    assert(BM.rank() == m*k)

print("OK")