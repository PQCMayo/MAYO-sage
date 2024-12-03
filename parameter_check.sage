# Test if the parameter sets are valid
K = GF(16); # finite field with 16 elements
x = K.gen()
assert(x**4 + x + 1 == 0) # Z2[x]/(x4 +x+1).
print("Field with 16 elements is correct")

Kz = PolynomialRing(K,'z')
Kz.inject_variables()

# irreducible polynomials
F = {}
F[64] = z**64 + x**3*z**3 + x*z**2 + x**3
F[78] = z**78 + z**2 + z + x**3
F[108] = z**108 + (x**2+x+1)*z**3 + z**2 + x**3
F[142] = z**142 + z**3 + x**3*z**2 + x**2

for m in F:
    print("F_"+str(m)+" is irreducible: ", F[m].is_irreducible())


for m,k in [(78, 10), (64, 4), (108, 11), (142, 12)]:
    Fm = F[m]

    CM = companion_matrix(Fm)

    BM = matrix(K, k*m, k*m)
    l = k*(k+1)/2-1
    assert(l+1 < m)
    for i in range(k):
        for j in range(k-1,i-1,-1):
            BM[ i*m:(i+1)*m, j*m:(j+1)*m ] = CM**l;
            BM[ j*m:(j+1)*m, i*m:(i+1)*m ] = CM**l;
            l -= 1

    rk = BM.rank()
    print("m,k,rank:", m,k, rk)
    assert(rk == m*k)

print("Parameters are correct")