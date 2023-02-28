#!/usr/bin/sage
# vim: syntax=python

from hashlib import shake_256
try:
    from sagelib.utilities \
    import decode_vec, \
           encode_vec, \
           decode_matrix, \
           decode_matrices, \
           encode_matrices, \
           partial_encode_matrices, \
           partial_decode_matrices, \
           upper, \
           bitsliced_upper, \
           bitsliced_matrices_add, \
           bitsliced_matrices_matrix_mul, \
           bitsliced_matrix_matrices_mul
    from sagelib.aes256_ctr_drbg \
    import AES256_CTR_DRBG
    from sagelib.aes128_ctr \
    import AES128_CTR
except ImportError as e:
    print("Error importing AES CTR DRBG. Have you tried installing requirements?")
    print(f"ImportError: {e}\n")
    print("Sage will work perfectly fine with system randomness")

# Current version of the library
VERSION = "MAYO-00"

F16 = GF(16, names=('x',))
(x,) = F16._first_ngens(1)
assert x**4 + x+1 == 0
R = F16['z']
(z,) = R._first_ngens(1)
# import itertools
# F.<x> = GF(16)
# R.<y> = F[]
# m = 72
# for c0 in F:
#     if c0 in ZZ:
#         continue
#     f0 = y^m + c0
#     for w in range(1,3):
#         for js in itertools.combinations(list(range(1,m)), w):
#             f = f0 + sum(y^j for j in js)
#             if f.is_irreducible():
#                 print(f)

assert (z**64 + x**3*z**3 + x*z**2 + x**3).is_irreducible()
assert (z**96 + x*z**3 + x*z + x).is_irreducible()
assert (z**128 + x*z**4 + x**2*z**3 + x**3*z + x**2).is_irreducible()

# The parameters for the MAYO variants. They are:
# q (the size of the finite field F_q), m (the number of multivariate quadratic polynomials in the public key),
# n (the number of variables in the multivariate quadratic polynomials in the public key),
# o (the dimension of the oil space), k (the whipping parameter)
DEFAULT_PARAMETERS = {
    "mayo_1": {
        "name": "mayo1",
        "n": 66,
        "m": 64,
        "o": 8,
        "k": 9,
        "q": 16,
        "sk_salt_bytes": 24,
        "pk_bytes": 16,
        "digest_bytes": 32,
        "f": z**64 + x**3*z**3 + x*z**2 + x**3
    },
    "mayo_2": {
        "name": "mayo2",
        "n": 78,
        "m": 64,
        "o": 18,
        "k": 4,
        "q": 16,
        "sk_salt_bytes": 24,
        "pk_bytes": 16,
        "digest_bytes": 32,
        "f": z**64 + x**3*z**3 + x*z**2 + x**3
    },
    "mayo_3": {
        "name": "mayo3",
        "n": 99,
        "m": 96,
        "o": 10,
        "k": 11,
        "q": 16,
        "sk_salt_bytes": 32,
        "pk_bytes": 16,
        "digest_bytes": 48,
        "f": z**96 + x*z**3 + x*z + x
    },
    "mayo_5": {
        "name": "mayo5",
        "n": 133,
        "m": 128,
        "o": 12,
        "k": 12,
        "q": 16,
        "sk_salt_bytes": 40,
        "pk_bytes": 16,
        "digest_bytes": 64,
        "f": z**128 + x*z**4 + x**2*z**3 + x**3*z + x**2
    },
}

class Mayo:
    def __init__(self, parameter_set):
        self.set_name = str(parameter_set)
        self.name = parameter_set["name"]
        self.n = parameter_set["n"]
        self.m = parameter_set["m"]
        self.o = parameter_set["o"]
        self.k = parameter_set["k"]
        self.q = parameter_set["q"]
        self.aes = False

        self.f = parameter_set["f"]

        self.fx = R.quotient_ring(self.f)

        self.q_bytes = (math.log(self.q, 2)/8)
        self.m_bytes = math.ceil(self.q_bytes*self.m)

        self.O_bytes = math.ceil((self.n - self.o)*self.o * self.q_bytes)
        self.v_bytes = math.ceil((self.n - self.o) * self.q_bytes)
        self.r_bytes = math.ceil(self.k*self.o*self.q_bytes)
        self.P1_bytes = math.ceil(
            self.m*math.comb((self.n-self.o+1), 2) * self.q_bytes)
        self.P2_bytes = math.ceil(self.m*(self.n - self.o)*self.o * self.q_bytes)
        self.P3_bytes = math.ceil(self.m*math.comb((self.o+1), 2) * self.q_bytes)

        self.sk_seed_bytes = parameter_set["sk_salt_bytes"]
        self.salt_bytes = parameter_set["sk_salt_bytes"]
        self.pk_seed_bytes = parameter_set["pk_bytes"]
        self.digest_bytes = parameter_set["digest_bytes"]

        self.sig_bytes = math.ceil(
            self.k * self.n * self.q_bytes) + self.salt_bytes
        self.epk_bytes = self.P1_bytes + self.P2_bytes + self.P3_bytes
        self.cpk_bytes = self.P3_bytes + self.pk_seed_bytes
        self.csk_bytes = self.sk_seed_bytes
        self.esk_bytes = self.sk_seed_bytes + \
            self.O_bytes + self.P1_bytes + self.P2_bytes

        assert self.q == 16

    def random_bytes(self, len):
        if (self.aes == True):
            return self.drbg.random_bytes(len)

        return os.urandom(len)

    def set_drbg_seed(self, seed):
        """
        Setting the seed switches the entropy source
        from os.urandom to AES256 CTR DRBG

        Note: requires pycryptodomex for AES impl.
        """
        self.drbg = AES256_CTR_DRBG(seed)
        self.aes = True

    def reseed_drbg(self, seed):
        """
        Reseeds the DRBG, errors if a DRBG is not set.

        Note: requires pycryptodome for AES impl.
        """
        if self.drbg is None:
            raise Warning(f"Cannot reseed DRBG without first initialising. Try using `set_drbg_seed`")
        else:
            self.drbg.reseed(seed)

    def compact_key_gen(self):
        """
        outputs a pair (csk, cpk) in B^{csk_bytes} x B^{cpk_bytes}, where csk and cpk
        are compact representations of a secret key and public key.
        """

        seed_sk = self.random_bytes(self.sk_seed_bytes) # seed_sk $<- B^(sk_seed bytes)
        s = shake_256(seed_sk).digest(int(self.pk_seed_bytes + self.O_bytes)) # S <- SHAKE256(seedsk, pk seed bytes + O bytes)
        seed_pk = s[0:self.pk_seed_bytes] # seed_pk <- s[0 : pk_seed_bytes]

        o_bytestring = s[self.pk_seed_bytes:self.pk_seed_bytes + self.O_bytes]
        o = decode_matrix(o_bytestring, self.n-self.o, self.o) # o <- Decode_o(s[pk_seed_bytes : pk_seed_bytes + o_bytes])

        ctr = AES128_CTR(seed_pk, self.P1_bytes + self.P2_bytes)
        p = ctr.aes_ctr_gen() # p <- AES-128-CTR(seedpk, P1_bytes + P2_bytes)

        p1 = decode_matrices(p[0:self.P1_bytes], self.m, self.n -
                        self.o, self.n-self.o, triangular=True) # {P_i^(1)}_(i in [m]) <- Decode_(P(1))(p[0 : P1_bytes])
        p2 = decode_matrices(p[self.P1_bytes:self.P1_bytes+self.P2_bytes],
                        self.m, self.n-self.o, self.o, triangular=False) # {P_i^(2)}_(i in [m]) <- Decode_(P(2))(p[P1_bytes : P1_bytes + P2_bytes])
        # for i from 0 to m − 1 do
        #   P(3) <- Upper(−O^(T)P_i^(1) O − O^(T)P_i^((2))
        p3 = [matrix(F16, self.o, self.o) for _ in range(self.m)]
        for i in range(self.m):
            p3[i] = upper(- o.transpose()*p1[i]*o - o.transpose()*p2[i], self.o)

        cpk = seed_pk + encode_matrices(p3, self.m, self.o, self.o, triangular=True) # cpk <- seedpk || EncodeP(3)({P_i^(3)}i in [m])
        csk = seed_sk # csk <- seedsk
        return csk, cpk

    def compact_key_gen_bitsliced(self):
        """
        outputs a pair (csk, cpk) in B^{csk_bytes} x B^{cpk_bytes}, where csk and cpk
        are compact representations of a secret key and public key
        """
        seed_sk = self.random_bytes(self.sk_seed_bytes)

        s = shake_256(seed_sk).digest(int(self.pk_seed_bytes + self.O_bytes))
        seed_pk = s[:self.pk_seed_bytes]

        o = decode_matrix(s[self.pk_seed_bytes:self.pk_seed_bytes +
                       self.O_bytes], self.n-self.o, self.o)

        ctr = AES128_CTR(seed_pk, self.P1_bytes + self.P2_bytes)
        p = ctr.aes_ctr_gen()

        p1 = partial_decode_matrices(p[:self.P1_bytes], self.m, self.n -
                        self.o, self.n-self.o, triangular=True)

        p2 = partial_decode_matrices(p[self.P1_bytes:self.P1_bytes+self.P2_bytes],
                        self.m, self.n-self.o, self.o, triangular=False)

        p3 = [ [ None for _ in range(self.o)] for _ in range(self.o) ]

        # compute p1o + p2
        p1o_p2 = bitsliced_matrices_add(bitsliced_matrices_matrix_mul(p1,o),p2)
        # compute p3
        p3 = bitsliced_matrix_matrices_mul(o.transpose(), p1o_p2)
        p3 = bitsliced_upper(p3)

        cpk = seed_pk + partial_encode_matrices(p3, self.m, self.o, self.o, triangular=True)
        csk = seed_sk
        return csk, cpk

    def expand_sk(self, csk):
        """
        takes as input csk, the compact representation of a secret key, and outputs sk in B^{sk_bytes},
        an expanded representation of the secret key
        """
        assert len(csk) == self.csk_bytes

        seed_sk = csk[0:self.sk_seed_bytes] # seedsk <- csk[0 : sk seed bytes]
        s = shake_256(seed_sk).digest(int(self.pk_seed_bytes + self.O_bytes)) # s <- SHAKE256(seedsk, pk_seed_bytes + o_bytes)
        seed_pk = s[0:self.pk_seed_bytes] # seed_pk <- s[0 : pk seed bytes]

        o_bytestring = s[self.pk_seed_bytes:self.pk_seed_bytes + self.O_bytes]
        o = decode_matrix(o_bytestring, self.n-self.o, self.o) # o <- Decode_o(s[pk_seed_bytes : pk_seed_bytes + o_bytes])

        ctr = AES128_CTR(seed_pk, self.P1_bytes + self.P2_bytes)
        p = ctr.aes_ctr_gen() # p <- AES-128-CTR(seedpk, P1_bytes + P2_bytes)

        p1 = decode_matrices(p[0:self.P1_bytes], self.m, self.n -
                        self.o, self.n-self.o, triangular=True) # {P_i^(1)}_(i in [m]) <- Decode_(P(1))(p[0 : P1_bytes])
        p2 = decode_matrices(p[self.P1_bytes:self.P1_bytes+self.P2_bytes],
                        self.m, self.n-self.o, self.o, triangular=False) # {P_i^(2)}_(i in [m]) <- Decode_(P(2))(p[P1_bytes : P1_bytes + P2_bytes])

        # for i from 0 to (m − 1) do
        # L_i = (P_i^(1) + P_i^((1)T)) o + P_i^(2)
        l = [matrix(F16, self.n-self.o, self.o) for _ in range(self.m)]
        for i in range(self.m):
            l[i] = (p1[i] + p1[i].transpose())*o + p2[i]

        # sk = seed_sk || O bytestring || p[0 : P1 bytes] || Encode_L({L_i}i∈[m])
        esk = seed_sk + o_bytestring + p[0:self.P1_bytes] + encode_matrices(l, self.m, self.n-self.o, self.o, triangular=False)
        return esk

    def expand_sk_bitsliced(self, csk):
        """
        takes as input csk, the compact representation of a secret key, and outputs sk in B^{sk_bytes},
        an expanded representation of the secret key
        """
        assert len(csk) == self.csk_bytes

        seed_sk = csk
        s = shake_256(seed_sk).digest(int(self.pk_seed_bytes + self.O_bytes))
        seed_pk = s[:self.pk_seed_bytes]

        o_bytestring = s[self.pk_seed_bytes:self.pk_seed_bytes + self.O_bytes]
        o = decode_matrix(o_bytestring, self.n-self.o, self.o)

        ctr = AES128_CTR(seed_pk, self.P1_bytes + self.P2_bytes)
        p = ctr.aes_ctr_gen()

        p1 = partial_decode_matrices(p[:self.P1_bytes], self.m, self.n -
                        self.o, self.n-self.o, triangular=True)

        p2 = partial_decode_matrices(p[self.P1_bytes:self.P1_bytes+self.P2_bytes],
                        self.m, self.n-self.o, self.o, triangular=False)

        # compute (p1 + p1^t)
        p1_p1t = p1.copy()
        for i in range(self.n-self.o):
            p1_p1t[i][i] = (0,0,0,0)
            for j in range(i+1,self.n-self.o):
                p1_p1t[j][i] = p1_p1t[i][j]

        # compute (p1 + p1^t)*o + p2
        l = bitsliced_matrices_add(bitsliced_matrices_matrix_mul(p1_p1t, o), p2)

        esk = seed_sk + o_bytestring + p[:self.P1_bytes] + partial_encode_matrices(l, self.m, self.n-self.o, self.o, triangular=False)

        return esk

    def expand_pk(self, cpk):
        """
        takes as input cpk and outputs pk in B^{pk_bytes}
        """
        assert len(cpk) == self.cpk_bytes

        seed_pk = cpk[0:self.pk_seed_bytes] # seedpk <- cpk[0 : pk_seed_bytes]
        p3 = cpk[self.pk_seed_bytes:self.pk_seed_bytes+self.P3_bytes] # cpk[pk_seed_bytes : pk_seed_bytes + P3_bytes]

        ctr = AES128_CTR(seed_pk, self.P1_bytes + self.P2_bytes)
        p = ctr.aes_ctr_gen()

        return p + p3 #epk

    def sign(self, msg, esk):
        """
        takes an expanded secret key sk, a message M in B^*, and a salt in B^{salt_bytes} as
        input, and outputs a signature sig in B^{sig_bytes}
        """

        seed_sk = esk[0:self.sk_seed_bytes] # seed_sk <- sk[0 : sk seed bytes]
        # o <- Decode_o(sk[sk_seed bytes : sk_seed_bytes + O_bytes])
        o = decode_matrix(esk[self.sk_seed_bytes:self.sk_seed_bytes + self.O_bytes], self.n-self.o, self.o)

        # {P_i^(1)}_{i in m} <- Decode_P(1) (sk[sk_seed_bytes + O_bytes : sk_seed_bytes + O_bytes + P1_bytes])
        p1 = decode_matrices(esk[self.sk_seed_bytes + self.O_bytes:self.sk_seed_bytes +
                        self.O_bytes + self.P1_bytes], self.m, self.n-self.o, self.n-self.o, triangular=True)
        # {Li}_{i in m} <- Decode_L(sk[sk_seed_bytes + O_bytes + P1_bytes : sk_bytes])
        l = decode_matrices(esk[self.sk_seed_bytes + self.O_bytes + self.P1_bytes:self.esk_bytes],
                       self.m, self.n-self.o, self.o, triangular=False)

        # hash the message
        # M_digest <- SHAKE256(M, digest_bytes)
        h_msg = shake_256(msg).digest(int(self.digest_bytes))
        # R <- 0_{R_bytes} or R <- B^{R_bytes}
        r_salt = self.random_bytes(self.salt_bytes) # TODO: this can be optionally zero
        # salt <- SHAKE256(M_digest || R || seed_sk, salt_bytes)
        salt = shake_256(h_msg + r_salt + seed_sk).digest(int(self.salt_bytes))

        # t <- Decode_vec(m, SHAKE256(M_digest || salt, ⌈mlog(q)/8⌉))
        t = decode_vec(shake_256(h_msg + salt).digest(self.m_bytes), self.m)

        for ctr in range(256): # for ctr from 0 to 255 do
            # V <- SHAKE256(M_digest || salt || seedsk || ctr, k * v_bytes + ⌈ko log(q)/8⌉)
            V = shake_256(h_msg + salt + seed_sk +
                          bytes([ctr])).digest(int(self.k*self.v_bytes + self.r_bytes))

            # for i from 0 to k − 1 do
            #   v_i <- Decode_vec(n − o, V[i * v_bytes, (i + 1) * v_bytes])
            #   M_i <- 0_{m x o} in F_q^{m x o}
            #   for j from 0 to (m − 1) do
            #     M_i[j,:] <- v_i^(T)
            v = [vector(F16, self.n-self.o) for _ in range(self.k)]
            M = [matrix(F16, self.m, self.o) for _ in range(self.k)]
            for i in range(self.k):
                v[i] = decode_vec(
                    V[i*self.v_bytes:(i+1)*self.v_bytes], self.n-self.o)
                for j in range(self.m):
                    M[i][j, :] = v[i]*l[j]

            # r <- Decode_vec(ko, V [k * v_bytes : k * v_bytes + ⌈ko log(q)/8⌉])
            r = decode_vec(V[self.k*self.v_bytes:self.k*self.v_bytes+ self.r_bytes], self.k*self.o)

            # compute v_i*P1 for all i
            vip = [ [v[i]*p1[a] for a in range(self.m)] for i in range(self.k) ]

            # A <- 0_{m x ko} in F_q^{m x ko}
            A = matrix(F16, self.m, self.k*self.o)
            # y <- t, ell <- 0
            y = t
            ell = 0

            # for i from 0 to (k − 1) do
            #     for j from (k − 1) to i do
            for i in range(self.k):
                for j in range(self.k-1, i-1, -1):
                    u = vector(F16, self.m)
                    for a in range(self.m):
                        if i == j:
                            u[a] = vip[i][a]*v[j]                  # v[i]*p1[a]*v[j]
                        else:
                            u[a] = vip[i][a]*v[j] + vip[j][a]*v[i] # v[i]*p1[a]*v[j] + v[j]*p1[a]*v[i]

                    # convert to polysample_solutionnomial
                    u = self.fx(list(u))
                    # y <- y − z^ell * u
                    y = y - vector(z**ell * u)

                    # TODO: prettify this

                    # A[:, i * o : (i + 1) * o] <- A[:, i * o : (i + 1) * o] + E^{ell}M_{j}
                    tmp_x = [z**ell * self.fx(M[j][:, a].list()) for a in range(self.o)]
                    tmp_y = matrix([list(v) for v in tmp_x])
                    A[:, i*self.o:(i+1)*self.o] = A[:, i *
                                                    self.o:(i+1)*self.o] + tmp_y.transpose()
                    if i != j:
                        tmp_x = [z**ell * self.fx(M[i][:, a].list()) for a in range(self.o)]
                        tmp_y = matrix([list(v) for v in tmp_x])
                        # A[:, j * o : (j + 1) * o] <- A[:, j * o : (j + 1) * o] + E^{ell}M_{i}
                        A[:, j*self.o:(j+1)*self.o] = A[:, j *
                                                        self.o:(j+1)*self.o] + tmp_y.transpose()
                    ell = ell + 1

            x = self._sample_solution(A, y, r) # x <- SampleSolution(A, y, r)
            assert(A*x == y)
            if x is not None:
                break

        # sig <- 0_{kn}
        # for i from 0 to (k − 1) do
        # sig[i * n : (i + 1) * n] <- (v_i + Ox[i * o : (i + 1) * o]) || x[i * o : (i + 1) * o]
        sig = vector(F16, self.k*self.n)
        for i in range(self.k):
            sig[i*self.n:(i+1)*self.n] = vector(list(v[i] + o *
                                                     x[i*self.o:(i+1)*self.o])+list(x[i*self.o:(i+1)*self.o]))
        return encode_vec(sig) + salt + msg # TODO: we should remove msg from here

    def verify(self, sig, msg, epk):
        # TODO: msg is included in sig, we don't need it as an extra argument
        """
        takes as input a message M , an expanded
        public key pk, a signature sig outputs 1 (invalid) or 0 (valid)
        """

        assert len(sig) == self.sig_bytes
        assert len(epk) == self.epk_bytes

        # {P_i^(1)}_{i in m} <- Decode_P(1) (pk[0 : P1_bytes])
        p1 = decode_matrices(epk[:self.P1_bytes], self.m, self.n -
                        self.o, self.n-self.o, triangular=True)
        # {P_i^(2)}_{i in m} <- Decode_P(1) (pk[P1_bytes : P1_bytes + P2_bytes])
        p2 = decode_matrices(epk[self.P1_bytes:self.P1_bytes+self.P2_bytes],
                        self.m, self.n-self.o, self.o, triangular=False)
        # {P_i^(3)}_{i in m} <- Decode_P(1) (pk[P1 bytes + P2 bytes : P1 bytes + P2 bytes + P3 bytes])
        p3 = decode_matrices(epk[self.P1_bytes+self.P2_bytes:self.P1_bytes+self.P2_bytes+self.P3_bytes],
                        self.m, self.o, self.o, triangular=True)

        salt = sig[self.sig_bytes-self.salt_bytes:self.sig_bytes]

        # s <- decode_vec(kn, sig)
        s = decode_vec(sig, self.n*self.k)

        # for i from 0 to (k − 1) do
        #    s_i <- s[i * n : (i + 1) * n]
        s = [s[i*self.n:(i+1)*self.n] for i in range(self.k)]

        # hash the message
        # M_digest <- SHAKE256(M, digest_bytes)
        h_msg = shake_256(msg).digest(int(self.digest_bytes))
        # t <- Decodevec(m, SHAKE256(M || salt, ⌈mlog(q)/8⌉))
        t = decode_vec(shake_256(h_msg + salt).digest(self.m_bytes), self.m)

        # put p matrices together
        p = [ block_matrix( [[p1[a], p2[a]], [matrix(F16, self.o, self.n-self.o), p3[a]]]) for a in range(self.m) ]

        # compute s_i^T * {P_j}_{j in [m]} for all i
        sip = [ [s[i]*p[a] for a in range(self.m)] for i in range(self.k) ]

        ell = 0
        y = vector(F16, self.m)
        for i in range(self.k):
            for j in range(self.k-1,i-1,-1):
                u = vector(F16, self.m)
                for a in range(self.m):
                    if i == j:
                        u[a] = sip[i][a] * s[j]
                    else:
                        u[a] = sip[i][a] * s[j] + sip[j][a] * s[i]

                # convert to polynomial
                u = self.fx(list(u))

                # y <- y + E^(ell) * u
                y = y + vector(z**ell * u)

                # ell <- ell + 1
                ell = ell + 1

        return y == t

    def _ef(self,B):
        B = copy(B)
        assert B.nrows() == self.m
        assert B.ncols() == self.k*self.o + 1

        RS = B.row_space()

        pivot_row = 0
        pivot_col = 0
        while pivot_row < self.m and pivot_col < self.k*self.o + 1:
            next_pivot_row = pivot_row
            while next_pivot_row < self.m and B[next_pivot_row,pivot_col] == 0:
                next_pivot_row += 1
            if next_pivot_row == self.m:
                pivot_col += 1
            else:
                if next_pivot_row > pivot_row:
                    B.swap_rows(next_pivot_row, pivot_row)

                if B.row_space() != RS:
                    print("OOPS1")
                    return

                B.set_row(pivot_row, B.row(pivot_row)*B[pivot_row,pivot_col]^(-1))

                if B.row_space() != RS:
                    print("OOPS2")
                    return

                for row in range(pivot_row + 1, self.m):
                    for col in range(pivot_col+1, self.k*self.o + 1):
                        B[row,col] -= B[pivot_row,col]*B[row,pivot_col]
                    B[row,pivot_col] = 0
                    if B.row_space() != RS:
                        print("OOPS3", row)
                        return

                pivot_row += 1
                pivot_col += 1
        return B

    def _sample_solution(self, A, y, r):
        """
        takes as input a matrix A in F_q^{m x n} of rank m with n >= m,
        a vector y in F_q^m, and a vector r in F_q^n
        and outputs a solution x such that Ax = y
        """

        use_sage_linear_albegra = True

        if use_sage_linear_albegra:
            if A.rank() != self.m:
                return None
            x = A.solve_right(y - A*r)

            assert A*x == y - A*r
            return x + r

        # Above is the easy 'SAGE' way. To test if the spec is correct, we implement it below without using A.solve_right
        x = r
        y -= A*r

        Augmented_matrix = A.augment(matrix(self.m,1,y))
        Augmented_matrix = self._ef(Augmented_matrix)

        A = Augmented_matrix[:,0:self.k*self.o]
        y = Augmented_matrix.column(self.k*self.o)

        last_row_zero = True
        for i in range(self.k*self.o):
            if A[self.m-1,i] != 0:
                last_row_zero = False
                break

        if last_row_zero:
            return None

        for r in range(self.m-1,-1,-1):
            c = 0
            while A[r,c] == 0:
                c += 1
            x[c] += y[r]
            y -= vector(y[r]*A[:,c])

        return x

def setupMayo(params_type):
    if (params_type == ""):
      return None

    return Mayo(DEFAULT_PARAMETERS[params_type])

def printVersion():
    print(VERSION)

# Initialise with default parameters
Mayo1 = Mayo(DEFAULT_PARAMETERS["mayo_1"])
Mayo2 = Mayo(DEFAULT_PARAMETERS["mayo_2"])
Mayo3 = Mayo(DEFAULT_PARAMETERS["mayo_3"])
Mayo5 = Mayo(DEFAULT_PARAMETERS["mayo_5"])
