#!/usr/bin/sage
# vim: syntax=python

# import sys
from hashlib import shake_256
#from Crypto.Cipher import AES

# SL1 options: sk_seed_bytes = 32, pk_seed_bytes = 16, salt_bytes = 16
# pk: 556 B, sig: 568 B, vt: 42614784, (n,m,o,k,q): (68, 72, 5, 16, 16)
# pk: 740 B, sig: 466 B, vt: 26960232, (n,m,o,k,q): (68, 69, 6, 13, 16)
# pk: 954 B, sig: 398 B, vt: 18743384, (n,m,o,k,q): (68, 67, 7, 11, 16)
# pk: 1204 B, sig: 369 B, vt: 15711300, (n,m,o,k,q): (69, 66, 8, 10, 16)
# pk: 1456 B, sig: 300 B, vt: 9750528, (n,m,o,k,q): (69, 64, 9, 8, 16)*
# pk: 2128 B, sig: 272 B, vt: 7904288, (n,m,o,k,q): (71, 64, 11, 7, 16)
# pk: 2512 B, sig: 240 B, vt: 5971968, (n,m,o,k,q): (72, 64, 12, 6, 16)
# pk: 3856 B, sig: 211 B, vt: 4500000, (n,m,o,k,q): (75, 64, 15, 5, 16)
# pk: 5488 B, sig: 180 B, vt: 3115008, (n,m,o,k,q): (78, 64, 18, 4, 16)*
# pk: 9616 B, sig: 150 B, vt: 2032128, (n,m,o,k,q): (84, 64, 24, 3, 16)
# pk: 21328 B, sig: 131 B, vt: 1465472, (n,m,o,k,q): (107, 64, 36, 2, 16)

F16.<x> = GF(16)
assert x^4+x+1 == 0
R.<y> = F16[]
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

DEFAULT_PARAMETERS = {
    "mayo_1": {
        "n": 68,
        "m": 72,
        "o": 5,
        "k": 16,
        "q": 16,
        "f" : y^72 + y^5 + y^3 + x
    },
    "mayo_2": {
        "n": 68,
        "m": 69,
        "o": 6,
        "k": 13,
        "q": 16,
        "f" : y^69 + y^40 + x
    },
}



def decode_vec(t):
    t = [(t[i//2]>>i%2*4)&0xf for i in range(2*len(t))]
    return vector(map(F16.fetch_int, t))

def decode_mat(t, m, rows, columns, triangular):
    t = decode_vec(t)

    t = list(t[::-1])
    if triangular:
        As = [matrix(F16, rows, columns) for _ in range(m)]
        for i in range(rows):
            for j in range(i+1):
                for k in range(m):
                    As[k][i,j] = t.pop()
    else:
        As = [matrix(F16, rows, columns) for _ in range(m)]
        for i in range(rows):
            for j in range(columns):
                for k in range(m):
                    As[k][i,j] = t.pop()
    return As

def encode_mat(mat, m, rows, columns, triangular):
    if triangular:
        els = []
        for i in range(rows):
            for j in range(i, columns):
                for k in range(m):
                    els += [mat[k][i,j]]

        if len(els) % 2 == 1:
            els += [F16(0)]

        bs = []
        for i in range(len(els)/2):
            bs += [els[i*2].integer_representation() | (els[i*2+1].integer_representation() << 4)]
        return bytes(bs)
    else:
        els = []
        for i in range(rows):
            for j in range(columns):
                for k in range(m):
                    els += [mat[k][i,j]]

        if len(els) % 2 == 1:
            els += [F16(0)]

        bs = []
        for i in range(len(els)/2):
            bs += [els[i*2].integer_representation() | (els[i*2+1].integer_representation() << 4)]
        return bytes(bs)


class MAYO:
    def __init__(self, parameter_set):
        self.random_bytes = os.urandom
        self.n = parameter_set["n"]
        self.m = parameter_set["m"]
        self.o = parameter_set["o"]
        self.k = parameter_set["k"]
        self.q = parameter_set["q"]

        self.f = parameter_set["f"]

        self.fx = R.quotient_ring(self.f)

        self.q_bytes = (math.log(self.q,2)/8)
        self.m_bytes = math.ceil(self.q_bytes*self.m)

        self.O_bytes = math.ceil((self.n - self.o)*self.o*self.q_bytes)
        self.v_bytes = math.ceil((self.n - self.o)*self.q_bytes)
        self.P1_bytes = math.ceil(self.m*math.comb((self.n-self.o+1), 2)*self.q_bytes)
        self.P2_bytes = math.ceil(self.m*(self.n - self.o)*self.o*self.q_bytes)
        self.P3_bytes = math.ceil(self.m*math.comb((self.o+1), 2)*self.q_bytes)


        self.sk_seed_bytes = 32
        self.pk_seed_bytes = 16
        self.salt_bytes = 16

        self.sig_bytes = math.ceil(self.n * self.q_bytes) + self.salt_bytes
        self.epk_bytes = self.P1_bytes + self.P2_bytes + self.P3_bytes
        self.cpk_bytes = self.P3_bytes + self.pk_seed_bytes
        self.csk_bytes = self.sk_seed_bytes
        self.esk_bytes = self.sk_seed_bytes + self.O_bytes + self.P1_bytes + self.P2_bytes

        assert self.q == 16

    def compact_key_gen(self):
        """
        outputs a pair (csk, cpk) \in B^{csk_bytes} x B^{cpk_bytes}, where csk and cpk
        are compact representations of a Mayo secret key and public key
        """
        # F16.<y> = GF(16)

        seed_sk = self.random_bytes(self.sk_seed_bytes)                                      # seed_sk = B^sk_seed_bytes
        s = shake_256(seed_sk).digest(int(self.pk_seed_bytes + self.O_bytes))
        seed_pk = s[:self.pk_seed_bytes]

        o = decode_mat(s[self.pk_seed_bytes:self.pk_seed_bytes + self.O_bytes], 1, self.n-self.o, self.o, triangular=False)[0]

        p = shake_256(seed_pk).digest(int(self.P1_bytes + self.P2_bytes))

        p1 = decode_mat(p[:self.P1_bytes], self.m, self.n-self.o, self.n-self.o, triangular=True)
        p2 = decode_mat(p[self.P1_bytes:self.P1_bytes+self.P2_bytes], self.m, self.n-self.o, self.o, triangular=False)

        p3 = [matrix(F16, self.o, self.o) for _ in range(self.m)]
        for i in range(self.m):
            p3[i] = - o.transpose()*p1[i]*o - o.transpose()*p2[i]
            # Upper
            for j in range(1,self.o):
                for k in range(j-1):
                    p3[i][k,j] += p3[i][j,k]
                    p3[i][j,k] = 0

        cpk = seed_pk + encode_mat(p3, self.m, self.o, self.o, triangular=True)
        csk = seed_sk
        return csk, cpk

    def expand_sk(self, csk):
        """
        takes as input csk, the compact representation of a secret key, and outputs sk \in B^{sk_bytes},
        an expanded representation of the secret key
        """
        assert len(csk) == self.csk_bytes

        seed_sk = csk
        s = shake_256(seed_sk).digest(int(self.pk_seed_bytes + self.O_bytes))
        seed_pk = s[:self.pk_seed_bytes]

        o = decode_mat(s[self.pk_seed_bytes:self.pk_seed_bytes + self.O_bytes], 1, self.n-self.o, self.o, triangular=False)[0]

        p = shake_256(seed_pk).digest(int(self.P1_bytes + self.P2_bytes))

        p1 = decode_mat(p[:self.P1_bytes], self.m, self.n-self.o, self.n-self.o, triangular=True)
        p2 = decode_mat(p[self.P1_bytes:self.P1_bytes+self.P2_bytes], self.m, self.n-self.o, self.o, triangular=False)

        l = [matrix(F16, self.n-self.o, self.o) for _ in range(self.m)]
        for i in range(self.m):
            l[i] = (p1[i] + p1[i].transpose())*o + p2[i]

        esk = seed_sk + encode_mat([o], 1, self.n-self.o, self.o, triangular=False) + encode_mat(p1, self.m, self.n-self.o, self.n-self.o, triangular=True) + encode_mat(l, self.m, self.n-self.o, self.o, triangular=False)

        return esk

    def expand_pk(self, cpk):
        """
        takes as input cpk and outputs pk \in B^{pk_bytes}
        """
        assert len(cpk) == self.cpk_bytes

        seed_pk = cpk[:self.pk_seed_bytes]
        p3 = cpk[self.pk_seed_bytes:]

        p = shake_256(seed_pk).digest(int(self.P1_bytes + self.P2_bytes))

        return p + p3

    def sign(self, msg, esk):
        """
        takes an expanded secret key sk, a message M \in B^*, and a salt \in B^{salt_bytes} as
        input, and outputs a signature sig \in B^{sig_bytes}
        """

        # salt = self.random_bytes(self.)

        return 0

    def verify(self, sig, msg, epk):
        """
        takes as input a message M , an expanded
        public key pk, a signature sig outputs 1 (invalid) or 0 (valid)
        """

        assert len(sig) == self.sig_bytes
        assert len(epk) == self.epk_bytes

        salt = sig[:self.salt_bytes]
        sig = sig[self.salt_bytes:]

        p1 = decode_mat(epk[:self.P1_bytes], self.m, self.m, self.m, triangular=True)
        p2 = decode_mat(epk[self.P1_bytes:self.P1_bytes+self.P2_bytes], self.m, self.m, self.o, triangular=False)
        p3 = decode_mat(epk[self.P1_bytes+self.P2_bytes:], self.m, self.o, self.o, triangular=True)

        t = decode_vec(shake_256(msg + salt).digest(self.m_bytes))
        s = decode_vec(sig)

        s = [s[i*self.n:(i+1)*self.n] for i in range(k)]

        ell = 0
        y = vector(F16, m)
        for i in range(self.k):
            for j in range(i, self.k):
                for a in range(self.m):
                    u = vector(F16, m)
                    if i == j:
                        p = block_matrix([[p1[a], p2[a]],[matrix(F16, self.o, self.m), p3[a]]])
                    else:
                        p = block_matrix([[p1[a] + p1[a].transpose(), p2[a]],[p2[a].transpose(), p3[a]+p3[a].transpose()]])
                    u[a] = s[i].transpose() * p * s[j]

                # convert to polynomial
                u = self.fx(u)

                y = y + vector(y^ell * u)
                ell = ell + 1
        return y == t


    def open(self, sm, epk):
        """
        takes as input a signed message sm sm, an expanded
        public key pk and outputs 1 (invalid) or 0 (valid)
        and the message if the signature was valid
        """

        mlen = len(sm) - self.sig_bytes
        sig = sm[:self.sig_bytes]
        msg = sm[self.sig_bytes:]

        valid = self.verify(sig, msg, epk)

        if valid:
            return rc, msg
        else:
            return rc, None

    def sample_solution():
        """
        takes as input a matrix A \in F_q^{m x n} of rank m with n >= m,
        a vector y \in F_q^m, and a vector r \in F_q^n
        and outputs a solution x such that Ax = y
        """
        return 0

    def ef():
        """
        takes as input a matrix B \in F_q^{m x n}
        and outputs a matrix B' \in F_q^{m x n} in echelon form.
        """
        return 0


MAYO1 = MAYO(DEFAULT_PARAMETERS["mayo_1"])
csk, cpk = MAYO1.compact_key_gen()
print(csk.hex(), cpk.hex())

assert len(csk) == MAYO1.csk_bytes
assert len(cpk) == MAYO1.cpk_bytes

epk = MAYO1.expand_pk(cpk)
assert len(epk) == MAYO1.epk_bytes

esk = MAYO1.expand_sk(csk)
assert len(esk) == MAYO1.esk_bytes



VERSION = "MAYO-00"

def PrintVersion():
     print(VERSION)
