#!/usr/bin/sage
# vim: syntax=python

from hashlib import shake_256
from sage.cpython.string import str_to_bytes

# Current version of the library
VERSION = "MAYO-00"

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

DEFAULT_PARAMETERS = {
    "mayo_1": {
        "n": 68,
        "m": 72,
        "o": 5,
        "k": 16,
        "q": 16,
        "f": z**72 + z**5 + z**3 + x
    },
    "mayo_2": {
        "n": 68,
        "m": 69,
        "o": 6,
        "k": 13,
        "q": 16,
        "f": z**69 + z**40 + x
    },
}


def decode_vec(t, l):
    t = [(t[i//2] >> i % 2 * 4) & 0xf for i in range(2 * len(t))]
    v = vector(map(F16.fetch_int, t))

    if l % 2 == 1:
        v = v[:-1]
    return v


def encode_vec(v):
    assert len(v) % 2 == 0
    bs = []
    for i in range(len(v)//2):
        bs += [v[i*2].integer_representation() |
               (v[i*2 + 1].integer_representation() << 4)]
    return bytes(bs)


def decode_mat(t, m, rows, columns, triangular):
    t = decode_vec(t, len(t)*2)

    t = list(t[::-1])

    if triangular:
        As = [matrix(F16, rows, columns) for _ in range(m)]
        for i in range(rows):
            for j in range(i, columns):
                for k in range(m):
                    As[k][i, j] = t.pop()
    else:
        As = [matrix(F16, rows, columns) for _ in range(m)]
        for i in range(rows):
            for j in range(columns):
                for k in range(m):
                    As[k][i, j] = t.pop()

    return As


def encode_mat(mat, m, rows, columns, triangular):
    if triangular:
        els = []
        for i in range(rows):
            for j in range(i, columns):
                for k in range(m):
                    els += [mat[k][i, j]]

        if len(els) % 2 == 1:
            els += [F16(0)]

        bs = encode_vec(els)
        # for i in range(len(els)//2):
        #     bs += [els[i*2].integer_representation() |
        #            (els[i*2 + 1].integer_representation() << 4)]
        return bytes(bs)
    else:
        els = []
        for i in range(rows):
            for j in range(columns):
                for k in range(m):
                    els += [mat[k][i, j]]

        if len(els) % 2 == 1:
            els += [F16(0)]

        bs = encode_vec(els)
        # for i in range(len(els)//2):
        #     bs += [els[i*2].integer_representation() |
        #            (els[i*2 + 1].integer_representation() << 4)]
        return bytes(bs)

def Upper(p, rows):
    for j in range(0, rows):
        for k in range(j+1, rows):
            p[j, k] += p[k, j]
            p[k, j] = 0

    return p

_as_bytes = lambda x: x if isinstance(x, bytes) else bytes(x, "utf-8")

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

        self.q_bytes = (math.log(self.q, 2)/8)
        self.m_bytes = math.ceil(self.q_bytes*self.m)

        self.O_bytes = math.ceil((self.n - self.o)*self.o*self.q_bytes)
        self.v_bytes = math.ceil((self.n - self.o)*self.q_bytes)
        self.r_bytes = math.ceil(self.k*self.o*self.q_bytes)
        self.P1_bytes = math.ceil(
            self.m*math.comb((self.n-self.o+1), 2)*self.q_bytes)
        self.P2_bytes = math.ceil(self.m*(self.n - self.o)*self.o*self.q_bytes)
        self.P3_bytes = math.ceil(self.m*math.comb((self.o+1), 2)*self.q_bytes)

        self.sk_seed_bytes = 32
        self.pk_seed_bytes = 16
        self.salt_bytes = 16

        self.sig_bytes = math.ceil(
            self.k * self.n * self.q_bytes) + self.salt_bytes
        self.epk_bytes = self.P1_bytes + self.P2_bytes + self.P3_bytes
        self.cpk_bytes = self.P3_bytes + self.pk_seed_bytes
        self.csk_bytes = self.sk_seed_bytes
        self.esk_bytes = self.sk_seed_bytes + \
            self.O_bytes + self.P1_bytes + self.P2_bytes

        assert self.q == 16

    def compact_key_gen(self):
        """
        outputs a pair (csk, cpk) \in B^{csk_bytes} x B^{cpk_bytes}, where csk and cpk
        are compact representations of a Mayo secret key and public key
        """
        # F16.<y> = GF(16)
        seed_sk = self.random_bytes(self.sk_seed_bytes)

	# Representing a 1 in little endian
        seed_sk = str_to_bytes('\x01\x00\x00\x00\x00')
        seed_sk = shake_256(seed_sk).digest(
            int(self.pk_seed_bytes + self.O_bytes))[:self.sk_seed_bytes]

        s = shake_256(seed_sk).digest(int(self.pk_seed_bytes + self.O_bytes))
        seed_pk = s[:self.pk_seed_bytes]

        o = decode_mat(s[self.pk_seed_bytes:self.pk_seed_bytes +
                       self.O_bytes], 1, self.n-self.o, self.o, triangular=False)[0]


        p = shake_256(seed_pk).digest(int(self.P1_bytes + self.P2_bytes))

        p1 = decode_mat(p[:self.P1_bytes], self.m, self.n -
                        self.o, self.n-self.o, triangular=True)

        p2 = decode_mat(p[self.P1_bytes:self.P1_bytes+self.P2_bytes],
                        self.m, self.n-self.o, self.o, triangular=False)

        p3 = [matrix(F16, self.o, self.o) for _ in range(self.m)]
        for i in range(self.m):
            p3[i] = Upper(- o.transpose()*p1[i]*o - o.transpose()*p2[i], self.o)

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

        p1 = decode_mat(p[:self.P1_bytes], self.m, self.n -
                        self.o, self.n-self.o, triangular=True)

        p2 = decode_mat(p[self.P1_bytes:self.P1_bytes+self.P2_bytes],
                        self.m, self.n-self.o, self.o, triangular=False)

        l = [matrix(F16, self.n-self.o, self.o) for _ in range(self.m)]
        for i in range(self.m):
            l[i] = (p1[i] + p1[i].transpose())*o + p2[i]

        esk = seed_sk + encode_mat([o], 1, self.n-self.o, self.o, triangular=False) + encode_mat(p1, self.m, self.n -
                                                                                                 self.o, self.n-self.o, triangular=True) + encode_mat(l, self.m, self.n-self.o, self.o, triangular=False)

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

        salt = self.random_bytes(self.salt_bytes)
        seed_sk = esk[:self.sk_seed_bytes]
        o = decode_mat(esk[self.sk_seed_bytes:self.sk_seed_bytes + self.O_bytes], 1, self.n-self.o, self.o, triangular=False)[0]

        p1 = decode_mat(esk[self.sk_seed_bytes + self.O_bytes:self.sk_seed_bytes +
                        self.O_bytes + self.P1_bytes], self.m, self.n-self.o, self.n-self.o, triangular=True)

        l = decode_mat(esk[self.sk_seed_bytes + self.O_bytes + self.P1_bytes:],
                       self.m, self.n-self.o, self.o, triangular=False)

        t = decode_vec(shake_256(msg + salt).digest(self.m_bytes), self.m)
        # TODO: change back
        for ctr in range(4):  # range(256):
            V = shake_256(msg + salt + seed_sk +
                          bytes([ctr])).digest(int(self.k*self.v_bytes + self.r_bytes))

            v = [vector(F16, self.n-self.o) for _ in range(self.k)]
            M = [matrix(F16, self.m, self.o) for _ in range(self.k)]
            for i in range(self.k):
                v[i] = decode_vec(
                    V[i*self.v_bytes:(i+1)*self.v_bytes], self.n-self.o)
                for j in range(self.m):
                    M[i][j, :] = v[i]*l[j]

            A = matrix(F16, self.m, self.k*self.o)
            y = t
            ell = 0
            for i in range(self.k):
                for j in range(i, self.k):
                    u = vector(F16, self.m)
                    for a in range(self.m):
                        if i == j:
                            u[a] = v[i]*p1[a]*v[j]
                        else:
                            u[a] = v[i]*p1[a]*v[j] + v[j]*p1[a]*v[i]

                    # convert to polysample_solutionnomial
                    u = self.fx(list(u))
                    y = y - vector(z**ell * u)

                    # TODO: prettify this
                    xxx = [z**ell * self.fx(M[j][:, a].list())
                           for a in range(self.o)]
                    yyy = matrix([list(v) for v in xxx])
                    A[:, i*self.o:(i+1)*self.o] = A[:, i *
                                                    self.o:(i+1)*self.o] + yyy.transpose()
                    if i != j:
                        xxx = [z**ell * self.fx(M[i][:, a].list())
                               for a in range(self.o)]
                        yyy = matrix([list(v) for v in xxx])
                        A[:, j*self.o:(j+1)*self.o] = A[:, j *
                                                        self.o:(j+1)*self.o] + yyy.transpose()
                    ell = ell + 1

            r = decode_vec(V[self.k*self.v_bytes:], self.k*self.o)
            x = self.sample_solution(A, y, r)
            if x is not None:
                break

        sig = vector(F16, self.k*self.n)
        for i in range(self.k):
            sig[i*self.n:(i+1)*self.n] = vector(list(v[i] + o *
                                                     x[i*self.o:(i+1)*self.o])+list(x[i*self.o:(i+1)*self.o]))
        return salt + encode_vec(sig) + bytes(msg)

    def verify(self, sig, msg, epk):
        """
        takes as input a message M , an expanded
        public key pk, a signature sig outputs 1 (invalid) or 0 (valid)
        """

        assert len(sig) == self.sig_bytes
        assert len(epk) == self.epk_bytes

        salt = sig[:self.salt_bytes]
        sig = sig[self.salt_bytes:]

        p1 = decode_mat(epk[:self.P1_bytes], self.m, self.n -
                        self.o, self.n-self.o, triangular=True)

        p2 = decode_mat(epk[self.P1_bytes:self.P1_bytes+self.P2_bytes],
                        self.m, self.n-self.o, self.o, triangular=False)

        p3 = decode_mat(epk[self.P1_bytes+self.P2_bytes:self.P1_bytes+self.P2_bytes+self.P3_bytes],
                        self.m, self.o, self.o, triangular=True)

        t = decode_vec(shake_256(msg + salt).digest(self.m_bytes), self.m)
        s = decode_vec(sig, self.n)

        s = [s[i*self.n:(i+1)*self.n] for i in range(self.k)]

        ell = 0
        y = vector(F16, self.m)
        for i in range(self.k):
            for j in range(i, self.k):
                u = vector(F16, self.m)
                for a in range(self.m):
                    if i == j:
                        p = block_matrix(
                            [[p1[a], p2[a]], [matrix(F16, self.o, self.n-self.o), p3[a]]])
                    else:
                        p = block_matrix(
                            [[p1[a] + p1[a].transpose(), p2[a]], [p2[a].transpose(), p3[a]+p3[a].transpose()]])
                    u[a] = s[i] * p * s[j]

                # convert to polynomial
                u = self.fx(list(u))

                y = y + vector(z**ell * u)

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
            return valid, msg
        else:
            return valid, None

    def sample_solution(self, A, y, r):
        """
        takes as input a matrix A \in F_q^{m x n} of rank m with n >= m,
        a vector y \in F_q^m, and a vector r \in F_q^n
        and outputs a solution x such that Ax = y
        """

        if A.rank() != self.m:
            return None
        # TODO: make sure that this gives the same solution as the spec
        x = A.solve_right(y - A*r)

        assert A*x == y - A*r

        return x + r

    def check_decode_encode(self):
        seed = self.random_bytes(self.sk_seed_bytes)
        s = shake_256(seed).digest(int(self.O_bytes + self.P1_bytes))

        s1 = s[:self.O_bytes]

        # check encode_vec and decode_vec
        vec1 = decode_vec(s1, len(s)*2)
        s_check1 = encode_vec(vec1)

        # check encode_mat and decode_mat
        o = decode_mat(s1, 1, self.n-self.o, self.o, triangular=False)[0]
        s_check2 = encode_mat([o], 1, self.n-self.o, self.o, triangular=False)

        # check encode_mat and decode_mat triangular
        p = s[self.O_bytes:self.O_bytes + self.P1_bytes]
        p1 = decode_mat(p, self.m, self.n-self.o, self.n-self.o, triangular=True)
        p_check = encode_mat(p1, self.m, self.n - self.o, self.n-self.o, triangular=True)

        # ignoring possible half bytes@decode_mat
        return s1 == s_check1 and s1[:-1] == s_check2[:-1] and p == p_check

def SetupMAYO(params_type):
    if (params_type == ""):
      return None

    return MAYO(DEFAULT_PARAMETERS[params_type])

def PrintVersion():
    print(VERSION)
