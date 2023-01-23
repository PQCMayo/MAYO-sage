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
        "n": 69,
        "m": 64,
        "o": 9,
        "k": 8,
        "q": 16,
        "f": z**64 + x*z**4 + z**3 + z + 1
    },
    "mayo_2": {
        "n": 78,
        "m": 64,
        "o": 18,
        "k": 4,
        "q": 16,
        "f": z**64 + x*z**4 + z**3 + z + 1
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

def decode_matrix(t, rows, columns, triangular):
    t = decode_vec(t, len(t)*2)

    t = list(t[::-1])

    As = matrix(F16, rows, columns)
    if triangular:
        for i in range(rows):
            for j in range(i, columns):
                As[i, j] = t.pop()
    else:
        for i in range(rows):
            for j in range(columns):
                As[i, j] = t.pop()

    return As

def decode_matrices_old(t, m, rows, columns, triangular):
    t = decode_vec(t, len(t)*2)

    t = list(t[::-1])

    As = [matrix(F16, rows, columns) for _ in range(m)]
    if triangular:
        for i in range(rows):
            for j in range(i, columns):
                for k in range(m):
                    As[k][i, j] = t.pop()
    else:
        for i in range(rows):
            for j in range(columns):
                for k in range(m):
                    As[k][i, j] = t.pop()

    return As

def encode_matrix(mat, rows, columns, triangular):

    els = []
    if triangular:
        for i in range(rows):
            for j in range(i, columns):
                els += [mat[i, j]]
    else:
        for i in range(rows):
            for j in range(columns):
                els += [mat[i, j]]

    if len(els) % 2 == 1:
        els += [F16(0)]

    bs = encode_vec(els)
    return bytes(bs)

# turns an 8 bit abcdefgh int into a 32-bit int 000a000b000c000d000e000f000g000h 
explode_table = [ int("".join([ "".join(x) for x in zip("00000000","00000000","00000000",bin(i+256)[3:])]),2) for i in range(256) ]

# take a tuple of four m-bit integers and outputs a vector of m field elements
def unbitslice_m_vec(tuple,m):
    assert len(tuple) == 4
    d0,d1,d2,d3 = tuple

    t = bytes()
    for x in range(m//8):
        t = t + int(explode_table[d0%256] + explode_table[d1%256]*2 + explode_table[d2%256]*4 + explode_table[d3%256]*8).to_bytes(4, byteorder='little');
        d0 //= 256
        d1 //= 256
        d2 //= 256
        d3 //= 256

    return decode_vec(t,m)

# inverse of explode 
implode_dict = { explode_table[i]:i for i in range(256)}

# take a vector of m field elements and output a tuple of four m-bit integers
def bitslice_m_vec(vec):
    assert len(vec) %32 == 0
    m = len(vec)

    d0,d1,d2,d3 = 0,0,0,0
    t = encode_vec(vec)

    for x in range(m//8,-1,-1):
        eight_elements = int.from_bytes(t[x*4:(x+1)*4], byteorder = 'little')
        d0 = d0*256 + implode_dict[      eight_elements & 0b00010001000100010001000100010001 ]
        d1 = d1*256 + implode_dict[ (eight_elements//2) & 0b00010001000100010001000100010001 ]
        d2 = d2*256 + implode_dict[ (eight_elements//4) & 0b00010001000100010001000100010001 ]
        d3 = d3*256 + implode_dict[ (eight_elements//8) & 0b00010001000100010001000100010001 ]

    return (d0,d1,d2,d3)


"""
decode a string to a matrices of bitsliced vectors
"""
def partial_decode_matrices(t, m, rows, columns, triangular):
    assert m % 32 == 0
    bytes_per_vec = m//2
    bytes_per_deg = m//8
    bytes_used = 0

    matrices = [ [None for _ in range(columns)] for _ in range(rows) ]
    if triangular:
        assert rows == columns
        assert bytes_per_vec*(rows+1)*rows//2 == len(t)
        As = [matrix(F16, rows, columns) for _ in range(m)]
        for i in range(rows):
            for j in range(i, columns):
                matrices[i][j] = ( int.from_bytes(t[bytes_used+0*bytes_per_deg:bytes_used+1*bytes_per_deg], byteorder='little'),
                                   int.from_bytes(t[bytes_used+1*bytes_per_deg:bytes_used+2*bytes_per_deg], byteorder='little'),
                                   int.from_bytes(t[bytes_used+2*bytes_per_deg:bytes_used+3*bytes_per_deg], byteorder='little'),
                                   int.from_bytes(t[bytes_used+3*bytes_per_deg:bytes_used+4*bytes_per_deg], byteorder='little'))
                bytes_used += bytes_per_vec
    else:
        assert bytes_per_vec*rows*columns == len(t)
        As = [matrix(F16, rows, columns) for _ in range(m)]
        for i in range(rows):
            for j in range(columns):
                matrices[i][j] = ( int.from_bytes(t[bytes_used+0*bytes_per_deg:bytes_used+1*bytes_per_deg], byteorder='little'),
                                   int.from_bytes(t[bytes_used+1*bytes_per_deg:bytes_used+2*bytes_per_deg], byteorder='little'),
                                   int.from_bytes(t[bytes_used+2*bytes_per_deg:bytes_used+3*bytes_per_deg], byteorder='little'),
                                   int.from_bytes(t[bytes_used+3*bytes_per_deg:bytes_used+4*bytes_per_deg], byteorder='little'))
                bytes_used += bytes_per_vec

    return matrices

def decode_matrices(t, m, rows, columns, triangular):
    matrices = partial_decode_matrices(t, m, rows, columns, triangular)

    As = [matrix(F16, rows, columns) for _ in range(m)]

    for i in range(rows):
        for j in range(columns):
            if matrices[i][j] is None:
                continue
            
            v = unbitslice_m_vec(matrices[i][j], m)
            for k in range(m):
                As[k][i,j] = v[k]

    return As


"""
encode set of m matrices to a matrix of bitsliced vectors
"""
def partial_encode_matrices(matrices, m, rows, columns, triangular):
    assert m % 32 == 0
    bytes_per_deg = m//8

    t = bytes()
    if triangular:
        assert rows == columns
        for i in range(rows):
            for j in range(i, columns):
                t += int(matrices[i][j][0]).to_bytes(bytes_per_deg, byteorder='little')
                t += int(matrices[i][j][1]).to_bytes(bytes_per_deg, byteorder='little')
                t += int(matrices[i][j][2]).to_bytes(bytes_per_deg, byteorder='little')
                t += int(matrices[i][j][3]).to_bytes(bytes_per_deg, byteorder='little')
        return t
    else:
        for i in range(rows):
            for j in range(columns):
                t += int(matrices[i][j][0]).to_bytes(bytes_per_deg, byteorder='little')
                t += int(matrices[i][j][1]).to_bytes(bytes_per_deg, byteorder='little')
                t += int(matrices[i][j][2]).to_bytes(bytes_per_deg, byteorder='little')
                t += int(matrices[i][j][3]).to_bytes(bytes_per_deg, byteorder='little')
        return t


def encode_matrices(mat, m, rows, columns, triangular):

    matrices = [ [None for _ in range(columns)] for _ in range(rows)]

    if triangular:
        for i in range(rows):
            for j in range(i, columns):
                matrices[i][j] = bitslice_m_vec([mat[k][i,j] for k in range(m)])
    else:
        for i in range(rows):
            for j in range(columns):
                matrices[i][j] = bitslice_m_vec([mat[k][i,j] for k in range(m)])

    return partial_encode_matrices(matrices, m, rows, columns, triangular)


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
        outputs a pair (csk, cpk) in B^{csk_bytes} x B^{cpk_bytes}, where csk and cpk
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

        o = decode_matrix(s[self.pk_seed_bytes:self.pk_seed_bytes +
                       self.O_bytes], self.n-self.o, self.o, triangular=False)


        p = shake_256(seed_pk).digest(int(self.P1_bytes + self.P2_bytes))

        p1 = decode_matrices(p[:self.P1_bytes], self.m, self.n -
                        self.o, self.n-self.o, triangular=True)

        p2 = decode_matrices(p[self.P1_bytes:self.P1_bytes+self.P2_bytes],
                        self.m, self.n-self.o, self.o, triangular=False)

        p3 = [matrix(F16, self.o, self.o) for _ in range(self.m)]
        P3 = [ [ None for _ in range(self.o)] for _ in range(self.o) ]

        for i in range(self.m):
            p3[i] = Upper(- o.transpose()*p1[i]*o - o.transpose()*p2[i], self.o)

        cpk = seed_pk + encode_matrices(p3, self.m, self.o, self.o, triangular=True)
        csk = seed_sk
        return csk, cpk


    def expand_sk(self, csk):
        """
        takes as input csk, the compact representation of a secret key, and outputs sk in B^{sk_bytes},
        an expanded representation of the secret key
        """
        assert len(csk) == self.csk_bytes

        seed_sk = csk
        s = shake_256(seed_sk).digest(int(self.pk_seed_bytes + self.O_bytes))
        seed_pk = s[:self.pk_seed_bytes]

        o = decode_matrix(s[self.pk_seed_bytes:self.pk_seed_bytes + self.O_bytes], self.n-self.o, self.o, triangular=False)

        p = shake_256(seed_pk).digest(int(self.P1_bytes + self.P2_bytes))

        p1 = decode_matrices(p[:self.P1_bytes], self.m, self.n -
                        self.o, self.n-self.o, triangular=True)

        p2 = decode_matrices(p[self.P1_bytes:self.P1_bytes+self.P2_bytes],
                        self.m, self.n-self.o, self.o, triangular=False)

        l = [matrix(F16, self.n-self.o, self.o) for _ in range(self.m)]
        for i in range(self.m):
            l[i] = (p1[i] + p1[i].transpose())*o + p2[i]

        esk = seed_sk + encode_matrix(o, self.n-self.o, self.o, triangular=False) + encode_matrices(p1, self.m, self.n -
                                                                                                 self.o, self.n-self.o, triangular=True) + encode_matrices(l, self.m, self.n-self.o, self.o, triangular=False)

        return esk

    def expand_pk(self, cpk):
        """
        takes as input cpk and outputs pk in B^{pk_bytes}
        """
        assert len(cpk) == self.cpk_bytes

        seed_pk = cpk[:self.pk_seed_bytes]
        p3 = cpk[self.pk_seed_bytes:]

        p = shake_256(seed_pk).digest(int(self.P1_bytes + self.P2_bytes))

        return p + p3

    def sign(self, msg, esk):
        """
        takes an expanded secret key sk, a message M in B^*, and a salt in B^{salt_bytes} as
        input, and outputs a signature sig in B^{sig_bytes}
        """

        salt = self.random_bytes(self.salt_bytes)
        seed_sk = esk[:self.sk_seed_bytes]
        o = decode_matrix(esk[self.sk_seed_bytes:self.sk_seed_bytes + self.O_bytes], self.n-self.o, self.o, triangular=False)

        p1 = decode_matrices(esk[self.sk_seed_bytes + self.O_bytes:self.sk_seed_bytes +
                        self.O_bytes + self.P1_bytes], self.m, self.n-self.o, self.n-self.o, triangular=True)

        l = decode_matrices(esk[self.sk_seed_bytes + self.O_bytes + self.P1_bytes:],
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

        p1 = decode_matrices(epk[:self.P1_bytes], self.m, self.n -
                        self.o, self.n-self.o, triangular=True)

        p2 = decode_matrices(epk[self.P1_bytes:self.P1_bytes+self.P2_bytes],
                        self.m, self.n-self.o, self.o, triangular=False)

        p3 = decode_matrices(epk[self.P1_bytes+self.P2_bytes:self.P1_bytes+self.P2_bytes+self.P3_bytes],
                        self.m, self.o, self.o, triangular=True)

        t = decode_vec(shake_256(msg + salt).digest(self.m_bytes), self.m)
        s = decode_vec(sig, self.n*self.k)

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
                    #print(p.ncols(),p.nrows())
                    #print(len(s[i]),len(s[j]))
                    u[a] = s[i] * p * s[j]

                # convert to polynomial
                u = self.fx(list(u))

                y = y + vector(z**ell * u)

                ell = ell + 1
        return y == t

    def sample_solution(self, A, y, r):
        """
        takes as input a matrix A in F_q^{m x n} of rank m with n >= m,
        a vector y in F_q^m, and a vector r in F_q^n
        and outputs a solution x such that Ax = y
        """

        if A.rank() != self.m:
            return None
        # TODO: make sure that this gives the same solution as the spec
        x = A.solve_right(y - A*r)

        assert A*x == y - A*r

        return x + r

def SetupMAYO(params_type):
    if (params_type == ""):
      return None

    return MAYO(DEFAULT_PARAMETERS[params_type])

def PrintVersion():
    print(VERSION)
