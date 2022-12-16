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


DEFAULT_PARAMETERS = {
    "mayo_1": {
        "n": 68,
        "m": 72,
        "o": 5,
        "k": 16,
        "q": 16,
    },
    "mayo_2": {
        "n": 68,
        "m": 69,
        "o": 6,
        "k": 13,
        "q": 16,
    },
}

F16.<y> = GF(16)
assert y^4+y+1 == 0

class MAYO:
    def __init__(self, parameter_set):
        self.random_bytes = os.urandom
        self.n = parameter_set["n"]
        self.m = parameter_set["m"]
        self.o = parameter_set["o"]
        self.k = parameter_set["k"]
        self.q = parameter_set["q"]

        self.q_bytes = (math.log(self.q,2)/8)

        self.O_bytes = math.ceil((self.n - self.o)*self.o*self.q_bytes)
        self.v_bytes = math.ceil((self.n - self.o)*self.q_bytes)
        self.P1_bytes = math.ceil(math.comb((self.m-self.o+1), 2)*self.q_bytes)
        self.P2_bytes = math.ceil(self.m*(self.n - self.o)*self.o*self.q_bytes)
        self.P3_bytes = math.ceil(math.comb((self.o+1), 2)*self.q_bytes)


        self.sk_seed_bytes = 32
        self.pk_seed_bytes = 16
        self.salt_bytes = 16

        self.sig_bytes = math.ceil(self.n * self.q_bytes) + self.salt_bytes

    def compact_key_gen(self):
        """
        outputs a pair (csk, cpk) \in B^{csk_bytes} x B^{cpk_bytes}, where csk and cpk
        are compact representations of a Mayo secret key and public key
        """
        # F16.<y> = GF(16)

        seed_sk = self.random_bytes(sk_seed_bytes)                                      # seed_sk = B^sk_seed_bytes
        S = shake_256(seed_sk).digest(int(pk_seed_bytes + self.O_bytes))                # S = SHAKE256(seed_sk , pk_seed_bytes + O_bytes)
        self.seed_pk = S[0: pk_seed_bytes]                                              # seed_pk = S[0 : pk_seed_bytes]


        return 0

    def expand_sk():
        """
        takes as input csk, the compact representation of a secret key, and outputs sk \in B^{sk_bytes},
        an expanded representation of the secret key
        """
        return 0

    def expand_pk():
        """
        takes as input cpk and outputs pk \in B^{pk_bytes}
        """
        return 0

    def sign():
        """
        takes an expanded secret key sk, a message M \in B^*, and a salt \in B^{salt_bytes} as
        input, and outputs a signature sig \in B^{sig_bytes}
        """
        return 0

    def verify(self, sig, msg, pk):
        """
        takes as input a message M , an expanded
        public key pk, a signature sig outputs 1 (invalid) or 0 (valid)
        """
        salt = sig[:self.salt_bytes]
        sig = sig[self.salt_bytes]


        pass

    def open(self, sm, pk):
        """
        takes as input a signed message sm sm, an expanded
        public key pk and outputs 1 (invalid) or 0 (valid)
        and the message if the signature was valid
        """

        mlen = len(sm) - self.sig_bytes
        sig = sm[:self.sig_bytes]
        msg = sm[self.sig_bytes:]

        rc = self.verify(sig, msg, pk)

        if rc == 0:
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
MAYO1.CompactKeyGen()


VERSION = "MAYO-00"

def PrintVersion():
     print(VERSION)
