#!/usr/bin/sage
# vim: syntax=python

import os
from Cryptodome.Cipher import AES
from sage.cpython.string import str_to_bytes

def xor_bytes(a, b):
    """
    XOR two byte arrays, assume that they are
    of the same length
    """
    return bytes(a^^b for a,b in zip(a,b))

# Params taken from https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf
class AES128_CTR_DRBG:
    def __init__(self, seed=None, personalization=b""):
        self.seed_length = 16 # TODO: Check is this need to be 32 or 16
        self.reseed_interval = 2**48
        self.key = bytes([0])*16
        self.V   = bytes([0])*16
        self.entropy_input = self.__check_entropy_input(seed)
        seed_material = self.__instantiate(personalization=personalization)
        self.ctr_drbg_update(seed_material)
        self.reseed_ctr = 1

    def __check_entropy_input(self, entropy_input):
        """
        If no entropy given, us os.urandom, else
        check that the input is of the right length.
        """
        if entropy_input is None:
            return os.urandom(self.seed_length)
        elif len(entropy_input) != self.seed_length:
            raise ValueError(f"The entropy input must be of length: {self.seed_length}. Input has length {len(entropy_input)}")
        return entropy_input

    def __instantiate(self, personalization=b""):
        """
        Combine the input seed and optional personalisation
        string into the seed material for the DRBG
        """
        if len(personalization) > self.seed_length:
            raise ValueError(f"The Personalization String must be at most length: {self.seed_length}. Input has length {len(personalization)}")
        elif len(personalization) < self.seed_length:
            personalization += bytes([0]) * (self.seed_length - len(personalization))
        # debugging
        assert len(personalization) == self.seed_length
        return xor_bytes(self.entropy_input, personalization)

    def __increment_counter(self):
        int_V = int.from_bytes(self.V, 'big')
        new_V = (int_V + 1) % 2**(8*16) # V = (V+1) mod 2^{blocklen}, which is 16.
        hex_V = int(new_V.hex(), 16) # horrible conversion due to sage
        self.V = hex_V.to_bytes(16, byteorder='big')

    def ctr_drbg_update(self, provided_data):
        tmp = b""
        cipher = AES.new(self.key, AES.MODE_ECB)
        # Collect bytes from AES ECB
        while len(tmp) != self.seed_length:
            self.__increment_counter()
            tmp  += cipher.encrypt(self.V)

        # Take the first 32 bytes
        tmp = tmp[:self.seed_length]
        tmp = xor_bytes(tmp, provided_data)

        # Set the new values of key and V
        self.key = tmp[:16] # based on key len
        self.V = tmp[16:]

    def reseed(self, additional_information=b""):
        """
        Reseed the DRBG for when reseed_ctr hits the
        limit.
        """
        seed_material = self.__instantiate(additional_information)
        self.ctr_drbg_update(seed_material)
        self.reseed_ctr = 1

    def random_bytes(self, num_bytes, additional=None):
        if self.reseed_ctr >= self.reseed_interval:
            raise Warning("The DRBG has been exhausted! Reseed!")

        # Set the optional additional information
        if additional is None:
            additional = bytes([0]) * self.seed_length
        else:
            if len(additional) > self.seed_length:
                 raise ValueError(f"The additional input must be of length at most: {self.seed_length}. Input has length {len(seed)}")
            elif len(additional) < self.seed_length:
                additional += bytes([0]) * (self.seed_length - len(additional))
            self.ctr_drbg_update(additional)

        # Collect bytes!
        tmp = b""
        cipher = AES.new(self.key, AES.MODE_ECB)
        while len(tmp) < num_bytes:
            self.__increment_counter()
            tmp += cipher.encrypt(self.V)

        # Collect only the requested number of bits
        output_bytes = tmp[:num_bytes]
        self.ctr_drbg_update(additional)
        self.reseed_ctr += 1
        return output_bytes
