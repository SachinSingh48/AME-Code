from src.base_pke import ElGamalPKE
from src.utils import sha255_hash, get_random_int

class SenderAnamorphicEncryption:
    def __init__(self):
        self.pke = ElGamalPKE()
        self.prf_key_K = None 

    def set_prf_key(self, key):
        self.prf_key_K = key

    def PRF(self, key, data):
        if self.prf_key_K is None:
            raise ValueError("PRF key not set.")
        if not isinstance(data, bytes):
            data = str(data).encode('utf-8')
        combined_data = str(key).encode('utf-8') + data
        return sha255_hash(combined_data)[0] % 2

    def fRandom(self, fPK, m0_forced, dPK, m1_covert_bit):
        if self.prf_key_K is None:
            raise ValueError("PRF key (K) must be set for fRandom in this model.")

        attempts = 0
        MAX_ATTEMPTS = 1000000

        while attempts < MAX_ATTEMPTS:
            random_y = get_random_int(2, fPK['p'] - 2)
            ct = self.pke.Encrypt(fPK, m0_forced, randomness=random_y)
            if self.PRF(self.prf_key_K, ct['c1']) == m1_covert_bit:
                return ct, random_y
            attempts += 1

        print(f"Warning: fRandom failed to find suitable randomness after {MAX_ATTEMPTS} attempts.")
        return None, None

    def CovertDecryptSender(self, covert_party_prf_key, ciphertext):
        return self.PRF(covert_party_prf_key, ciphertext['ct']['c1'])
