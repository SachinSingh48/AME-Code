from src.utils import pow_mod, generate_prime, get_random_int, sha255_hash
from Crypto.Util import number

class ElGamalPKE:

    def __init__(self):
        pass

    def KeyGen(self, lambda_bits):
        p = generate_prime(lambda_bits)
        g = 2

        while True:
            if g < p - 1:
                break
            g = get_random_int(2, p - 1)

        x = get_random_int(2, p - 2)
        
        h = pow_mod(g, x, p)
        
        PK = {'p': p, 'g': g, 'h': h}
        SK = {'x': x, 'p': p}
        
        return PK, SK

    def Encrypt(self, PK, message, randomness=None):
        p = PK['p']
        g = PK['g']
        h = PK['h']

        if not isinstance(message, int):
            message_int = int.from_bytes(sha255_hash(message), 'big') % p
        else:
            message_int = message % p

        if randomness is None:
            y = get_random_int(2, p - 2)
        else:
            y = randomness
        
        c1 = pow_mod(g, y, p)
        
        s = pow_mod(h, y, p)
        
        c2 = (message_int * s) % p
        
        ciphertext = {'c1': c1, 'c2': c2, 'y_used': y}
        return ciphertext

    def Decrypt(self, SK, ciphertext):
        p = SK['p']
        x = SK['x']
        
        c1 = ciphertext['c1']
        c2 = ciphertext['c2']
        
        s = pow_mod(c1, x, p)
        
        s_inv = number.inverse(s, p)
        
        message_int = (c2 * s_inv) % p
        
        return message_int