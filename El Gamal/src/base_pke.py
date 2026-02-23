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

    def text_to_int(self, text, p):
        # Convert string to bytes, then to int
        m_int = int.from_bytes(text.encode('utf-8'), 'big')
        if m_int >= p:
            raise ValueError("Message too long for the key size!")
        return m_int
    
    def int_to_text(self, number):
        # Convert int back to bytes, then to string
        # We need to calculate the number of bytes needed
        try:
            num_bytes = (number.bit_length() + 7) // 8
            return number.to_bytes(num_bytes, 'big').decode('utf-8')
        except:
            return "[Decryption Error: Not text]"

    def Encrypt(self, PK, message, randomness=None):
        p = PK['p']
        g = PK['g']
        h = PK['h']

        # FIX: Check if it IS a string to convert it
        if isinstance(message, str):
            message_int = self.text_to_int(message, p)
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