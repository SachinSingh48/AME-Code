from src.utils import pow_mod, generate_prime, get_random_int, sha255_hash
from Crypto.Util import number
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

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
        """Convert string to bytes, then to int. Used for short messages only."""
        m_int = int.from_bytes(text.encode('utf-8'), 'big')
        if m_int >= p:
            raise ValueError("Message too long for the key size!")
        return m_int
    
    def int_to_text(self, number):
        """Convert int back to bytes, then to string"""
        try:
            num_bytes = (number.bit_length() + 7) // 8
            return number.to_bytes(num_bytes, 'big').decode('utf-8')
        except:
            return "[Decryption Error: Not text]"

    def Encrypt(self, PK, message, randomness=None):
        """
        Encrypt a message (string or int) under a public key.
        For long messages, use hybrid encryption internally.
        """
        p = PK['p']
        g = PK['g']
        h = PK['h']

        # Convert message to int if it's a string
        if isinstance(message, str):
            message_bytes = message.encode('utf-8')
            # For long messages, use hybrid encryption
            if len(message_bytes) > (p.bit_length() - 8) // 8:
                return self._encrypt_hybrid(PK, message_bytes, randomness)
            else:
                message_int = int.from_bytes(message_bytes, 'big')
        else:
            message_int = message % p

        # Standard ElGamal for short messages
        if randomness is None:
            y = get_random_int(2, p - 2)
        else:
            y = randomness
        
        c1 = pow_mod(g, y, p)
        s = pow_mod(h, y, p)
        c2 = (message_int * s) % p
        
        ciphertext = {'c1': c1, 'c2': c2, 'y_used': y, 'is_hybrid': False}
        return ciphertext

    def _encrypt_hybrid(self, PK, message_bytes, randomness=None):
        """
        Hybrid encryption for long messages:
        1. ElGamal encrypts a random symmetric key
        2. AES-256-GCM encrypts the actual message with that key
        """
        p = PK['p']
        g = PK['g']
        h = PK['h']

        # Generate a random symmetric key
        sym_key = get_random_bytes(32)  # 256-bit key for AES-256
        
        # Encrypt the symmetric key using ElGamal
        if randomness is None:
            y = get_random_int(2, p - 2)
        else:
            y = randomness
        
        c1 = pow_mod(g, y, p)
        s = pow_mod(h, y, p)
        
        # Convert symmetric key to int and encrypt it
        key_as_int = int.from_bytes(sym_key, 'big') % p
        c2 = (key_as_int * s) % p
        
        # Encrypt message with AES-256-GCM
        iv = get_random_bytes(16)
        cipher = AES.new(sym_key, AES.MODE_GCM, nonce=iv)
        ciphertext_msg, tag = cipher.encrypt_and_digest(message_bytes)
        
        return {
            'c1': c1,
            'c2': c2,
            'y_used': y,
            'is_hybrid': True,
            'iv': iv.hex(),
            'ciphertext': ciphertext_msg.hex(),
            'tag': tag.hex()
        }

    def Decrypt(self, SK, ciphertext):
        """
        Decrypt a ciphertext (standard or hybrid).
        Returns the decrypted message as an integer.
        """
        p = SK['p']
        x = SK['x']
        
        c1 = ciphertext['c1']
        c2 = ciphertext['c2']
        
        s = pow_mod(c1, x, p)
        s_inv = number.inverse(s, p)
        
        message_int = (c2 * s_inv) % p
        
        return message_int

    def Decrypt_Hybrid(self, SK, ciphertext):
        """
        Decrypt a hybrid-encrypted message and return the original plaintext as bytes.
        """
        if not ciphertext.get('is_hybrid'):
            raise ValueError("This ciphertext is not hybrid-encrypted!")
        
        p = SK['p']
        x = SK['x']
        
        c1 = ciphertext['c1']
        c2 = ciphertext['c2']
        
        # Recover the symmetric key
        s = pow_mod(c1, x, p)
        s_inv = number.inverse(s, p)
        key_as_int = (c2 * s_inv) % p
        
        # Convert int back to bytes (pad to 32 bytes for AES-256)
        sym_key = key_as_int.to_bytes(32, 'big')
        
        # Decrypt the message
        iv = bytes.fromhex(ciphertext['iv'])
        encrypted_msg = bytes.fromhex(ciphertext['ciphertext'])
        tag = bytes.fromhex(ciphertext['tag'])
        
        cipher = AES.new(sym_key, AES.MODE_GCM, nonce=iv)
        plaintext = cipher.decrypt_and_verify(encrypted_msg, tag)
        
        return plaintext

    def decrypt_and_decode(self, SK, ciphertext):
        """
        Universal decryption that handles both standard and hybrid ciphertexts.
        Returns the plaintext as a string.
        """
        if ciphertext.get('is_hybrid'):
            plaintext_bytes = self.Decrypt_Hybrid(SK, ciphertext)
            return plaintext_bytes.decode('utf-8', errors='replace')
        else:
            message_int = self.Decrypt(SK, ciphertext)
            return self.int_to_text(message_int)
