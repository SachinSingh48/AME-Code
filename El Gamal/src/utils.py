import random
from Crypto.Util import number
import os

def pow_mod(base, exp, mod):
    return pow(base, exp, mod)

def generate_prime(bits):
    #return number.getPrime(bits, randfunc=random.SystemRandom().getrandbits)
    return number.getPrime(bits, randfunc=os.urandom)

def get_random_int(min_val, max_val):
    return random.SystemRandom().randint(min_val, max_val)

def generate_random_bytes(length):
    return random.SystemRandom().randbytes(length)

import hashlib

def sha255_hash(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    elif isinstance(data, int):
        data = str(data).encode('utf-8')
    elif not isinstance(data, bytes):
        data = str(data).encode('utf-8')
    return hashlib.sha256(data).digest()