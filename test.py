from dualRegev import *
import numpy as np
import time
from termcolor import colored

# set up parameters and key generation
tic = time.time()
q = 2**22
ask, apk, dk, tk = agen(q)
p, q, n, m_bar, alpha, std_dev = apk[0]
toc = time.time()
print(f"\nKey generation takes :{toc-tic:.4f} seconds\n")

def pad_message(msg, target_len):
    return msg + " " * (target_len - len(msg))

fake_str = input("Enter FAKE message: ")
real_str = input("Enter REAL message: ")

max_len = max(len(fake_str), len(real_str), n) # n is dimension = secret key length
if max_len == n:

    # padding message to reach key length
    fake_str = pad_message(fake_str, max_len)
    real_str = pad_message(real_str, max_len)
    
    # convert string to vector for calculation using ASCII characters table
    fake_arr = np.fromiter((ord(ch) for ch in fake_str), dtype=int)
    mu = fake_arr.reshape(len(fake_arr),1)

    real_str = np.fromiter((ord(ch) for ch in real_str), dtype=int)
    mu_bar = real_str.reshape(len(real_str),1)

    print(colored("\n---------Regular encryption and decryption on anamorphic key pair-------------\n", "green"))
    
    tic = time.time()
    ct = enc(apk, mu)
    toc = time.time()
    print(colored(f"Encryption takes :{toc-tic:.4f} seconds", "grey"))

    tic = time.time()
    dm = dec(ask, ct, p, q)
    toc = time.time()
    message = ''.join(chr(x) for x in dm.flatten())
    print("You have new message: " + message)
    print(colored(f"Decryption takes :{toc-tic:.4f} seconds", "grey"))

    print(colored("\n---------Anamorphic Dual Regev-------------\n", "green"))
    tic = time.time()
    act = aenc(apk, dk, mu, mu_bar)
    toc = time.time()
    print(colored(f"Encryption takes :{toc-tic:.4f} seconds", "grey"))

    tic = time.time()
    afm = dec(ask,act,p,q)                  # decrypt anamorphic ciphertext with regular decryption
    toc = time.time()
    fake_message = ''.join(chr(x) for x in afm.flatten())
    print("You have new message: " + fake_message)
    print(colored(f"Regular decryption takes :{toc-tic:.4f} seconds", "grey"))
    
    tic = time.time()
    adm, _ = adec(apk, dk, tk, ask, act)
    toc = time.time()
    real_message = ''.join(chr(x) for x in adm.flatten())
    print("You have new hidden message: " + real_message)
    print(colored(f"Anamorphic decryption takes :{toc-tic:.4f} seconds", "grey"))

elif max_len == len(fake_str):
    print(colored("Exceed key length!!!", "red"))
    sliced_fake_str = list(fake_str[i:i+40] for i in range(0,len(fake_str),n))
    sliced_real_str = list(real_str[i:i+40] for i in range(0,len(real_str),n))
    