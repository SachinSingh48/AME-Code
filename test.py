from dualRegev import *
import numpy as np

q = 2**22
ask, apk, dk, tk = agen(q)
p, q, n, m_bar, alpha, std_dev = apk[0]

def pad_message(msg, target_len):
    return msg + " " * (target_len - len(msg))

fake_str = input("Enter FAKE message: ")
real_str = input("Enter REAL message: ")

max_len = max(len(fake_str), len(real_str), 64) # n=64 is key length
if max_len == 64:
    fake_str = pad_message(fake_str, max_len)
    real_str = pad_message(real_str, max_len)
    fake_arr = np.fromiter((ord(ch) for ch in fake_str), dtype=int)
    mu = fake_arr.reshape(len(fake_arr),1)

    real_str = np.fromiter((ord(ch) for ch in real_str), dtype=int)
    mu_bar = real_str.reshape(len(real_str),1)

    print("\n---------Regular encryption and decryption on anamorphic key pair-------------")
    ct = enc(apk, mu)
    dm = dec(ask, ct, p, q)
    message = ''.join(chr(x) for x in dm.flatten())
    print("You have new message: " + message)

    print("\n---------Anamorphic Dual Regev-------------")
    act = aenc(apk, dk, mu, mu_bar)
    adm, _ = adec(apk, dk, tk, ask, act)
    message = ''.join(chr(x) for x in adm.flatten())
    print("You have new hidden message: " + message)
elif max_len == len(fake_str):
    sliced_fake_str = list(fake_str[i:i+40] for i in range(0,len(fake_str),40))
    sliced_real_str = list(real_str[i:i+40] for i in range(0,len(real_str),40))
    
    





