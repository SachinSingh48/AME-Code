import math
import numpy as np

#        CORE CRYPTO LOGIC
# ==========================================

lam = 2

def sample_uniform_matrix(rows, cols, q):
    return np.random.randint(0, q-1, size=(rows,cols), dtype=int)

def sample_error_matrix(rows, cols, std_dev, q):
    return np.round(np.random.normal(loc=0, scale=std_dev, size=(rows, cols))).astype(int)

def gadget_matrix(n, k, q):
    g = 2 ** np.arange(k)
    G = np.kron(np.eye(n, dtype=int), g) % q
    return G

def calculateSMatrix(k, l, q):
    q_bits = [(q >> i) & 1 for i in range(k)]
    Sk = np.zeros((k,k), dtype=int)
    for i in range(k):
        if i > 0: Sk[i, i-1] = -1
        if i < k - 1: Sk[i,i] = 2
        Sk[i, -1] = q_bits[i]
    I = np.eye(l, dtype=int)
    S = np.kron(I, Sk)
    return S

def gen_parameters(q=None):
    if q is None: q = 8192 * 64
    k = math.ceil(math.log2(q))
    n = 4*lam
    m_bar = n*k+2*lam
    p = 128  # Support for ASCII
    alpha = 1/(2*q)
    std_dev = 1
    return p,q,n,m_bar,alpha,std_dev

def agen(q):
    par = gen_parameters(q)
    p, q, n, m_bar, alpha, std_dev = par
    k = math.ceil(math.log2(q))
    
    R = np.random.randint(-1, 2, size=(m_bar, n*k))
    A_bar = sample_uniform_matrix(n, m_bar, q)
    G = gadget_matrix(n, k, q)
    
    right = (np.matmul(A_bar, R) + G) % q
    A = np.hstack((A_bar, right)).astype(int)
    
    E = sample_error_matrix(m_bar + n*k, n, std_dev, q)
    U = (np.matmul(A, E)) % q
    
    apk = par, A, U
    ask = E
    dk = None
    tk = R
    
    return ask, apk, dk, tk

def aenc(apk, mu_fake, mu_real):
    par, A, U = apk
    p, q, n, m_bar, alpha, std_dev = par
    k = math.ceil(math.log2(q))
    m = m_bar + n * k
    delta = int(np.round(q / p))
    
    mu_fake_delta = (delta * mu_fake) % q
    mu_real_delta = (delta * mu_real) % q
    
    s = sample_error_matrix(n, 1, alpha * q, q)
    s_hat = (s + mu_real_delta) % q

    e0 = sample_error_matrix(m, 1, std_dev, q)
    e1 = sample_error_matrix(n, 1, std_dev, q)

    c0 = (np.matmul(A.T, s_hat) + e0) % q
    c1 = (np.matmul(U.T, s_hat) + e1 + mu_fake_delta) % q

    return c0, c1

def dec(sk, ct, p, q):
    c0, c1 = ct
    delta = int(np.round(q/p))
    c0_s = (np.matmul(sk.T, c0)) % q
    sub = (c1 - c0_s) % q
    m = np.round(sub/delta).astype(int) % p
    return m

def adec(apk, tk, act):
    c0, c1 = act
    par, A, U = apk
    p, q, n, m_bar, alpha, std_dev = par
    k = math.ceil(math.log2(q))

    c0_part1 = c0[:m_bar]
    c0_part2 = c0[m_bar:]
    c0_diff = (c0_part2 - np.matmul(tk.T, c0_part1))

    G = gadget_matrix(n, k, q)
    S = calculateSMatrix(k, n, q)
    diff_T = np.matmul(S.T, c0_diff)
    Gs = c0_diff - diff_T
    
    s = Gs[::k]
    s_final = np.round(s * (p / q)).astype(int) % p
    return s_final

# ==========================================
#              SIMPLE USER INTERFACE
# ==========================================

def pad_message(msg, target_len):
    return msg + " " * (target_len - len(msg))

def run_program():
    # Setup keys silently
    q = 2**22
    ask, apk, dk, tk = agen(q)
    par = apk[0]
    p, q, n, m_bar, alpha, std_dev = par
    
    # 1. Take Inputs
    fake_str = input("Enter FAKE message: ")
    real_str = input("Enter REAL message: ")
    
    # 2. Process
    max_len = max(len(fake_str), len(real_str))
    fake_str = pad_message(fake_str, max_len)
    real_str = pad_message(real_str, max_len)
    
    dictator_output = ""
    receiver_output = ""
    
    for i in range(max_len):
        val_fake = ord(fake_str[i])
        val_real = ord(real_str[i])
        
        mu_fake = np.full((n, 1), val_fake, dtype=int)
        mu_real = np.full((n, 1), val_real, dtype=int)
        
        ciphertext = aenc(apk, mu_fake, mu_real)
        
        # Dictator Decryption
        dec_vec_fake = dec(ask, ciphertext, p, q)
        dictator_output += chr(dec_vec_fake[0][0])
        
        # Receiver Decryption
        dec_vec_real = adec(apk, tk, ciphertext)
        receiver_output += chr(dec_vec_real[0][0])

    # 3. Show Output
    print("\n--- DECRYPTION RESULTS ---")
    print(f"Dictator View (Shared Key):  {dictator_output.strip()}")
    print(f"Receiver View (Hidden Key):  {receiver_output.strip()}")

if __name__ == "__main__":
    run_program()