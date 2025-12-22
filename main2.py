import math
import numpy as np
import secrets
import time  # <--- IMPORTED FOR TIMING

# ==========================================
#      1. STRICT DISCRETE GAUSSIAN SAMPLING
# ==========================================
def sample_discrete_gaussian(rows, cols, sigma):
    """
    Samples from the Discrete Gaussian distribution D_{Z, sigma}.
    Uses standard numpy normal but ensures integer rounding is unbiased.
    """
    rng = np.random.default_rng(secrets.randbits(32))
    continuous_samples = rng.normal(loc=0, scale=sigma, size=(rows, cols))
    
    # Randomized Rounding: x = floor(x) + Bernoulli(x - floor(x))
    floored = np.floor(continuous_samples)
    fractional = continuous_samples - floored
    bernoulli = rng.random(size=(rows, cols)) < fractional
    return (floored + bernoulli).astype(int)

# ==========================================
#      2. ROBUST GADGET INVERSION
# ==========================================
def bit_decomposition_inverse(vec, n, k, q):
    pass # (Not used in this simplified demo, but placeholder for strict theory)

# ==========================================
#      CORE CRYPTO
# ==========================================
LAMBDA_PARAM =  64

def get_secure_random_seed():
    return secrets.randbits(32)

def sample_uniform_matrix(rows, cols, q):
    rng = np.random.default_rng(get_secure_random_seed())
    return rng.integers(0, q, size=(rows,cols))

def gadget_matrix(n, k, q):
    g = 2 ** np.arange(k)
    return np.kron(np.eye(n, dtype=int), g) % q

def calculateSMatrix(k, l, q):
    q_bits = [(q >> i) & 1 for i in range(k)]
    Sk = np.zeros((k,k), dtype=int)
    for i in range(k):
        if i > 0: Sk[i, i-1] = -1
        if i < k - 1: Sk[i,i] = 2
        Sk[i, -1] = q_bits[i]
    return np.kron(np.eye(l, dtype=int), Sk)

def gen_parameters(q=None):
    if q is None: q = 2**22
    k = math.ceil(math.log2(q))
    n = 4 * LAMBDA_PARAM
    m_bar = n*k + 2*LAMBDA_PARAM
    p = 256  
    alpha = 1/(2*q)
    std_dev = 3.2 
    return p, q, n, m_bar, alpha, std_dev

def agen(q):
    par = gen_parameters(q)
    p, q, n, m_bar, alpha, std_dev = par
    k = math.ceil(math.log2(q))
    
    rng = np.random.default_rng(get_secure_random_seed())
    R = rng.integers(0, 2, size=(m_bar, n*k)) 
    
    A_bar = sample_uniform_matrix(n, m_bar, q)
    G = gadget_matrix(n, k, q)
    
    right = (np.matmul(A_bar, R) + G) % q
    A = np.hstack((A_bar, right)).astype(int)
    
    E = sample_discrete_gaussian(m_bar + n*k, n, std_dev)
    U = (np.matmul(A, E)) % q
    
    return E, (par, A, U), None, R

def aenc(apk, mu_fake_vec, mu_real_vec):
    par, A, U = apk
    p, q, n, m_bar, alpha, std_dev = par
    k = math.ceil(math.log2(q))
    m = m_bar + n * k
    delta = int(np.round(q / p))
    
    mu_fake_delta = (delta * mu_fake_vec) % q
    mu_real_delta = (delta * mu_real_vec) % q
    
    s = sample_discrete_gaussian(n, 1, std_dev * 2) 
    s_hat = (s + mu_real_delta) % q

    e0 = sample_discrete_gaussian(m, 1, std_dev)
    e1 = sample_discrete_gaussian(n, 1, std_dev)

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
    
    c0_diff = (c0_part2 - np.matmul(tk.T, c0_part1)) % q

    Gs = c0_diff - np.matmul(calculateSMatrix(k, n, q).T, c0_diff)
    s = Gs[::k] 
    s_final = np.round(s * (p / q)).astype(int) % p
    return s_final

# ==========================================
#      TEXT PROCESSING & TIMING UTILS
# ==========================================

def string_to_chunks(text, n):
    ascii_vals = [ord(c) for c in text]
    chunks = []
    for i in range(0, len(ascii_vals), n):
        chunk = ascii_vals[i : i + n]
        while len(chunk) < n: chunk.append(32) 
        chunks.append(np.array(chunk).reshape(n, 1))
    return chunks

def chunks_to_string(chunks):
    text = ""
    for chunk in chunks:
        flat = chunk.flatten()
        for val in flat:
            if 32 <= val <= 126: text += chr(val)
            else: text += "?"
    return text

def run_program():
    print("--- TIMED ANAMORPHIC MESSENGER ---")
    
    # 1. MEASURE KEY GENERATION
    print("[Timing] Generating Keys...")
    t_start = time.perf_counter()
    ask, apk, dk, tk = agen(2**22)
    t_end = time.perf_counter()
    print(f"   -> Key Gen Time: {(t_end - t_start):.4f} seconds")
    
    par = apk[0]
    p, q, n, m_bar, alpha, std_dev = par
    print(f"[System] Block size n={n}")
    
    fake_str = input("\nEnter FAKE message: ")
    real_str = input("Enter REAL message: ")
    
    fake_chunks = string_to_chunks(fake_str, n)
    real_chunks = string_to_chunks(real_str, n)
    max_blocks = max(len(fake_chunks), len(real_chunks))
    
    empty_block = np.full((n, 1), 32, dtype=int)
    while len(fake_chunks) < max_blocks: fake_chunks.append(empty_block)
    while len(real_chunks) < max_blocks: real_chunks.append(empty_block)
    
    ciphertexts = []
    dec_fake = []
    dec_real = []
    
    print(f"\n[Timing] Processing {max_blocks} block(s)...")

    # 2. MEASURE ENCRYPTION
    t_start = time.perf_counter()
    for i in range(max_blocks):
        c_txt = aenc(apk, fake_chunks[i], real_chunks[i])
        ciphertexts.append(c_txt)
    t_end = time.perf_counter()
    print(f"   -> Encryption Time: {(t_end - t_start)*1000:.2f} ms")

    # 3. MEASURE STANDARD DECRYPTION (DICTATOR)
    t_start = time.perf_counter()
    for i in range(max_blocks):
        m = dec(ask, ciphertexts[i], p, q)
        dec_fake.append(m)
    t_end = time.perf_counter()
    print(f"   -> Standard Decryption Time: {(t_end - t_start)*1000:.2f} ms")

    # 4. MEASURE ANAMORPHIC DECRYPTION (RECEIVER)
    t_start = time.perf_counter()
    for i in range(max_blocks):
        m = adec(apk, tk, ciphertexts[i])
        dec_real.append(m)
    t_end = time.perf_counter()
    print(f"   -> Anamorphic Decryption Time: {(t_end - t_start)*1000:.2f} ms")
        
    print(f"\nDictator View: {chunks_to_string(dec_fake)}")
    print(f"Receiver View: {chunks_to_string(dec_real)}")

if __name__ == "__main__":
    run_program()