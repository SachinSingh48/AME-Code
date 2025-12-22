import math
import numpy as np
import secrets  # For secure randomness




# lam=16 -> n=64. This means we can encrypt 64 characters in ONE go.
LAMBDA_PARAM = 16 

def get_secure_random_seed():
    """Generates a secure seed for NumPy using the OS random source."""
    return secrets.randbits(32)

def sample_uniform_matrix(rows, cols, q):

    # SECURE RANDOMNESS: Re-seed generator for every operation
    rng = np.random.default_rng(get_secure_random_seed())
    return rng.integers(0, q, size=(rows,cols))

def sample_error_matrix(rows, cols, std_dev, q):
    rng = np.random.default_rng(get_secure_random_seed())
    return np.round(rng.normal(loc=0, scale=std_dev, size=(rows, cols))).astype(int)

# --- Standard Helper Functions (Optimized) ---
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
    if q is None: q = 2**22 # Keep q large enough
    k = math.ceil(math.log2(q))
    n = 4 * LAMBDA_PARAM
    m_bar = n*k + 2*LAMBDA_PARAM
    p = 256  # Full Extended ASCII support
    alpha = 1/(2*q)
    std_dev = 2.0 # Slightly higher noise tolerance
    return p, q, n, m_bar, alpha, std_dev

# ==========================================
#        CORE CRYPTO (Vectorized)
# ==========================================

def agen(q):
    par = gen_parameters(q)
    p, q, n, m_bar, alpha, std_dev = par
    k = math.ceil(math.log2(q))
    
    print(f"[System] Generating Keys (Dimension n={n})...")
    
    # 2. TRAPDOOR GENERATION
    rng = np.random.default_rng(get_secure_random_seed())
    R = rng.integers(-1, 2, size=(m_bar, n*k))
    
    A_bar = sample_uniform_matrix(n, m_bar, q)
    G = gadget_matrix(n, k, q)
    
    right = (np.matmul(A_bar, R) + G) % q
    A = np.hstack((A_bar, right)).astype(int)
    
    E = sample_error_matrix(m_bar + n*k, n, std_dev, q)
    U = (np.matmul(A, E)) % q
    
    return E, (par, A, U), None, R

def aenc(apk, mu_fake_vector, mu_real_vector):
    """
    Encrypts an n-dimensional vector at once.
    mu_fake_vector: Shape (n, 1)
    mu_real_vector: Shape (n, 1)
    """
    par, A, U = apk
    p, q, n, m_bar, alpha, std_dev = par
    k = math.ceil(math.log2(q))
    m = m_bar + n * k
    delta = int(np.round(q / p))
    
    # Scale messages
    mu_fake_delta = (delta * mu_fake_vector) % q
    mu_real_delta = (delta * mu_real_vector) % q
    
    # Anamorphic Embedding
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

    # Inversion Logic
   
    Gs = c0_diff - np.matmul(calculateSMatrix(k, n, q).T, c0_diff)
    s = Gs[::k]
    
    s_final = np.round(s * (p / q)).astype(int) % p
    return s_final

# ==========================================
#      TEXT PROCESSING (PACKING LOGIC)
# ==========================================

def string_to_chunks(text, n):
    """
    Splits a string into chunks of size 'n'. 
    Pads with spaces if the last chunk is too short.
    """
    # Convert string to ASCII values
    ascii_vals = [ord(c) for c in text]
    
    chunks = []
    for i in range(0, len(ascii_vals), n):
        chunk = ascii_vals[i : i + n]
        # Pad with spaces (ASCII 32) if needed
        while len(chunk) < n:
            chunk.append(32) 
        chunks.append(np.array(chunk).reshape(n, 1))
    return chunks

def chunks_to_string(chunks):
    """Converts a list of vector chunks back to a single string."""
    text = ""
    for chunk in chunks:
        # chunk is (n, 1), flatten it
        flat = chunk.flatten()
        for val in flat:
            # Simple error handling for non-printable chars
            if 32 <= val <= 126: 
                text += chr(val)
            else:
                text += "?" # Error placeholder
    return text

def run_program():
    print("--- PROFESSIONAL ANAMORPHIC MESSENGER ---")
    
    # Setup
    q = 2**22
    ask, apk, dk, tk = agen(q)
    par = apk[0]
    p, q, n, m_bar, alpha, std_dev = par
    
    print(f"[System] Ready. Block size n={n} chars per encryption.")
    
    fake_str = input("Enter FAKE message: ")
    real_str = input("Enter REAL message: ")
    
    # 1. Chunking (Vector Packing)
    # We break the long message into blocks of size 'n'
    fake_chunks = string_to_chunks(fake_str, n)
    real_chunks = string_to_chunks(real_str, n)
    
    # Ensure equal number of chunks (pad the message list itself)
    max_blocks = max(len(fake_chunks), len(real_chunks))
    
    # Fill missing blocks with "space" vectors
    empty_block = np.full((n, 1), 32, dtype=int)
    while len(fake_chunks) < max_blocks: fake_chunks.append(empty_block)
    while len(real_chunks) < max_blocks: real_chunks.append(empty_block)
    
    print(f"\n[Sender] Encrypting {max_blocks} blocks...")
    
    decrypted_fake_chunks = []
    decrypted_real_chunks = []
    
    # 2. Efficient Loop
    for i in range(max_blocks):
        # We process 'n' characters at once here!
        c_txt = aenc(apk, fake_chunks[i], real_chunks[i])
        
        # Dictator Decrypt
        m_vec_fake = dec(ask, c_txt, p, q)
        decrypted_fake_chunks.append(m_vec_fake)
        
        # Receiver Decrypt
        m_vec_real = adec(apk, tk, c_txt)
        decrypted_real_chunks.append(m_vec_real)
        
    print("[Sender] Transmission Complete.")
    
    # 3. Reassemble
    final_fake = chunks_to_string(decrypted_fake_chunks)
    final_real = chunks_to_string(decrypted_real_chunks)
    
    print("\n--- DECRYPTION RESULTS ---")
    print(f"Dictator View:  {final_fake}")
    print(f"Receiver View:  {final_real}")

if __name__ == "__main__":
    run_program()