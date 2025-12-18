import math
import numpy as np
import random

# ----------------- Helper Functions -----------------

def gadget_matrix(n, k, q):
    """Constructs the Gadget matrix G = I_n ⊗ [1, 2, 4, ..., 2^{k-1}]"""
    g = 2 ** np.arange(k)
    G = np.kron(np.eye(n, dtype=int), g) % q
    return G

def gadget_inverse(vec, q, base=2):
    """Decomposes a vector into its binary representation (G-inverse)"""
    vec = np.asarray(vec, dtype=int).reshape(-1)
    k = int(np.ceil(np.log2(q)))
    digits = []
    for x in vec:
        coeffs = []
        y = int(x)
        for _ in range(k):
            coeffs.append(y % base)
            y //= base
        digits.extend(coeffs)
    return np.array(digits, dtype=int)

def sample_error(rows, cols, sigma, q):
    """Samples discrete Gaussian noise"""
    return np.round(np.random.normal(0, sigma, size=(rows, cols))).astype(int) % q

# ----------------- Core AME Logic -----------------

def generate_parameters(lam=2):
    """Sets up the lattice dimensions and moduli"""
    q = 2**15
    p = 128  # Plaintext modulus
    n = lam * 2
    k = int(np.ceil(np.log2(q)))
    m = 10 * n
    # Trapdoor size
    n0 = random.randint(4, 8) 
    sigma = 1.0
    return {"q": q, "p": p, "m": m, "n": n, "n0": n0, "k": k, "sigma": sigma}

def anamorphic_keygen(par):
    """
    Generates:
    1. ask: Standard Secret Key (for fake msg)
    2. apk: Anamorphic Public Key
    3. dk/tk: Double Key/Trapdoor (for real msg)
    """
    q, m, n, n0 = par['q'], par['m'], par['n'], par['n0']

    # 1. Create secret key s (with some zeros to plant the trapdoor)
    s = np.zeros((m, 1), dtype=int)
    indices = list(range(m))
    random.shuffle(indices)
    
    # Fill secret key with {-1, 0, 1}
    for i in range(m):
        s[i, 0] = random.choice([-1, 0, 1])

    # 2. Identify indices where s is 0 to 'plant' the trapdoor
    J = [i for i in range(m) if s[i, 0] == 0]
    if len(J) < n0: return anamorphic_keygen(par) # Retry if not enough zeros
    dk = random.sample(J, n0)

    # 3. Construct the public matrix A with a hidden relationship in dk columns
    A = np.random.randint(0, q, size=(n, m))
    
    # Internal trapdoor components (Section 5.2 of the paper)
    A0 = np.random.randint(0, q, size=(n, n0-1))
    t_prime = sample_error(n0-1, 1, 1.0, q)
    eI = sample_error(n, 1, 1.0, q)
    
    # A_hat construction
    A_hat_last_col = (np.matmul(A0, t_prime) + eI) % q
    
    # Assign A_hat to the A matrix at dk indices
    for idx, col in enumerate(dk[:-1]):
        A[:, col] = A0[:, idx]
    A[:, dk[-1]] = A_hat_last_col.flatten()

    # 4. Finalize Public Key B = [A^T | As]
    As = np.matmul(s.T, A.T) % q
    B = np.vstack([A.T, As])

    # Trapdoor vector tk
    tk = np.zeros((m, 1), dtype=int)
    for i, idx in enumerate(dk[:-1]):
        tk[idx, 0] = -t_prime[i, 0]
    tk[dk[-1], 0] = 1

    return s, (par, B), dk, tk



def anamorphic_encrypt(apk, dk, msg_fake, msg_real):
    """
    Embeds two messages into one ciphertext.
    msg_fake: what the dictator sees.
    msg_real: what the secret contact sees.
    """
    par, B = apk
    q, m, n, k, sigma = par['q'], par['m'], par['n'], par['k'], par['sigma']
    
    M = k * (m + 1)
    S = sample_error(n, M, 0.5, q) # Small masking matrix
    E = sample_error(m + 1, M, sigma, q)

    # Diagonal matrix J to hold different messages at trapdoor indices
    J = np.zeros((m + 1, m + 1), dtype=int)
    for i in range(m + 1):
        if i in dk:
            J[i, i] = msg_real
        else:
            J[i, i] = msg_fake

    # Kronecker product for G-matrix embedding
    g = 2 ** np.arange(k)
    Jg = np.kron(J, g) % q
    
    # Ciphertext C = B*S + Jg + E
    C = (np.matmul(B, S) + Jg + E) % q
    return C

def normal_decrypt(par, ask, C):
    """Decrypts using the standard secret key (reveals fake msg)"""
    q, p, m = par['q'], par['p'], par['m']
    delta = q // p
    
    # Decryption vector [ -s^T | 1 ]
    sk_neg = np.concatenate([-ask.T, [[1]]], axis=1)
    
    # Extract scaled message
    em_delta = np.zeros((m+1, 1))
    em_delta[-1] = delta
    G_inv = gadget_inverse(em_delta, q)
    
    v = np.matmul(np.matmul(sk_neg, C), G_inv) % q
    return int(np.round(v.item() / delta)) % p

def secret_decrypt(par, dk, tk, C):
    """Decrypts using the trapdoor key (reveals real msg)"""
    q, p, m = par['q'], par['p'], par['m']
    delta = q // p
    
    # Unit vector at the last trapdoor index
    e_hat = np.zeros((m+1, 1))
    e_hat[dk[-1]] = delta
    G_inv = gadget_inverse(e_hat, q)
    
    # Decryption row [ tk^T | 0 ]
    t_row = np.concatenate([tk.T, [[0]]], axis=1)
    
    v = np.matmul(np.matmul(t_row, C), G_inv) % q
    return int(np.round(v.item() / delta)) % p

# ----------------- Execution -----------------

if __name__ == "__main__":
    params = generate_parameters()
    ask, apk, dk, tk = anamorphic_keygen(params)

    # 1. Define your two messages
    REAL_MSG = 88   # The secret communication
    FAKE_MSG = 12   # The decoy for the dictator

    print(f"Original Intent -> Real: {REAL_MSG}, Fake: {FAKE_MSG}")

    # 2. Encrypt into a single ciphertext
    ciphertext = anamorphic_encrypt(apk, dk, FAKE_MSG, REAL_MSG)

    # 3. Decrypt with Key 1 (Secret Key - Dictator's view)
    revealed_fake = normal_decrypt(params, ask, ciphertext)
    print(f"Key 1 (ask) Decryption: {revealed_fake}  <-- This is what the Dictator sees")

    # 4. Decrypt with Key 2 (Trapdoor Key - Real view)
    revealed_real = secret_decrypt(params, dk, tk, ciphertext)
    print(f"Key 2 (tk)  Decryption: {revealed_real}  <-- This is the hidden message")