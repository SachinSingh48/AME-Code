import math
import numpy as np

lam = 16


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
        if i > 0:
             Sk[i, i-1] = -1
        if i < k - 1:
            Sk[i,i] = 2
        Sk[i, -1] = q_bits[i]

    I = np.eye(l, dtype=int)
    S = np.kron(I, Sk)
    return S


def gen_parameters(q=None):
    if q is None:
        q = 8192 * 64
    k = math.ceil(math.log2(q))
    n = 4*lam
    m_bar = n*k+2*lam
    p = 128
    alpha = 1/(2*q)
    std_dev = 1
    return p,q,n,m_bar,alpha,std_dev


def kgen(q):
    par = gen_parameters(q)
    p, q, n, m_bar, alpha, std_dev = par
    k = math.ceil(math.log2(q))
    m = m_bar + n*k
    A = sample_uniform_matrix(n,m,q)
    E = sample_error_matrix(m, n, std_dev, q)
    U = np.matmul(A, E) % q
    pk = par, A, U
    sk = E
    return sk, pk


def enc(pk, mu):
    par, A, U = pk
    p, q, n, m_bar, alpha, std_dev = par
    k = math.ceil(math.log2(q))
    m = m_bar + n*k
    delta = int(np.round(q/p))
    mu_delta = (delta*mu) % q

    s = sample_uniform_matrix(n, 1, q)
    e0 = sample_error_matrix(m, 1, std_dev, q)
    e1 = sample_error_matrix(n, 1, std_dev, q)

    c0 = (np.matmul(A.T, s) + e0) % q
    Us = (np.matmul(U.T, s)) % q
    c1 = (Us+e1+mu_delta) % q

    return c0, c1


def dec(sk, ct, p, q):
    c0, c1 = ct
    delta = int(np.round(q/p))

    c0_s = (np.matmul(sk.T, c0)) % q
    sub = (c1 - c0_s) % q
    m = np.round(sub/delta).astype(int) % p

    return m


def agen(q):
    # Generate parameters (same as kgen)
    par = gen_parameters(q)
    p, q, n, m_bar, alpha, std_dev = par
    k = math.ceil(math.log2(q))
    m = m_bar + n*k

    # Generate trapdoor matrix R ∈ {−1, 0, 1}
    R = np.random.randint(-1, 2, size=(m_bar, n*k))
    A_bar = sample_uniform_matrix(n, m_bar, q)
    G = gadget_matrix(n, k, q)

    right = (np.matmul(A_bar, R) + G) % q
    A = np.hstack((A_bar, right)).astype(int)

    E = sample_error_matrix(m, n, std_dev, q)

    U = (np.matmul(A, E)) % q

    apk = par, A, U
    ask = E
    dk = None
    tk = R

    return ask, apk, dk, tk


def aenc(apk, dk, mu, mu_bar):
    par, A, U = apk
    p, q, n, m_bar, alpha, std_dev = par
    k = math.ceil(math.log2(q))
    m = m_bar + n * k
    delta = int(np.round(q / p))
    mu_delta = (delta * mu) % q
    mu_bar_delta = (delta * mu_bar) % q

    s = sample_error_matrix(n, 1, alpha * q, q)
    s_hat = (s + mu_bar_delta) % q

    e0 = sample_error_matrix(m, 1, std_dev, q)
    e1 = sample_error_matrix(n, 1, std_dev, q)

    c0 = (np.matmul(A.T, s_hat) + e0) % q
    c1 = (np.matmul(U.T, s_hat) + e1 + mu_delta) % q

    return c0, c1


def adec(apk, dk, tk, ask, act):
    c0, c1 = act
    par, A, U = apk
    p, q, n, m_bar, alpha, std_dev = par
    k = math.ceil(math.log2(q))

    # Split c0 in two pieces
    c0_part1 = c0[:m_bar]
    c0_part2 = c0[m_bar:]

    # Calculate c0_part2 - R^T*c0_part1
    c0_diff = (c0_part2 - np.matmul(tk.T, c0_part1))

    # Calculate gadget matrix G
    G = gadget_matrix(n, k, q)

    # Calculate S matrix
    S = calculateSMatrix(k, n, q)

    # Check that G*S mod q is 0
    result = np.matmul(G, S)
    is_zero = np.all((result % q) == 0)
    # print("G*S == 0 mod q?", is_zero)

    # Calculate S^T*(c0_part2 - R^T*c0_part1) = e2 - R^T*e1
    diff_T = np.matmul(S.T, c0_diff)

    # Calculate G^T*s = (c0_part2 - R^T*c0_part1) - (e2 - R^T*e1)
    Gs = c0_diff - diff_T

    # Get s from Gs
    s = Gs[::k]
    # Calculate e
    e = (c0 - np.matmul(A.T, s)%q)
    s_final = np.round(s * (p / q)).astype(int) % p

    return s_final, e


# q = 2**22
# sk, pk = kgen(q)
# par = pk[0]
# p, q, n, m_bar,  alpha, std_dev = par
# mu1 = sample_uniform_matrix(n, 1, p)
# enc_mu = enc(pk, mu1)
# d_mu = dec(sk, enc_mu, p, q)

# print(mu1.T)
# print(d_mu.T)

# if np.array_equal(mu1, d_mu):
#     print("Dual Regev decryption works!")
# else:
#     print("Dual Regev decryption fails!")

# mu = sample_uniform_matrix(n, 1, p)
# mu_bar = mu

# ask, apk, dk, tk = agen(q)
# par = apk[0]
# p, q, n, m_bar, alpha, std_dev = par
# ct = enc(apk, mu)
# dm = dec(ask, ct, p, q)
# act = aenc(apk, dk, mu, mu_bar)
# de_mu_bar = adec(apk, dk, tk, ask, act)

# print(mu.T)
# print(dm.T)

# if np.array_equal(mu, dm):
#     print("Regular encryption and decryption works on anamorphic key pair!")
# else:
#     print("Regular encryption and decryption fails on anamorphic key pair!")

# print(mu_bar.T)
# print(de_mu_bar[0].T)

# if np.array_equal(mu_bar, de_mu_bar[0]):
#     print("Anamorphic Dual Regev decryption works! :)")
# else:
#     print("Anamorphic Dual Regev decryption fails! :(")

# d_mu = dec(ask, act, p, q)

# print(d_mu.T)
# print(mu.T)

# if np.array_equal(d_mu, mu):
#     print("Regular decryption works on anamorphic ciphertext!")
# else:
#     print("Regular decryption fails on anamorphic ciphertext!")

