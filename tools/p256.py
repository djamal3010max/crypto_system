"""Minimal pure-Python NIST P-256 / ECDSA / ECDH reference (for test vectors only)."""
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)

def on_curve(P):
    return P is not None and 0 <= P[0] < p and 0 <= P[1] < p and (P[1]*P[1] - (P[0]**3 - 3*P[0] + b)) % p == 0

def add(P, Q):
    if P is None: return Q
    if Q is None: return P
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0: return None
    if P == Q: l = (3*P[0]*P[0] + p - 3) * pow(2*P[1], -1, p) % p
    else:      l = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p) % p
    x = (l*l - P[0] - Q[0]) % p
    return (x, (l*(P[0] - x) - P[1]) % p)

def mul(k, P):
    R = None
    while k:
        if k & 1: R = add(R, P)
        P = add(P, P); k >>= 1
    return R

assert on_curve(G) and mul(n, G) is None

def sign(d, e, k):
    R = mul(k, G); r = R[0] % n
    s = pow(k, -1, n) * (e + r*d) % n
    assert r and s
    return r, s

def verify(Q, e, r, s):
    if not (0 < r < n and 0 < s < n): return False
    w = pow(s, -1, n)
    X = add(mul(e*w % n, G), mul(r*w % n, Q))
    return X is not None and X[0] % n == r

def ecdh(d, Q): return mul(d, Q)[0]
