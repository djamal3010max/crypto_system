#!/usr/bin/env python3
"""Generate tb/ops/vectors.vh (known-answer vectors for the 8 operation testbenches)."""
import hashlib, os, sys
sys.path.insert(0, os.path.dirname(__file__))
from p256 import *
from Crypto.Cipher import AES

out = []
def v(name, val, bits=256):
    out.append(f"localparam [{bits-1}:0] {name} = {bits}'h{val:0{bits//4}x};")
def H(x): return int.from_bytes(x, "big")

# ---------------- AES-128 (FIPS-197 C.1, SP 800-38A F.1.1 / F.2.1) ----------------
k1 = bytes(range(16)); pt1 = bytes.fromhex("00112233445566778899aabbccddeeff")
ct1 = AES.new(k1, AES.MODE_ECB).encrypt(pt1); assert ct1.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"
v("AES_K1", H(k1), 128); v("AES_P1", H(pt1), 128); v("AES_C1", H(ct1), 128)
k2 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"); iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
pts = ["6bc1bee22e409f96e93d7e117393172a", "ae2d8a571e03ac9c9eb76fac45af8e51",
       "30c81c46a35ce411e5fbc1191a0a52ef", "f69f2445df4f9b17ad2b417be66c3710"]
ecb = [AES.new(k2, AES.MODE_ECB).encrypt(bytes.fromhex(x)) for x in pts]
assert ecb[0].hex() == "3ad77bb40d7a3660a89ecaf32466ef97"
cbc = AES.new(k2, AES.MODE_CBC, iv).encrypt(bytes.fromhex("".join(pts)))
assert cbc[:16].hex() == "7649abac8119b246cee98e9b12e9197d"
v("AES_K2", H(k2), 128); v("AES_IV", H(iv), 128)
for i in range(4):
    v(f"AES_P2_{i}", H(bytes.fromhex(pts[i])), 128)
    v(f"AES_E2_{i}", H(ecb[i]), 128)
    v(f"AES_CB_{i}", H(cbc[16*i:16*i+16]), 128)

# AES key unwrap example: KEK = AES_K1, wrapped (ECB) 128-bit working key
wk = bytes.fromhex("5a17c0de0badcafe1122334455667788")
v("UNWRAP_PT", H(wk), 128); v("UNWRAP_CT", H(AES.new(k1, AES.MODE_ECB).encrypt(wk)), 128)

# ---------------- SHA-256 of 32-byte messages ----------------
msgs = {"H_M0": bytes(32), "H_M1": bytes([0xff]*32), "H_M2": bytes(range(32)),
        "H_M3": b"smart-card crypto core test!!".ljust(32, b"."), "H_M4": hashlib.sha256(b"seed").digest()}
for nm, m in msgs.items():
    v(nm, H(m)); v(nm.replace("_M", "_D"), H(hashlib.sha256(m).digest()))

# ---------------- keys ----------------
dA = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef % n
dB = 0xc0ffee00deadbeef0123456789abcdef0fedcba9876543210011223344556677 % n
dI = 0x0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff1 % n   # "issuer" key
QA, QB, QI = mul(dA, G), mul(dB, G), mul(dI, G)
for nm, d in (("DA", dA), ("DB", dB), ("DI", dI)): v(nm, d)
for nm, Q in (("QA", QA), ("QB", QB), ("QI", QI)): v(nm + "X", Q[0]); v(nm + "Y", Q[1])

# ---------------- ECDH ----------------
S = ecdh(dA, QB); assert S == ecdh(dB, QA)
v("ECDH_SHARED", S)
kq = 0x3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b % n
Qk = mul(kq, G); v("ECDH_EPH_D", kq); v("ECDH_EPH_QX", Qk[0]); v("ECDH_EPH_QY", Qk[1])
# off-curve point: valid x with a wrong y
bad = (QB[0], (QB[1] + 1) % p); assert not on_curve(bad)
v("BAD_PX", bad[0]); v("BAD_PY", bad[1])
v("GX", G[0]); v("GY", G[1])

# ---------------- ECDSA known-answer signatures (fixed nonces) ----------------
def ksig(tag, d, Q, msg, k):
    e = H(hashlib.sha256(msg).digest()); r, s = sign(d, e, k); assert verify(Q, e, r, s)
    v(tag + "_E", e); v(tag + "_R", r); v(tag + "_S", s)
ksig("SIG1", dA, QA, b"ECDSA KAT message one", 0x9f3c17e5a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c % n)
ksig("SIG2", dI, QI, b"certificate body (TBS) v1", 0x1c2d3e4f5a6b7c8d9eafb0c1d2e3f405162738495a6b7c8d9eafb0c1d2e3f405 % n)
# certificate body is a 32-byte string whose SHA-256 is signed by the issuer
cert_body = b"CERT:cardpub:0001:issuer:CA-01".ljust(32, b"."); assert len(cert_body) == 32
ce = H(hashlib.sha256(cert_body).digest()); cr, cs = sign(dI, ce, 0x5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c % n)
assert verify(QI, ce, cr, cs)
v("CERT_BODY", H(cert_body)); v("CERT_HASH", ce); v("CERT_R", cr); v("CERT_S", cs)
bad_body = bytearray(cert_body); bad_body[10] ^= 0x01
v("CERT_BAD_BODY", H(bytes(bad_body)))
v("N_ORDER", n)

# ---------------- hash-then-sign / hash-then-verify / ECDH KDF vectors ----------------
hm = bytes((i * 37 + 11) & 0xff for i in range(100))
hm_bad = bytearray(hm); hm_bad[99] ^= 0x01
out.append(f"localparam [799:0] HM_MSG = 800'h{hm.hex()};")
out.append(f"localparam [799:0] HM_MSG_BAD = 800'h{bytes(hm_bad).hex()};")
def e_of(name, data):
    d = hashlib.new(name, data).digest()
    return H(d[:32]) if len(d) >= 32 else H(d)          # leftmost 256 bits, or the digest as an integer
for tag, nm in (("256", "sha256"), ("384", "sha384"), ("224", "sha224")):
    e = e_of(nm, hm); v("HM_E" + tag, e)
    r_, s_ = sign(dA, e, (0x7a1b2c3d4e5f60718293a4b5c6d7e8f9 << 128 | int(tag) * 0x0102030405060708090a0b0c0d0e0f10) % n or 1)
    assert verify(QA, e, r_, s_)
    v("SIGM" + tag + "_R", r_); v("SIGM" + tag + "_S", s_)
_info = b"ctx-key"
_zb = ECDH_Z = S.to_bytes(32, "big")
v("KDF_INFO", H(_info.ljust(28, b"\0")) << 32, 256)           # info left-aligned in a[255:32]
v("KDF_OUT", H(hashlib.sha256(b"\x00\x00\x00\x01" + _zb + _info).digest()))
v("KDF_OUT0", H(hashlib.sha256(b"\x00\x00\x00\x01" + _zb).digest()))

# ---------------- SCC-1 certificates: 0x01 || subject x || subject y, signed (SHA-256) by the issuer ----------------
dS = 0x6b8d4e2f1a3c5d7e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9011223344556 % n
QS = mul(dS, G)
def scc(tag, body, nonce, sign_it=True):
    v(tag + "_BODY", H(body), 8 * len(body))
    if sign_it:
        e = H(hashlib.sha256(body).digest()); r_, s_ = sign(dI, e, nonce % n); assert verify(QI, e, r_, s_)
        v(tag + "_R", r_); v(tag + "_S", s_); v(tag + "_E", e)
good_body = b"\x01" + QS[0].to_bytes(32, "big") + QS[1].to_bytes(32, "big")
scc("SCC", good_body, 0x6d8fa1c3e5071a2b3c4d5e6f8091a2b3c4d5e6f708192a3b4c5d6e7f80910)
bad = bytearray(good_body); bad[40] ^= 0x01
v("SCC_TAMPER_BODY", H(bytes(bad)), 8 * 65)                 # same signature, altered subject key
offc = b"\x01" + QS[0].to_bytes(32, "big") + ((QS[1] + 1) % p).to_bytes(32, "big")
scc("SCCOFF", offc, 0x7e90b2d4f60819a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f8192)   # validly signed, key NOT on the curve
badver = b"\x02" + good_body[1:]
v("SCCVER_BODY", H(badver), 8 * 65)
# the subject proves the installed key works: it signs a message hash
ch_e = H(hashlib.sha256(b"chain test message").digest()); ch_r, ch_s = sign(dS, ch_e, 0x1122334455667788990a1b2c3d4e5f60718293a4b5c6d7e8f9011223344556 % n)
assert verify(QS, ch_e, ch_r, ch_s)
v("CHAIN_E", ch_e); v("CHAIN_R", ch_r); v("CHAIN_S", ch_s)

# ---------------- secure-load packages (wrapped key signed by the issuer, with anti-replay version) ----------------
_pt = bytes.fromhex("00112233445566778899aabbccddeeff")
def sl_package(tag, key, dest, attr, kek, iss, version, nonce):
    wrapped = AES.new(k1, AES.MODE_ECB).encrypt(key)                   # KEK = AES_K1, held in key slot 0
    msg = wrapped + bytes([dest, attr, kek, iss]) + version.to_bytes(4, "big")   # signed message: 24 bytes
    e = H(hashlib.sha256(msg).digest())
    r_, s_ = sign(dI, e, nonce % n)
    assert verify(QI, e, r_, s_)
    v(tag + "_A", (H(wrapped) << 128) | (version << 8) | (kek << 4) | iss)      # a[255:128]=wrapped, a[39:8]=version, a[7:4]=KEK slot, a[3:0]=issuer slot
    v(tag + "_R", r_); v(tag + "_S", s_)
    v(tag + "_CT", H(AES.new(key, AES.MODE_ECB).encrypt(_pt)), 128)    # a block encrypted under the installed key
KEY_A = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
KEY_B = bytes.fromhex("a1b2c3d4e5f60718293a4b5c6d7e8f90")
sl_package("SL",    KEY_A, 4, 2, 0, 6, 5, 0x2f4e6d8c9bafcde0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778)
sl_package("SLOLD", KEY_A, 4, 2, 0, 6, 4, 0x3a5c7e90b2d4f60819a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70)
sl_package("SLNEW", KEY_B, 4, 2, 0, 6, 6, 0x4b6d8fa1c3e5071a2b3c4d5e6f8091a2b3c4d5e6f708192a3b4c5d6e7f809)
sl_package("SLLCK", KEY_A, 5, 2, 0, 6, 1, 0x5c7e90b2d4f60819a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f81)
v("SL_PT", H(_pt), 128)

# ---------------- streaming hash vectors (all 9 algorithms, several lengths and chunk sizes) ----------------
import random
random.seed(2024)
_algs = [("sha1", 20), ("sha224", 28), ("sha256", 32), ("sha384", 48), ("sha512", 64),
         ("sha3_224", 28), ("sha3_256", 32), ("sha3_384", 48), ("sha3_512", 64)]
_lines = []
for ai, (nm, dl) in enumerate(_algs):
    for L in (0, 3, 64, 111, 129, 300):
        for ch in (64, 17):
            m = bytes(random.getrandbits(8) for _ in range(L))
            d = hashlib.new(nm, m).digest()
            _lines.append(f"    hs({ai}, {L}, {ch}, 2400'h{(m.hex() + '00'*(300-L))}, 512'h{(d + bytes(64-dl)).hex()}, {dl*8});")
open(os.path.join(os.path.dirname(__file__), "..", "tb", "ops", "hash_stream.vh"), "w").write("// GENERATED by tools/gen_vectors.py\n" + "\n".join(_lines) + "\n")

open(os.path.join(os.path.dirname(__file__), "..", "tb", "ops", "vectors.vh"), "w").write(
    "// GENERATED by tools/gen_vectors.py -- do not edit\n" + "\n".join(out) + "\n")
print(len(out), "vectors written")
