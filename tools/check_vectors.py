#!/usr/bin/env python3
"""Independent re-check of vectors dumped by the simulation:
   sign_vectors.txt  : "digest r s qx qy"  -> ECDSA verification in pure Python
   ecdh_vectors.txt  : "k x"               -> x must equal (k*G).x
usage: check_vectors.py [dir]"""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from p256 import *
d = sys.argv[1] if len(sys.argv) > 1 else "."
bad = 0
f = os.path.join(d, "sign_vectors.txt")
if os.path.exists(f):
    for i, line in enumerate(open(f)):
        e, r, s, qx, qy = (int(x, 16) for x in line.split())
        ok = verify((qx, qy), e % n if e >= n else e, r, s) or verify((qx, qy), e, r, s)
        print(f"sign vector {i}: {'PASS' if ok else 'FAIL'} (independent Python ECDSA verify)"); bad += (not ok)
f = os.path.join(d, "ecdh_vectors.txt")
if os.path.exists(f):
    for i, line in enumerate(open(f)):
        k, x = (int(v, 16) for v in line.split())
        ok = mul(k % n, G)[0] == x
        print(f"ecdh vector {i}: {'PASS' if ok else 'FAIL'} (x(k*G) matches Python)"); bad += (not ok)
sys.exit(1 if bad else 0)
