import hashlib

# 1. SHA-256
result_sha256 = hashlib.sha256(b"algeria").hexdigest().upper()
print(f"SHA-256: {result_sha256}")

# 2. SHA-512
result_sha512 = hashlib.sha512(b"algeria").hexdigest().upper()
print(f"SHA-512: {result_sha512}")

# 3. SHA-3 (NIST FIPS 202 Standard)
result_sha3 = hashlib.sha3_256(b"algeria").hexdigest().upper()
print(f"SHA3-256: {result_sha3}")

