import hashlib

def sha256(b: bytes) -> bytes:
    h_sha256 = hashlib.sha256()
    h_sha256.update(b)
    return h_sha256.digest()

def ripemd160(b: bytes) -> bytes:
    h_ripemd160 = hashlib.new("ripemd160")
    h_ripemd160.update(b)
    return h_ripemd160.digest()