import hashlib
from hashing import *

m_sha256 = hashlib.sha256()

m_sha256.update(b"")
dg = m_sha256.digest().hex()

# print(hashlib.algorithms_available)

m_ripe = hashlib.new("ripemd160")
m_ripe.update(b"hello this is a test")
ripe_digest = m_ripe.digest()
ripe_hex = ripe_digest.hex()


print(dg)

print(sha256(b"").hex())
print(sha256(b"").hex())
print(sha256(b"").hex())
