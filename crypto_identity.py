from __future__ import annotations
from dataclasses import dataclass

from numpy import binary_repr

from hashing import *

from base58 import b58encode



@dataclass
class Curve:
    """
    Elliptic Curve over the fielw of intergers modulo a prime.
    Points on the curve satisfy y^2 = x^3 + a*x + b (mod p).
    """
    p: int # the prime modulus of the finite field
    a: int
    b: int

# secp256k1 uses a = 0, b = 7, so we're dealing with the curve y^2 = x^3 + 7 (mod p)
bitcoin_curve = Curve(
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a = 0x0000000000000000000000000000000000000000000000000000000000000000, # a = 0
    b = 0x0000000000000000000000000000000000000000000000000000000000000007, # b = 7
)

@dataclass
class Point:
    """ An Integer point (x,y) on a Curve """
    curve: Curve
    x: int
    y: int

G = Point(
    bitcoin_curve,
    x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
)

# we can verify that the generator point is indeed on the curve, i.e y^2 = x^3 + 7 (mod p)
# print("Generator IS on the curve: ", (G.y**2 - G.x**3 - 7) % bitcoin_curve.p == 0)

@dataclass
class Generator:
    """ 
    A generator over a curve: an initial point and the (pre-compiled) order
    """

    G: Point    # a generator point on the curve
    n: int      # the order of the generating point, so 0*G = n*G = INF

bitcoin_gen = Generator(
    G = G,
    # the order of G is known and can be mathematically derived
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
)

# secret_key = random.randrange(1, bitcoin_gen.n) # this is how you _would_ do it
secret_key = int.from_bytes(b'Andrej is cool :P', 'big')
# secret_key = int.from_bytes(b'AbCdEfGhIjKlMnOpQrStUvWxYz', 'big')
assert 1 <= secret_key < bitcoin_gen.n

# print(secret_key)


# Special point at infinity, kind of like a zero
INF = Point(None, None, None)

def extended_euclidean_algorithm(a, b):
    """
    Returns (gcd, x, y) s.t. a * x + b * y == gcd
    This function implements the extended Euclidean
    algorithm and run in O(log b) in the worst case,
    taken from Wikipedia
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_r, old_s, old_t

def inv(n, p):
    """ returns modular multiplicate inverse m s.t. (n * m) %p == 1 """
    gcd, x, y = extended_euclidean_algorithm(n, p)
    return x % p

def elliptic_curve_addition(self, other: Point) -> Point:
    # Handle special case of P + 0 = 0 + P = 0
    if self == INF:
        return other
    if other == INF:
        return self
    ## Handle special case of P + (-P) = 0
    if self.x == other.x and self.y != other.y:
        return INF
    # compute the "slope"
    if self.x == other.x: # (self.y = other.y is guaranteed too per above check)
        m = (3 * self.x**2 + self.curve.a) * inv(2 * self.y, self.curve.p)
    else:
        m = (self.y - other.y) * inv(self.x - other.x, self.curve.p)
    ## Compute the new product
    rx = (m ** 2 - self.x - other.x) % self.curve.p
    ry = (-(m*(rx - self.x) + self.y)) % self.curve.p
    return Point(self.curve, rx, ry)

Point.__add__ = elliptic_curve_addition # monkey patch addition to the Point class



# if our secret key was the integer 1, then our public key would just be G:
# sk = 1
# pk = G
# print(f" secret key: {sk}\n public key: {(pk.x, pk.y)}")
# print("Verify the public key is on the curve: ", (pk.y**2 - pk.x**3 - 7) % bitcoin_curve.p == 0)
# # if it was 2, the public key is G + G:
# sk = 2
# pk = G + G
# print(f" secret key: {sk}\n public key: {(pk.x, pk.y)}")
# print("Verify the public key is on the curve: ", (pk.y**2 - pk.x**3 - 7) % bitcoin_curve.p == 0)
# # etc.:
# sk = 3
# pk = G + G + G
# print(f" secret key: {sk}\n public key: {(pk.x, pk.y)}")
# print("Verify the public key is on the curve: ", (pk.y**2 - pk.x**3 - 7) % bitcoin_curve.p == 0)


def double_and_add(self, k: int) -> Point:
    assert isinstance(k, int) and k >= 0
    result = INF
    append = self
    while k:
        if k & 1:
            result += append
        append += append
        k >>= 1
    return result

# monkey patch double and add into the Point class for convenience
Point.__rmul__ = double_and_add

# "verify" correctness
# print(G == 1*G)
# print(G + G == 2*G)
# print(G + G + G == 3*G)

# efficiently calculate our actual public key!
public_key = secret_key * G
# print(f"x: {public_key.x}\ny: {public_key.y}")
# print("Verify the public key is on the curve: ", (public_key.y**2 - public_key.x**3 - 7) % bitcoin_curve.p == 0)


class PublicKey(Point):
    """
    The public key is just a Point on a Curve, but has some additional specific
    encoding / decoding functionality that this class implements.
    """

    @classmethod
    def from_point(cls, pt: Point):
        """ promote a Point to be a PublicKey """
        return cls(pt.curve, pt.x, pt.y)

    def encode(self, compressed, hash160=False):
        """ return the SEC bytes encoding of the public key Point """
        # calculate the bytes
        if compressed:
            # (x,y) is very redundant. Because y^2 = x^3 + 7,
            # we can just encode x, and then y = +/- sqrt(x^3 + 7),
            # so we need one more bit to encode whether it was the + or the -
            # but because this is modular arithmetic there is no +/-, instead
            # it can be shown that one y will always be even and the other odd.
            prefix = b'\x02' if self.y % 2 == 0 else b'\x03'
            pkb = prefix + self.x.to_bytes(32, 'big')
        else:
            pkb = b'\x04' + self.x.to_bytes(32, 'big') + self.y.to_bytes(32, 'big')
        # hash if desired
        return ripemd160(sha256(pkb)) if hash160 else pkb
    
    def address(self, net: str, compressed: bool) -> str:
        """ return the associated bitcoin address for this public key as string """
        # encode the public key into bytes and hash to get the payload
        pkb_hash = self.encode(compressed=compressed, hash160=True)
        # add version byte (0x00 for Main Network, or 0x6f for Test Network)
        version = {'main': b'\x00', 'test': b'\x6f'}
        ver_pkb_hash = version[net] + pkb_hash
        # calculate the checksum
        checksum = sha256(sha256(ver_pkb_hash))[:4]
        # append to form the full 25-byte binary Bitcoin Address
        byte_address = ver_pkb_hash + checksum
        # finally b58 encode the result
        b58check_address = b58encode(byte_address)
        return b58check_address

    
# we are going to use the develop's Bitcoin parallel universe "test net" for this demo, so net='test'
address = PublicKey.from_point(public_key).address(net='test', compressed=True)
# print(address)

# lol_secret_key = 1
# lol_public_key = lol_secret_key * G
# lol_address = PublicKey.from_point(lol_public_key).address(net='test', compressed=True)
# print(lol_address)


print("Our first Bitcoin identity:")
print("1. secret key: ", secret_key)
print("2. public key: ", (public_key.x, public_key.y))
print("3. Bitcoin address: ", address)






