def gen_sha256_with_variable_scope_protector_to_not_pollute_global_namespace():

    """
    SHA256 implementation.

    Follows the FIPS PUB 180-4 description for calculating SHA-256 hash function
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

    Noone in their right mind should use this for any serious reason. This was written
    purely for educational purposes.
    """

    import math
    from itertools import count, islice

    # -----------------------------------------------------------------------------
    # SHA-256 Functions, defined in Section 4

    def rotr(x, n, size=32):
        return (x >> n) | (x << size - n) & (2**size - 1)

    def shr(x, n):
        return x >> n

    def sig0(x):
        return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)

    def sig1(x):
        return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)

    def capsig0(x):
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

    def capsig1(x):
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

    def ch(x, y, z):
        return (x & y)^ (~x & z)




        