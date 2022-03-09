# base58 encoding / decoding utilities
# reference: https://en.bitcoin.it/wiki/Base58Check_encoding

alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def b58encode(b: bytes) -> str:
    assert len(b) == 25 # version is 1 byte, pkb_hash 20 bytes, checksum 4 bytes
    n = int.from_bytes(b, 'big')
    chars = []
    while n:
        n, i = divmod(n, 58)
        chars.append(alphabet[i])
    # special case handle the leading 0 bytes... ¯\_(ツ)_/¯
    num_leading_zeros = len(b) - len(b.lstrip(b'\x00'))
    res = num_leading_zeros * alphabet[0] + ''.join(reversed(chars))
    return res