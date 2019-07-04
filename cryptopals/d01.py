from typing import *
from string import ascii_uppercase, ascii_lowercase, digits

s_hex = bytes.fromhex('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
s_b64 = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

encoding = (
    ascii_uppercase 
  + ascii_lowercase 
  + digits 
  + '+/'
)

def hex_to_b64(s: bytes) -> bytes:
    x = ''.join(encode_triple(buf) for buf in chunked(s, n=3))
    return x.encode('ascii')

def test_hex_to_b64():
    assert hex_to_b64(s_hex) == s_b64

def bit_iter(xs):
    i = 0
    N = int(len(xs) * 8 / 6)
    for i in range(N):
        bits = ([(xs << (8 * i))][0] >> 2)
        yield bits


def encode_triple(x: bytes) -> str:
    assert(len(x) == 3)
    s1 =  (0b11111100 & x[0]) >> 2
    s2 = ((0b00000011 & x[0]) << 4) | ((0b11110000 & x[1]) >> 4)
    s3 = ((0b00001111 & x[1]) << 2) | ((0b11000000 & x[2]) >> 6)
    s4 =  (0b00111111 & x[2])

    return ''.join(
      encoding[bits] for bits in (s1, s2, s3, s4)
    )

def chunked(buf: bytes, n=3) -> Iterable[bytes]:
    for i in range(len(buf) // n):
        yield buf[i*n : (i+1)*n]

'''
64  - 6 bits
hex - 4 bits

3 hex => 12 bits = 2_b64
'''
