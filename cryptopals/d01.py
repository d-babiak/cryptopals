from collections import defaultdict
from math import sqrt
import array
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

def fixed_xor(x: bytes, y: bytes):
    if isinstance(x, str):
        x = bytes.fromhex(x)

    if isinstance(y, str):
        y = bytes.fromhex(y)

    assert len(x) == len(y)

    buf = [
      x[i] ^ y[i]
      for i in range(len(x))
    ]    

    return array.array('B', buf).tobytes()

def test_fixed_xor():
    X = '1c0111001f010100061a024b53535009181c'
    Y = '686974207468652062756c6c277320657965'
    Z = bytes.fromhex('746865206b696420646f6e277420706c6179')
    assert fixed_xor(X, Y) == Z


LETTER_FREQ = defaultdict(int)
LETTER_FREQ.update({ 
  ord('e'): 12.02,
  ord('t'): 9.10,
  ord('a'): 8.12,
  ord('o'): 7.68,
  ord('i'): 7.31,
  ord('n'): 6.95,
  ord('s'): 6.28,
  ord('r'): 6.02,
  ord('h'): 5.92,
  ord('d'): 4.32,
  ord('l'): 3.98,
  ord('u'): 2.88,
  ord('c'): 2.71,
  ord('m'): 2.61,
  ord('f'): 2.30,
  ord('y'): 2.11,
  ord('w'): 2.09,
  ord('g'): 2.03,
  ord('p'): 1.82,
  ord('b'): 1.49,
  ord('v'): 1.11,
  ord('k'): 0.69,
  ord('x'): 0.17,
  ord('q'): 0.11,
  ord('j'): 0.10,
  ord('z'): 0.07,
})


with open('/usr/share/dict/words') as fp:
    ENGLISH = {s.strip().lower() for s in fp}

def argmax_single_byte_xor_cipher(cipher):
    highest = float('-inf')
    argmax  = None
    for i in range(256):
        try:
            key = array.array('B', [i for _ in cipher]).tobytes()
            M = fixed_xor(cipher, key)
            S = sum(
              x.decode('utf-8') in ENGLISH
              for x in M.split(b' ')
            )
            if S > highest:
                highest = S
                argmax  = M
        except UnicodeDecodeError:
            continue

    return highest, argmax or ''


def p4():
    with open('./data/single_byte_xor.input') as fp:
        buffers = tuple(bytes.fromhex(s.strip()) for s in fp)

    X = {
      buf: argmax_single_byte_xor_cipher(buf)
      for buf in buffers
    }

    buf, (N, msg) = max(
      list(X.items()), 
      key=lambda x: x[1][0]
    )
    print(buf, msg, N)
