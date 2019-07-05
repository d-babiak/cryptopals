import binascii
from itertools import cycle
from string import ascii_uppercase, ascii_lowercase, digits
from typing import *
import array

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


def repeating_key_xor(m: bytes, key: bytes) -> bytes:
    buf = (x ^ y for x, y in zip(m, cycle(key)))
    return array.array('B', buf).tobytes()

def test_repeating_key_xor():
    s1 = \
     b"Burning 'em, if you ain't quick and nimble\n" \
     b"I go crazy when I hear a cymbal"

    actual = binascii.hexlify(repeating_key_xor(s1, b'ICE'))

    expected = b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'

    assert actual == expected
