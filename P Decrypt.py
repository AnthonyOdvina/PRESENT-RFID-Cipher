"""
=====================================================================================
MIT License

Copyright (c) 2024 Anthony Odvina Henry Crawley

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
====================================================================================
"""
Sbox = [0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2]
Sbox_inv = [Sbox.index(x) for x in range(16)]

# P-box definitions
PBox = [
    0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
    4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
    8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
    12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63
]
PBox_inv = [PBox.index(x) for x in range(64)]

def generateRoundkeys80(key, rounds):
    """Generate the roundkeys for a 80-bit key

    Input:
        key:    the key as a 80-bit integer
        rounds: the number of rounds as an integer
    Output: list of 64-bit roundkeys as integers"""
    roundkeys = []
    for i in range(1, rounds + 1): # (K1 ... K32)
        roundkeys.append(key >> 16)
        key = ((key & (2 ** 19 - 1)) << 61) + (key >> 19)
        key = (Sbox[key >> 76] << 76) + (key & (2 ** 76 - 1))
        key ^= i << 15
    return roundkeys

def addRoundKey(state, roundkey):
    return state ^ roundkey

def sBoxLayer(state, inverse=False):
    """SBox function for encryption or decryption

    Input:  64-bit integer
    Output: 64-bit integer"""
    sbox = Sbox_inv if inverse else Sbox
    return sum(sbox[(state >> (i * 4)) & 0xF] << (i * 4) for i in range(16))

def pLayer(state, inverse=False):
    """Permutation layer for encryption or decryption

    Input:  64-bit integer
    Output: 64-bit integer"""
    pbox = PBox_inv if inverse else PBox
    return sum(((state >> i) & 0x01) << pbox[i] for i in range(64))

class Present:

    def __init__(self, key, rounds=32):
        """Create a PRESENT cipher object

        key:    the key as a 128-bit or 80-bit raw string
        rounds: the number of rounds as an integer, 32 by default
        """
        self.rounds = rounds
        if len(key) * 4 == 80:
            self.roundkeys = generateRoundkeys80(string2number(key),self.rounds)
        else:
            raise ValueError("Key must be a 128-bit or 80-bit raw string")

    def encrypt(self, block):
        """Encrypt 1 block (8 bytes)

        Input:  plaintext block as raw string
        Output: ciphertext block as raw string
        """
        state = string2number(block)
        for i in range (self.rounds-1):
            state = addRoundKey(state,self.roundkeys[i])
            state = sBoxLayer(state)
            state = pLayer(state)
        cipher = addRoundKey(state,self.roundkeys[-1])
        return number2string_N(cipher,8)

    def decrypt(self, block):
        """Decrypt 1 block (8 bytes)

        Input:  ciphertext block as raw string
        Output: plaintext block as raw string
        """
        state = string2number(block)
        for i in range (self.rounds-1):
            state = addRoundKey(state,self.roundkeys[-i-1])
            state = pLayer(state, inverse=True)  # Use inverse permutation
            state = sBoxLayer(state, inverse=True)  # Use inverse S-box
        decipher = addRoundKey(state,self.roundkeys[0])
        return number2string_N(decipher,8)

def string2number(i):
    """ Convert a string to a number

    Input: string (big-endian)
    Output: long or integer
    """
    return int(i, 16)

def number2string_N(i, N):
    """Convert a number to a string of fixed size

    i: long or integer
    N: length of string
    Output: string (big-endian)
    """
    s = '%0*x' % (N*2, i)
    return s

key   = "00000000000000000000"
plain = "bed0000000000000"

cipher = Present(key)

encrypted = cipher.encrypt(plain) 
print("encrypted",encrypted)

decrypted = cipher.decrypt(encrypted) 
print("decrypted",decrypted)
