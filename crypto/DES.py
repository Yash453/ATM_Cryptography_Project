import math
import random

initPermutation = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

fExpansion = [
    32, 1, 2, 3, 4, 5, 4, 5,
    6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27,
    28, 29, 28, 29, 30, 31, 32, 1
]
 
p32 = [
    16,  7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
]

shifts = [ 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 ]

p48 = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
]

p56 = [
    1, 2, 3, 4, 5, 6, 7,
    9, 10, 11, 12, 13, 14, 15,
    17, 18, 19, 20, 21, 22, 23,
    25, 26, 27, 28, 29, 30, 31,
    33, 34, 35, 36, 37, 38, 39,
    41, 42, 43, 44, 45, 46, 47,
    49, 50, 51, 52, 53, 54, 55,
    57, 58, 59, 60, 61, 62, 63
]

sBoxes = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]
 
inverseInit = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

class DES:
    def __init__(self, rounds=16):
        self.rounds = rounds
    
    # permute bits according to a permutation array
    def perm(self, bits, permutation):
        result = 0

        for i in range(len(permutation)):
            result |= ((bits >> (permutation[len(permutation) - 1 - i] - 1)) & 1) << (len(permutation) - 1 - i)
        
        return result
    
    # feistal round function, accepts a 32 bit input and a 48 bit subkey
    def f(self, input, subkey):
        expanded = self.perm(input, fExpansion)
        expanded ^= subkey

        result = 0

        # divide into 8 sboxes and concatenate
        for i in range(8):
            block = (expanded >> (i * 6)) & ((1 << 6) - 1)

            # inner 4 are column, outer 2 are row
            col = (block >> 4) & ((1 << 4) - 1)
            row = ((block >> 5) & 2) | (block & 1)

            result |= sBoxes[i][row][col] << (i * 6)
        
        # permute concatenated result in return
        return self.perm(result, p32)

    # either encrypt or decrypt based on the algorithm specified
    def cipher(self, block, key, algorithm="encrypt"):
        # change 64 bit key into a 56 bit key
        k56 = self.perm(key, p56)

        k56Left = k56 >> 28
        k56Right = k56 & ((1 << 28) - 1)

        subkeys = []

        # generate subkeys and rotate based on the rotation schedule
        for i in range(self.rounds):
            for j in range(shifts[i]):
                k56Left = ((k56Left << 1) & ((1 << 28) - 1)) | (k56Left >> 27)
                k56Right = ((k56Right << 1) & ((1 << 28) - 1)) | (k56Right >> 27)

            k56Joined = (k56Left << 28) | k56Right

            subkey48 = self.perm(k56Joined, p48)

            subkeys.append(subkey48)
    
        in_text = self.perm(block, initPermutation)
        
        left = in_text >> 32
        right = in_text & ((1 << 32) - 1)

        # run the feistel function and swap, with subkey order based on encryption or decryption
        for i in range(self.rounds):
            tmp = right
            right = left ^ self.f(right, subkeys[i] if algorithm == "encrypt" else subkeys[self.rounds - 1 - i])
            left = tmp
        
        out_text = self.perm((right << 32) | left, inverseInit)

        return out_text
    
    # run DES three times with the outer layers sharing a key and the middle layer getting its own key
    # requires 128 bit key to be passed in
    def tripleCipher(self, block, key, algorithm="encrypt"):
        key1 = (key >> 64) & ((1 << 64) - 1)
        key2 = key & ((1 << 64) - 1)

        if algorithm == "encrypt":
            return self.cipher(self.cipher(self.cipher(block, key1, "encrypt"), key2, "decrypt"), key1, "encrypt")
        elif algorithm == "decrypt":
            return self.cipher(self.cipher(self.cipher(block, key1, "decrypt"), key2, "encrypt"), key1, "decrypt")
        else:
            return None
    
    # accepts a list of bytes for the input and the key, runs triple DES on it to encrypt
    def encrypt(self, inBytes, key):
        outBytes = []

        prev = 0

        for i in range(math.ceil(len(inBytes) / 8)):
            arr = list(inBytes[i * 8 : i * 8 + 8])

            # 0 token to delineate end of valid input
            if len(arr) < 8:
                arr.append(0)

            # random padding after
            while len(arr) < 8:
                arr.append(random.randint(0, (1 << 8) - 1))

            out = self.tripleCipher(prev ^ int.from_bytes(arr), int.from_bytes(key), "encrypt")

            outBytes += out.to_bytes(8)

            prev = out

        return bytes(outBytes)
    
    # decrypt using triple DES with the same algorithm as above
    def decrypt(self, inBytes, key):
        outBytes = []

        prev = 0

        for i in range(math.ceil(len(inBytes) / 8)):
            arr = list(inBytes[i * 8 : i * 8 + 8])
            
            out = self.tripleCipher(int.from_bytes(arr), int.from_bytes(key), "decrypt") ^ prev

            outBytes += out.to_bytes(8)

            prev = int.from_bytes(arr)

        return bytes(outBytes)
