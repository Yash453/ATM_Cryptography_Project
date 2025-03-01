import math

k = [
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

class SHA256:
    def __init__(self):
        pass

    # rotate bytes left assuming 32 bit integers
    def leftRotate(self, x, n):
        for j in range(n):
            x = ((x << 1) & ((1 << 32) - 1)) | (x >> 31)

        return x
    
    # rotate bytes right assuming 32 bit integers
    def rightRotate(self, x, n):
        for j in range(n):
            x = ((x & 1) << 31) | (x >> 1)
        
        return x

    # add mod the max value of 32 bit integers
    def add(self, a, b):
        return (a + b) % (1 << 32)
    
    def binaryNot(self, x):
        for i in range(32):
            x ^= (1 << i)
        
        return x
    
    # perform the SHA256 algorithm for the 512 bit chunk
    def chunkOperation(self, hArr, chunk):
        w = [0 for i in range(0, 64)]

        # populate first 16 32 bit integer words with the chunk
        for i in range(0, 16):
            for j in range(0, 4):
                w[i] |= chunk[i * 4 + 3 - j] << (8 * j)

        # iteratively calculate 32 bit words using right rotations with previous words
        for i in range(16, 64):
            s0 = self.rightRotate(w[i - 15], 7) ^ self.rightRotate(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = self.rightRotate(w[i - 2], 17) ^ self.rightRotate(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = self.add(self.add(self.add(w[i - 16], s0), w[i - 7]), s1)

        a, b, c, d, e, f, g, h = hArr

        # 64 rounds of right rotations, xoring, and bitwise operations
        for i in range(0, 63):
            s1 = self.rightRotate(e, 6) ^ self.rightRotate(e, 11) ^ self.rightRotate(e, 25)
            ch = (e & f) ^ (self.binaryNot(e) & g)
            temp1 = self.add(self.add(self.add(self.add(h, s1), ch), k[i]), w[i])
            s0 = self.rightRotate(a, 2) ^ self.rightRotate(a, 13) ^ self.rightRotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = s0 + maj
    
            # update register values
            h = g
            g = f
            f = e
            e = d + temp1
            d = c
            c = b
            b = a
            a = temp1 + temp2
    
        return [a, b, c, d, e, f, g, h]

    # run the hash algorithm on an array of bytes of arbitrary length
    def run(self, byteArr):
        hArr = [ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 ]

        L = len(byteArr)

        byteArr = list(byteArr)

        byteArr.append(0b1000000)

        # ensure that it's equal to a multiple of 512 minus 64
        while len(byteArr) % 64 != 56:
            byteArr.append(0)
        
        byteArr += L.to_bytes(8)
        
        # perform the chunk operation on all 512 bit chunks
        for i in range(math.floor(len(byteArr) / 64)):
            arr = self.chunkOperation(hArr, byteArr[i * 64 : i * 64 + 64])

            for j in range(len(arr)):
                hArr[j] = self.add(hArr[j], arr[j])

        # separate 32 bit register values into bytes
        result = []
        for val in hArr:
            result += val.to_bytes(4)
        
        return bytes(result)