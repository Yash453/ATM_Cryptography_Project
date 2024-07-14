import math
from crypto.SHA256 import SHA256

class HMAC:
    def __init__(self):
        pass

    def run(self, key, message):
        h = SHA256()

        # pad key to be 512 bits
        blockKey = int.from_bytes(list(key) + [0 for i in range(64 - len(key))])

        # generate repeating strings of bits for outer and inner xoring

        outerRepeating = 0

        for i in range(64):
            outerRepeating |= (0x5c << (i * 8))
        
        innerRepeating = 0

        for i in range(64):
            innerRepeating |= (0x36 << (i * 8))
        
        # xor both 512 bit values with 512 bit key
        outerPad = blockKey ^ outerRepeating
        innerPad = blockKey ^ innerRepeating

        # return HMAC through concatenated inner values
        return h.run(list(outerPad.to_bytes(64)) + list(h.run(list(innerPad.to_bytes(64)) + list(message))))
