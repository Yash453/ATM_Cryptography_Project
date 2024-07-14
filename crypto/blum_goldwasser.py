import sympy as sp
import math
import random


# Converting an integer to a binary string
def int_to_binary(number):
    return bin(number)[2:]


def generate_random_quadratic_residue(n):
    # Select a random element in Z*n
    r = random.randrange(1, n)

    # Calculate the quadratic residue
    x0 = pow(r, 2, n)

    return x0


def extended_gcd(a, b):
    """Extended Euclidean Algorithm implementation."""
    if b == 0:
        return 1, 0, a
    else:
        x, y, gcd = extended_gcd(b, a % b)
        return y, x - (a // b) * y, gcd


def generate_blum_primes(bit_size):
    p = sp.nextprime(sp.randprime(2**(bit_size-1), 2**bit_size))
    while p % 4 != 3:
        p = sp.nextprime(p)

    q = sp.nextprime(sp.randprime(2**(bit_size-1), 2**bit_size))
    while q % 4 != 3 or q == p:
        q = sp.nextprime(q)

    return p, q


def keygen():
    p, q = generate_blum_primes(128)
    n = p * q
    a, b, _ = extended_gcd(p, q)

    public_key = n
    private_key = ((p, q), a, b)

    return public_key, private_key


def encrypt(message_bits, n, x0):
    k = math.floor(math.log(n, 2))
    h = math.floor(math.log(k, 2))

    m_blocks = [message_bits[i:i+h] for i in range(0, len(message_bits), h)]

    xi = x0
    ciphertext = []

    # Encryption process
    for m in m_blocks:
        xi = pow(xi, 2, n)

        pi = format(xi, '0' + str(k) + 'b')[-h:]

        ci = format(int(pi, 2) ^ int(m, 2), '0' + str(h) + 'b')

        # Append ci to the ciphertext
        ciphertext.append(ci)

    # Compute xt+1
    x_next = pow(xi, 2, n)

    ciphertext.append(format(x_next, '0' + str(k) + 'b'))

    return ' '.join(ciphertext)


def decrypt(ciphertext, private_key, public_key):
    # Unpack the private key and ciphertext
    (p, q), a, b = private_key
    c_blocks = ciphertext.split()[:-1]
    xt_plus_1 = int(ciphertext.split()[-1], 2)  # This is xt+1

    # Calculate k and h
    k = math.floor(math.log(public_key, 2))
    h = math.floor(math.log(k, 2))

    # Compute d1 and d2 using the formulas provided
    t = len(c_blocks)
    d1 = pow((p + 1) // 4, t+1, p - 1)
    d2 = pow((q + 1) // 4, t+1, q - 1)

    u = pow(xt_plus_1, d1, p)
    v = pow(xt_plus_1, d2, q)

    x0 = (v * p * a + u * q * b) % public_key

    # Decrypt the message blocks
    decrypted_message = ""
    xi = x0
    for ci in c_blocks:
        # Compute xi = xi^2 mod n
        xi = pow(xi, 2, public_key)

        pi = format(xi, '0' + str(k) + 'b')[-h:]

        mi = format(int(pi, 2) ^ int(ci, 2), '0' + str(h) + 'b')

        decrypted_message += mi

    return decrypted_message
