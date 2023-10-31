from Crypto.Util.number import *
from secret import flag

NBITS = 1337

def keygen():
    p = getPrime(NBITS)
    q = p + 2
    while not isPrime(q):
        q += 2

    n = p**2 * q
    g = getRandomRange(2, n-1)
    assert pow(g, p-1, p**2) != 1
    return (g, n), p

(g, n), pk = keygen()
print(f"g = {g}")
print(f"n = {n}")

m = pow(g, bytes_to_long(flag), n)
print(f"m = {m}")
