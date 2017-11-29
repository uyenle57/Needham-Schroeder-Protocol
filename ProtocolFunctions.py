# -*- coding: utf-8 -*-#

from RsaEncryption import *
from RsaDecryption import *


def generate_public_keypair():
    """Return public and private key tuple"""

    rsaEncryption = RsaEncryption()

    key_p = rsaEncryption.generate_randPrime()
    key_q = rsaEncryption.generate_randPrime()

    while key_q == key_p:
        key_q = rsaEncryption.generate_randPrime()

    if rsaEncryption.is_prime(key_p):
        pass
    else:
        print("ERROR: p is not prime. Please try again.")
        sys.exit(1)

    if rsaEncryption.is_prime(key_q):
        pass
    else:
        print("ERROR: q is not prime. Please try again.")
        sys.exit(1)

    # Calculate key n
    key_n = rsaEncryption.calculate_n(key_p, key_q)

    # Calculate phi(n)
    phiN = rsaEncryption.totient(key_p, key_q)

    # Generate key e
    coPrimeList = []

    for i in range(2, phiN):
        if(rsaEncryption.is_coprime([i, phiN])):
            coPrimeList.append(i)

    key_e = coPrimeList[random.randint(0, len(coPrimeList) - 1)]

    # Verify e is coprime to phiN
    if gcd(key_e, phiN) == 1:
        pass
    else:
        print("ERROR: E is not coprime. Please try again.")
        sys.exit(1)

    # Generate key d using Extended Euclidean algorithm
    _, key_d, _ = rsaEncryption.egcd(key_e, phiN)

    # ensure key e and d are distinct
    while key_e == key_d:
        key_e = coPrimeList[random.randint(0, len(coPrimeList) - 1)]
        _, key_d, _ = rsaEncryption.egcd(key_e, phiN)

    # ensure key d is positive
    if key_d < 0:
        key_d = key_d % phiN

    # verify d is coprime to phiN
    if gcd(key_d,phiN) == 1:
        pass
    else:
        print("ERROR: D is not coprime. Please try again.")
        sys.exit(1)

    publicKey = (key_e, key_n)
    privateKey = (key_d, key_n)

    return (publicKey, privateKey)


def generateNonce(length=2):
    """ Returns a 2 bits pseudorandom number"""

    # https://github.com/joestump/python-oauth2/blob/81326a07d1936838d844690b468660452aafdea9/oauth2/__init__.py#L165

    nonce = int(''.join([str(random.randint(0, 9)) for i in range(length)]))
    return nonce
