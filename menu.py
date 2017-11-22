# -*- coding: utf-8 -*-#

import textwrap
from RsaEncryption import *
from RsaDecryption import *

def generatePublicKeyPair():
    """Return public and private key tuple"""

    rsaEncryption = RsaEncryption()

    key_p = rsaEncryption.generateRandPrime()
    key_q = rsaEncryption.generateRandPrime()

    while key_q == key_p:
        key_q = rsaEncryption.generateRandPrime()

    if rsaEncryption.isPrime(key_p):
        pass
    else:
        print("ERROR: p is not prime. Please try again.")
        sys.exit(1)

    if rsaEncryption.isPrime(key_q):
        pass
    else:
        print("ERROR: q is not prime. Please try again.")
        sys.exit(1)

    # Calculate key n
    key_n = rsaEncryption.calculateN(key_p, key_q)

    # Calculate phi(n)
    phiN = rsaEncryption.totient(key_p, key_q)

    # Generate key e
    coPrimeList = []

    for i in range(1, phiN):
        if(rsaEncryption.isCoPrime([i, phiN])):
            coPrimeList.append(i)

    key_e = coPrimeList[random.randint(coPrimeList[0], len(coPrimeList)-1)]

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


def menu():

    print (textwrap.dedent("""
        ==========================================================================
        Computer Security Coursework
        Part 2: Needham-Schroeder Protocol
        by Uyen Le (tle004)
        ==========================================================================

        ALICE: Dear Server, this is Alice and I'd like to get Bob's public key.
    """))

    sendRequest = str(input("Press 's' and enter to request the server for Bob's public key:"))

    if not sendRequest:
        print("ERROR: Request not sent. Please try again.")
        sys.exit(1)

    else:

        # Generate public and private key for Alice, Bob and the server
        Alice_PublicKeyPair = generatePublicKeyPair()
        # Bob_PublicKeyPair = generatePublicKeyPair()
        # Server_PublicKeyPair = generatePublicKeyPair()

        print("\nSERVER: Dear Alice, this is Bob's public key:" , Alice_PublicKeyPair)


menu()
