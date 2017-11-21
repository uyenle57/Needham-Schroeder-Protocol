# -*- coding: utf-8 -*-#

import textwrap
from RsaEncryption import *
from RsaDecryption import *


def menu():

    print (textwrap.dedent("""
        ==========================================================================
        Computer Security Coursework
        Part 2: Key Exchange Protocol
        by Uyen Le (tle004)
        ==========================================================================

        Hello Alice! Now you want to talk to Bob through a trusted server.

        First, you need Bob's public key.
    """))

    sendReq = str(input("Press 's' and enter to request the server for Bob's public key:"))

    if not sendReq:
        print("ERROR: Request not sent. Please try again.")
        sys.exit(1)

    else:
        print("\n################ GENERATE PUBLIC AND PRIVATE KEYS FOR BOB, ALICE AND SERVER ###############")

        rsaEncryption = RsaEncryption()

        print("\n## Generating Bob's public key pair...\n##")
        bob_key_p = rsaEncryption.generateRandPrime()
        bob_key_q = rsaEncryption.generateRandPrime()

        while bob_key_q == bob_key_p:
            bob_key_q = rsaEncryption.generateRandPrime()

        if rsaEncryption.isPrime(bob_key_p):
            print("Verified p is prime!")
        else:
            print("ERROR: p is not prime. Please try again.")
            sys.exit(1)

        if rsaEncryption.isPrime(bob_key_q):
            print("Verified q is prime!")
        else:
            print("ERROR: q is not prime. Please try again.")
            sys.exit(1)

        # Calculate key n
        bob_key_n = rsaEncryption.calculateN(bob_key_p, bob_key_q)
        # print("\nn is:", str(bob_key_p), "*", str(bob_key_q), "=", bob_key_n)

        # Calculate phi(n)
        bob_phiN = rsaEncryption.totient(bob_key_p, bob_key_q)
        # print("phi(n) is: (", str(bob_key_p), "-1) * (", str(bob_key_q), "-1) =", bob_phiN)

        # Generate key e
        # by adding all coprime numbers to phi(n) to a list, then randomly pick a number in that list
        coPrimeList = []

        for i in range(1, bob_phiN):
            if(rsaEncryption.isCoPrime([i, bob_phiN])):
                coPrimeList.append(i)

        bob_key_e = coPrimeList[random.randint(coPrimeList[0], len(coPrimeList)-1)]
        print("\ne is: ", bob_key_e)

        # Verify e is coprime to phiN
        if gcd(bob_key_e, bob_phiN) == 1:
            print("Verified e is coprime!")
        else:
            print("ERROR: E is not coprime. Please try again.")
            sys.exit(1)

        # Generate key d using Extended Euclidean algorithm
        _, bob_key_d, _ = rsaEncryption.egcd(bob_key_e, bob_phiN)

        # ensure key e and d are distinct
        while bob_key_e == bob_key_d:
            _, bob_key_d, _ = rsaEncryption.egcd(bob_key_e, bob_phiN)

        # ensure key d is positive
        if bob_key_d < 0:
            bob_key_d = bob_key_d % bob_phiN

        print("\nd is: ", bob_key_d)

        # verify d is coprime to phiN
        if gcd(bob_key_d,bob_phiN) == 1:
            print("Verified d is coprime!")
        else:
            print("ERROR: D is not coprime. Please try again.")
            sys.exit(1)

        print("Bob's public key is:" , (bob_key_e, bob_key_n))
        print("Bob's private key is:" , (bob_key_d, bob_key_n))
menu()
