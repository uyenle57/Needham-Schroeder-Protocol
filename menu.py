# -*- coding: utf-8 -*-#

import textwrap
from ProtocolFunctions import *


def menu():

    print (textwrap.dedent("""
        ==========================================================================
        Computer Security Coursework
        Part 2: Needham-Schroeder Protocol
        by Uyen Le (tle004)
        ==========================================================================

        ALICE: Dear Server, this is Alice and I'd like to get Bob's public key.
    """))

    sendAliceRequest = str(input("Press 's' and enter to request the server for Bob's public key:"))

    if not sendAliceRequest:
        print("ERROR: Request not sent. Please try again.")
        sys.exit(1)

    else:

        ######### GENERATE PULBIC KEY PAIR FOR ALICE, BOB AND SERVER #########

        # ------------------------- Generate Alice Publickey pair -------------------------
        rsaEncryption = RsaEncryption()

        Alice_key_p = rsaEncryption.generateRandPrime()
        Alice_key_q = rsaEncryption.generateRandPrime()

        while Alice_key_q == Alice_key_p:
            Alice_key_q = rsaEncryption.generateRandPrime()

        if rsaEncryption.isPrime(Alice_key_p):
            pass
        else:
            print("ERROR: p is not prime. Please try again.")
            sys.exit(1)

        if rsaEncryption.isPrime(Alice_key_q):
            pass
        else:
            print("ERROR: q is not prime. Please try again.")
            sys.exit(1)

        # Calculate key n
        Alice_key_n = rsaEncryption.calculateN(Alice_key_p, Alice_key_q)

        # Calculate phi(n)
        Alice_phiN = rsaEncryption.totient(Alice_key_p, Alice_key_q)

        # Generate key e
        coPrimeList = []

        for i in range(1, Alice_phiN):
            if(rsaEncryption.isCoPrime([i, Alice_phiN])):
                coPrimeList.append(i)

        Alice_key_e = coPrimeList[random.randint(coPrimeList[0], len(coPrimeList)-1)]

        # Verify e is coprime to phiN
        if gcd(Alice_key_e, Alice_phiN) == 1:
            pass
        else:
            print("ERROR: E is not coprime. Please try again.")
            sys.exit(1)

        # Generate key d using Extended Euclidean algorithm
        _, Alice_key_d, _ = rsaEncryption.egcd(Alice_key_e, Alice_phiN)

        # ensure key e and d are distinct
        while Alice_key_e == Alice_key_d:
            _, Alice_key_d, _ = rsaEncryption.egcd(Alice_key_e, Alice_phiN)

        # ensure key d is positive
        if Alice_key_d < 0:
            Alice_key_d = Alice_key_d % Alice_phiN

        # verify d is coprime to phiN
        if gcd(Alice_key_d,Alice_phiN) == 1:
            pass
        else:
            print("ERROR: D is not coprime. Please try again.")
            sys.exit(1)

        Alice_PublicKey = (Alice_key_e, Alice_key_n)
        Alice_PrivateKey = (Alice_key_d, Alice_key_n)



        # ------------------------- Generate Bob's publickey pair -------------------------
        Bob_key_p = rsaEncryption.generateRandPrime()
        Bob_key_q = rsaEncryption.generateRandPrime()

        while Bob_key_q == Bob_key_p:
            Bob_key_q = rsaEncryption.generateRandPrime()

        if rsaEncryption.isPrime(Bob_key_p):
            pass
        else:
            print("ERROR: p is not prime. Please try again.")
            sys.exit(1)

        if rsaEncryption.isPrime(Bob_key_q):
            pass
        else:
            print("ERROR: q is not prime. Please try again.")
            sys.exit(1)

        # Calculate key n
        Bob_key_n = rsaEncryption.calculateN(Bob_key_p, Bob_key_q)

        # Calculate phi(n)
        Bob_phiN = rsaEncryption.totient(Bob_key_p, Bob_key_q)

        # Generate key e
        coPrimeList = []

        for i in range(1, Bob_phiN):
            if(rsaEncryption.isCoPrime([i, Bob_phiN])):
                coPrimeList.append(i)

        Bob_key_e = coPrimeList[random.randint(coPrimeList[0], len(coPrimeList)-1)]

        # Verify e is coprime to phiN
        if gcd(Bob_key_e, Bob_phiN) == 1:
            pass
        else:
            print("ERROR: E is not coprime. Please try again.")
            sys.exit(1)

        # Generate key d using Extended Euclidean algorithm
        _, Bob_key_d, _ = rsaEncryption.egcd(Bob_key_e, Bob_phiN)

        # ensure key e and d are distinct
        while Bob_key_e == Bob_key_d:
            _, Bob_key_d, _ = rsaEncryption.egcd(Bob_key_e, Bob_phiN)

        # ensure key d is positive
        if Bob_key_d < 0:
            Bob_key_d = Bob_key_d % Bob_phiN

        # verify d is coprime to phiN
        if gcd(Bob_key_d,Bob_phiN) == 1:
            pass
        else:
            print("ERROR: D is not coprime. Please try again.")
            sys.exit(1)

        Bob_PublicKey = (Bob_key_e, Bob_key_n)
        Bob_PrivateKey = (Bob_key_d, Bob_key_n)



        # ------------------------- Generate Server's publickey pair -------------------------
        Server_key_p = rsaEncryption.generateRandPrime()
        Server_key_q = rsaEncryption.generateRandPrime()

        while Server_key_q == Server_key_p:
            Server_key_q = rsaEncryption.generateRandPrime()

        if rsaEncryption.isPrime(Server_key_p):
            pass
        else:
            print("ERROR: p is not prime. Please try again.")
            sys.exit(1)

        if rsaEncryption.isPrime(Server_key_q):
            pass
        else:
            print("ERROR: q is not prime. Please try again.")
            sys.exit(1)

        # Calculate key n
        Server_key_n = rsaEncryption.calculateN(Server_key_p, Server_key_q)

        # Calculate phi(n)
        Server_phiN = rsaEncryption.totient(Server_key_p, Server_key_q)

        # Generate key e
        coPrimeList = []

        for i in range(1, Server_phiN):
            if(rsaEncryption.isCoPrime([i, Bob_phiN])):
                coPrimeList.append(i)

        Server_key_e = coPrimeList[random.randint(coPrimeList[0], len(coPrimeList)-1)]

        # Verify e is coprime to phiN
        if gcd(Server_key_e, Server_phiN) == 1:
            pass
        else:
            print("ERROR: E is not coprime. Please try again.")
            sys.exit(1)

        # Generate key d using Extended Euclidean algorithm
        _, Server_key_d, _ = rsaEncryption.egcd(Server_key_e, Server_phiN)

        # ensure key e and d are distinct
        while Server_key_e == Server_key_d:
            _, Server_key_d, _ = rsaEncryption.egcd(Server_key_e, Server_phiN)

        # ensure key d is positive
        if Server_key_d < 0:
            Server_key_d = Server_key_d % Server_phiN

        # verify d is coprime to phiN
        if gcd(Server_key_d,Server_phiN) == 1:
            pass
        else:
            print("ERROR: D is not coprime. Please try again.")
            sys.exit(1)

        Server_PublicKey = (Server_key_e, Server_key_n)
        Server_PrivateKey = (Server_key_d, Server_key_n)



        ######### SIGN ALICE AND BOB CERTIFICATES #########

        # Certificate has identity (name) and key (public key)
        certificate = {}
        certificate['Alice'] = Alice_PublicKey
        certificate['Bob'] = Bob_PublicKey

        print(certificate)

        # TO DO
        # Sign certificate using RSA encryption (authentication)
        # signed_Alice_PublicKey = pow(certificate['Alice'], Server_PrivateKey, Server_phiN)
        # signed_Bob_PublicKey = pow(certificate['Bob'], Server_PrivateKey, Server_phiN)

        print("signed_Alice_PublicKey", signed_Alice_PublicKey)
        print("signed_Bob_PublicKey", signed_Bob_PublicKey)

        # Send Bob's public key to Alice
        # print("\nSERVER: Dear Alice, this is Bob's public key: " , signed_Bob_PublicKey)



        ######### ALICE AND BOB COMMUNICATIONS #########

        # Generate Alice's nonce
        Alice_Nonce = generateNonce()

        # TO DO
        # Encrypt Alice's nonce
        # encrypted_Alice_Nonce = pow()

        # print("\nAlice\'s nonce is: ", encrypted_Alice_Nonce)

        print("\nALICE: Dear Bob, this is Alice and I've sent you a nonce only you can read.")
        sendBobNonce = str(input("Press 's' and enter to send your nonce to Bob:"))

        if not sendBobNonce:
            print("ERROR: Nonce not sent. Please try again.")
            sys.exit(1)
        else:

            pass
            print("\nBOB: Dear Server, this is Bob and I'd like to get Alice's public key")

            sendBobRequest = str(input("\nPress 's' and enter to request the server for Alice's public key"))

            if not sendBobRequest:
                print("ERROR: Request not sent. Please try again.")
                sys.exit(1)
            else:

                print("\nSERVER: Dear Bob, here's Alice's public key signed by me", signed_Alice_PublicKey)

                Bob_Nonce = generateNonce()

                # TO DO
                # Encrypt Bob's nonce
                # Decrypt encrypted_Alice_Nonce with signed_Alice_PublicKey
                print("\nBOB: Dear Alice, here's my nonce and yours, proving I decrypted it")

                # TO DO
                # Validate decrypted_Alice_Nonce matches
                # Decrypt encrypted_Bob_Nonce with signed_Bob_PublicKey
                print("\nALICE: Dear Bob, here's your nonce proving I decrypted it")

                # TO DO
                # Validate decrypted_Bob_Nonce matches
                # If so, program successfully completes.

        # TO DO
        # Delete nonces from working memory after use
        # del Alice_Nonce, encrypted_Alice_Nonce
        # del Bob_Nonce, encrypted_Bob_Nonce
menu()
