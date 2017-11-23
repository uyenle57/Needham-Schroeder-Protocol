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

         .____________________________________________________________________________.
         | @ALICE: Dear Server, this is Alice and I'd like to get Bob's public key.   |
         |____________________________________________________________________________|
    """))

    aliceSendRequestToServer = str(input("Press 's' and enter to request the server for Bob's public key:"))

    if not aliceSendRequestToServer:
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



        # ==================== NEEDHAM SCHROEDER PROTOCOL ==================== #

        # ----------------------- STEP 1 -----------------------
        # Create certificate for Alice and Bob, which contains name : public key
        certificate = {}
        certificate['Alice'] = Alice_PublicKey
        certificate['Bob'] = Bob_PublicKey

        # Convert certificate from Hash Map to string for encryption
        aliceCertificate = "Alice," + str(certificate['Alice'][0]) + "," + str(certificate['Alice'][1])
        bobCertificate = "Bob," + str(certificate['Bob'][0]) + "," + str(certificate['Bob'][1])

        print("certificate ", certificate)

        # Sign Bob certificate (with Server private key) (authentication)
        # using RSA encryption
        bobSignedPublicKey = [ rsaEncryption.encrypt(ord(c), Server_key_d, Server_key_n) for c in bobCertificate ]

        # Send Bob's public key to Alice
        print(" .____________________________________________________________________________________________________________________________.")
        print(" | @SERVER: Dear Alice, this is Bob's public key signed by me: " , bobSignedPublicKey, "|")
        print(" |____________________________________________________________________________________________________________________________|")


        # ----------------------- STEP 2 -----------------------
        # Alice decrypts Bob's certificate (with Server public key) to get Bob's public key
        rsaDecryption = RsaDecryption()

        decryptedBobCertificate = "".join(str(x) for x in [ chr(rsaDecryption.decrypt(c, Server_key_e, Server_key_n)) for c in bobSignedPublicKey ])
        print("decryptedBobCertificate:", decryptedBobCertificate)
        decryptedBobCertificate = decryptedBobCertificate.split(',')

        print("Decrypted Bob certificate: ", decryptedBobCertificate)

        # TO DO: Verify

        # ----------------------- STEP 3 -----------------------
        # Generate and encrypt Alice's nonce (with Bob public key)
        aliceNonce = generateNonce()
        print("Alice nonce: ", int(aliceNonce))

        aliceNonceEncryptedWithBobPublicKey = rsaEncryption.encrypt(int(aliceNonce), int(decryptedBobCertificate[1]), int(decryptedBobCertificate[2]))

        print(" .___________________________________________________________________________________.")
        print(" | @ALICE: Dear Bob, this is Alice and I've sent you a nonce only you can read." , aliceNonceEncryptedWithBobPublicKey, "|")
        print(" |___________________________________________________________________________________|")

        aliceSendNonceToBob = str(input("Press 's' and enter to send your nonce to Bob:"))

        if not aliceSendNonceToBob:
            print("ERROR: Nonce not sent. Please try again.")
            sys.exit(1)
        else:

            # ----------------------- STEP 4 -----------------------
            print (textwrap.dedent("""
             .________________________________________________________________________.
             | @BOB: Dear Server, this is Bob and I'd like to get Alice's public key. |
             |________________________________________________________________________|
            """))

            # ----------------------- STEP 5 -----------------------
            # Sign Alice certificate (with Server private key) (authentication)
            aliceSignedPublicKey = [ rsaEncryption.encrypt(ord(c), Server_key_d, Server_key_n) for c in aliceCertificate ]
            print(" .____________________________________________________________________________________________________________________________.")
            print(" | @SERVER: Dear Bob, here's Alice's public key signed by me: " , aliceSignedPublicKey, "|")
            print(" |____________________________________________________________________________________________________________________________|")

            # ----------------------- STEP 6 -----------------------
            # Bob decrypts Alice's certificate (with Server public key) to get Alice's public key
            decryptedAliceCertificate = "".join(str(x) for x in [ chr(rsaDecryption.decrypt(c, Server_key_e, Server_key_n)) for c in aliceSignedPublicKey ])
            decryptedAliceCertificate = decryptedAliceCertificate.split(',')

            # Bob decrypts Alice's nonce (with his private key)
            decryptedAliceNonce = rsaDecryption.decrypt(aliceNonceEncryptedWithBobPublicKey, Bob_key_d, Bob_key_n)

            print("Decrypted Alice nonce: ", decryptedAliceNonce)

            #Verify decrypted Alice's nonce is correct
            if decryptedAliceNonce == aliceNonce:
                print("Verified decrypted Alice nonce is correct.\n")
            else:
                print("ERROR: Decrypted Alice nonce is not correct. Please try again.")
                sys.exit(1)


            # Generate Bob nonce
            bobNonce = generateNonce()
            print("Bob nonce: ", int(bobNonce))

            # Add Alice's nonce with Bob's nonce and encrypt it (with Alice public key)
            aliceNonceWithBobsNonce = str(decryptedAliceNonce) + "," + str(bobNonce)
            print("aliceNonceWithBobsNonce: ", aliceNonceWithBobsNonce)

            bobNonceEncryptedWithAlicePublicKey = [ rsaEncryption.encrypt(ord(c), int(decryptedAliceCertificate[1]), int(decryptedAliceCertificate[1])) for c in aliceNonceWithBobsNonce ]

            print(" .___________________________________________________________________________________________.")
            print(" | @BOB: Dear Alice, here's my nonce and yours, proving I decrypted it: " , bobNonceEncryptedWithAlicePublicKey, "|")
            print(" |___________________________________________________________________________________________|")

            # ----------------------- STEP 7 -----------------------

            # TO DO

            # Alice decrypts Bob's nonce (with her private key)
            decryptedBobNonce = "".join(str(x) for x in [ chr(rsaDecryption.decrypt(c, Alice_key_d, Alice_key_n)) for c in bobNonceEncryptedWithAlicePublicKey ])
            decryptedBobNonce = decryptedBobNonce.split(',')

            print(" .__________________________________________________________________________.")
            print(" | @ALICE: Dear Bob, here's your nonce proving I decrypted it: " , decryptedBobNonce, "|")
            print(" |__________________________________________________________________________|")

            # Validate decrypted Bob's nonce matches
            # if so successfully exits
            if decryptedBobNonce == bobNonce:
                print("Verified decrypted Bob nonce is correct. Protocol transmission successful.\n")
                sys.exit(0)
            else:
                print("ERROR: Decrypted Bob nonce is not correct. Please try again.")
                sys.exit(1)


        # Delete nonces from working memory as nonces are used only once
        del aliceNonce
        del decryptedAliceNonce
        del bobNonce
        del decryptedBobNonce

menu()
