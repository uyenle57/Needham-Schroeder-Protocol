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
    """))

    # GENERATE PULBIC KEY PAIR FOR ALICE, BOB AND SERVER #

    # Generate Alice public key pair
    alicePublicKeyPair = generatePublicKeyPair()

    Alice_PublicKey = alicePublicKeyPair[0]
    Alice_PrivateKey = alicePublicKeyPair[1]
    Alice_key_e = Alice_PublicKey[0]
    Alice_key_n = Alice_PublicKey[1]
    Alice_key_d = Alice_PrivateKey[0]

    # Generate Bob's public key pair
    bobPublicKeyPair = generatePublicKeyPair()

    Bob_PublicKey = bobPublicKeyPair[0]
    Bob_PrivateKey = bobPublicKeyPair[1]
    Bob_key_e = Bob_PublicKey[0]
    Bob_key_n = Bob_PublicKey[1]
    Bob_key_d = Bob_PrivateKey[0]

    # Generate Server's public key pair
    serverPublicKeyPair = generatePublicKeyPair()

    server_PublicKey = serverPublicKeyPair[0]
    server_PrivateKey = serverPublicKeyPair[1]
    Server_key_e = server_PublicKey[0]
    Server_key_n = server_PublicKey[1]
    Server_key_d = server_PrivateKey[0]

    certificate = {}
    certificate['Alice'] = Alice_PublicKey
    certificate['Bob'] = Bob_PublicKey

    print("Server: Key Distribution Center initialised with Alice's and Bob's certificates: ", certificate)
    print("Server: Key Distribution Center public key: ", server_PublicKey, "\n")

    aliceSendRequestToServer = str(input("Press 's' to start protocol:"))

    if not aliceSendRequestToServer:
        print("ERROR: Protocol not started. Please try again.")
        sys.exit(1)
    else:

        # ----------------------- STEP 1 -----------------------
        # Create certificate for Alice and Bob, which contains { name : public key }
        certificate = {}
        certificate['Alice'] = Alice_PublicKey
        certificate['Bob'] = Bob_PublicKey

        print("S: Certificate Store: ", certificate)

        # Convert certificate from Hash Map to string for encryption
        aliceCertificate = "Alice," + str(certificate['Alice'][0]) + "," + str(certificate['Alice'][1])
        bobCertificate = "Bob," + str(certificate['Bob'][0]) + "," + str(certificate['Bob'][1])

        print("\n@ALICE: Dear Server, this is Alice and I'd like to get Bob's public key.")

        # Sign Bob certificate (with Server private key) (authentication)
        rsaEncryption = RsaEncryption()
        bobSignedPublicKey = [ rsaEncryption.encrypt(ord(c), Server_key_d, Server_key_n) for c in bobCertificate ]

        # Send Bob's public key to Alice
        print("@SERVER: Dear Alice, this is Bob's public key signed by me: " , bobSignedPublicKey)


        # ----------------------- STEP 2 -----------------------
        # Alice decrypts Bob's certificate (with Server public key) to get Bob's public key
        rsaDecryption = RsaDecryption()

        decryptedBobCertificate = "".join(str(x) for x in [ chr(rsaDecryption.decrypt(c, Server_key_e, Server_key_n)) for c in bobSignedPublicKey ])

        decryptedBobCertificate = decryptedBobCertificate.split(',')
        print("Alice decrypts Bob's certificate: ", decryptedBobCertificate)

        # ----------------------- STEP 3 -----------------------
        # Generate and encrypt Alice's nonce (with Bob public key)
        aliceNonce = generateNonce()
        aliceNonceEncryptedWithBobPublicKey = rsaEncryption.encrypt(int(aliceNonce), int(decryptedBobCertificate[1]), int(decryptedBobCertificate[2]))

        # and send it to Bob
        print("\n@ALICE: Dear Bob, this is Alice and I've sent you a nonce only you can read.")
        print("Alice's nonce plaintext: ", aliceNonce)
        print("Alice's nonce encrypted with Bob's public key: ", aliceNonceEncryptedWithBobPublicKey)

        aliceSendNonceToBob = str(input("\nPress 's' to send your nonce to Bob:"))

        if not aliceSendNonceToBob:
            print("ERROR: Nonce not sent. Please try again.")
            sys.exit(1)
        else:

            # ----------------------- STEP 4 -----------------------
            print ("\n@BOB: Dear Server, this is Bob and I'd like to get Alice's public key.")

            # ----------------------- STEP 5 -----------------------
            # Sign Alice certificate (with Server private key) (authentication) and send it to Bob
            aliceSignedPublicKey = [ rsaEncryption.encrypt(ord(c), Server_key_d, Server_key_n) for c in aliceCertificate ]
            print("\n@SERVER: Dear Bob, here's Alice's public key signed by me: " , aliceSignedPublicKey)

            # ----------------------- STEP 6 -----------------------
            # Bob decrypts Alice's certificate (with Server public key) to get Alice's public key
            decryptedAliceCertificate = "".join(str(x) for x in [ chr(rsaDecryption.decrypt(c, Server_key_e, Server_key_n)) for c in aliceSignedPublicKey ])
            decryptedAliceCertificate = decryptedAliceCertificate.split(',')
            print("Bob decrypts Alice's certificate: ", decryptedAliceCertificate)

            # Bob decrypts Alice's nonce (with his private key)
            decryptedAliceNonce = rsaDecryption.decrypt(aliceNonceEncryptedWithBobPublicKey, Bob_key_d, Bob_key_n)

            print("Bob decrypts Alice's nonce: ", decryptedAliceNonce)

            # Generate Bob nonce
            bobNonce = generateNonce()

            # Add Alice's nonce with Bob's nonce and encrypt it (with Alice public key)
            aliceNonceWithBobsNonce = str(decryptedAliceNonce) + "," + str(bobNonce)
            print("Alice's nonce with Bob's nonce: ", aliceNonceWithBobsNonce)

            bobNonceEncryptedWithAlicePublicKey = [ rsaEncryption.encrypt(ord(c), int(decryptedAliceCertificate[1]), int(decryptedAliceCertificate[2])) for c in aliceNonceWithBobsNonce ]

            print("\n@BOB: Dear Alice, here's my nonce and yours, proving I decrypted it: " , bobNonceEncryptedWithAlicePublicKey)


            # ----------------------- STEP 7 -----------------------
            # Alice decrypts Bob's nonce (with her private key)
            decryptedAliceNonceFromBob = "".join(str(x) for x in [ chr(rsaDecryption.decrypt(c, Alice_key_d, Alice_key_n)) for c in bobNonceEncryptedWithAlicePublicKey ])
            decryptedAliceNonceFromBob = decryptedAliceNonceFromBob.split(",")

            print("\nDecrypted Alive Nonce From Bob: ", decryptedAliceNonceFromBob)

            # Verify
            if decryptedAliceNonceFromBob[0] == str(aliceNonce):
                print("\nAlice verified decrypted Alice's nonce from Bob is correct.\n")
            else:
                print("ERROR: Decrypted Alice's nonce from Bob is not correct. Please try again.")
                sys.exit(1)


            # Alice encrypts Bob's nonce (with Bob's public key) and send it back to him
            encryptBobNonceToSendBack = [ rsaEncryption.encrypt(ord(c), Bob_key_e, Bob_key_n) for c in decryptedAliceNonceFromBob[1] ]

            print("@ALICE: Dear Bob, here's your nonce proving I decrypted it: " , encryptBobNonceToSendBack)

            finalBobNonceFromAlice = "".join(str(x) for x in [ chr(rsaDecryption.decrypt(c, Bob_key_d, Bob_key_n)) for c in encryptBobNonceToSendBack ])

            print("\nBob decrypts nonce from Alice: ", finalBobNonceFromAlice)

            # Verify
            if finalBobNonceFromAlice == str(bobNonce):
                print("Bob verifies Bob's nonce from Alice is correct.")
            else:
                print("ERROR: Decrypted Bob's nonce from Alice is not correct. Please try again.")
                sys.exit(1)

            # Delete nonces from working memory as nonces are used only once
            del aliceNonce, bobNonce

            print("\nTRANSMISSION SUCCESSFUL. CONNECTION CLOSED.\n")
            sys.exit(0)

menu()
