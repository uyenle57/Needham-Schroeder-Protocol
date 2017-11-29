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

    # GENERATE PUBLIC KEY PAIR FOR ALICE, BOB AND SERVER

    # Generate Alice public key pair
    alicePublicKeyPair = generate_public_keypair()

    alicePublicKey = alicePublicKeyPair[0]
    alicePrivateKey = alicePublicKeyPair[1]
    aliceKeyE = alicePublicKey[0]
    aliceKeyN = alicePublicKey[1]
    aliceKeyD = alicePrivateKey[0]

    # Generate Bob's public key pair
    bobPublicKeyPair = generate_public_keypair()

    bobPublicKey = bobPublicKeyPair[0]
    bobPrivateKey = bobPublicKeyPair[1]
    bobKeyE = bobPublicKey[0]
    bobKeyN = bobPublicKey[1]
    bobKeyD = bobPrivateKey[0]

    # Generate Server's public key pair
    serverPublicKeyPair = generate_public_keypair()

    serverPublicKey = serverPublicKeyPair[0]
    serverPrivateKey = serverPublicKeyPair[1]
    serverKeyE = serverPublicKey[0]
    serverKeyN = serverPublicKey[1]
    serverKeyD = serverPrivateKey[0]

    # Create Alice and Bob certificates which contains { name : public key }
    certificate = {}

    certificate['Alice'] = alicePublicKey
    certificate['Bob'] = bobPublicKey

    # Convert certificate from Hash Map to string for encryption
    aliceCertificate = "Alice," + str(certificate['Alice'][0]) + "," + str(certificate['Alice'][1])
    bobCertificate = "Bob," + str(certificate['Bob'][0]) + "," + str(certificate['Bob'][1])

    print("Server: Key Distribution Center initialised with Alice's and Bob's certificates: ", certificate)
    print("Server: Key Distribution Center public key: ", serverPublicKey, "\n")

    aliceSendRequestToServer = str(input("Press 's' to start protocol:"))

    if not aliceSendRequestToServer:
        print("ERROR: Protocol not started. Please try again.")
        sys.exit(1)
    else:

        print("\n.:: STARTING PROTOCOL. CONNECTION OPENED ::.\n")

        # ----------------------- STEP 1 -----------------------
        print("\n(1) ALICE: Dear Server, this is Alice and I'd like to get Bob's public key.")

        # Server signs Bob's certificate (with Server private key) (authentication)
        rsaEncryption = RsaEncryption()

        bobSignedCertificate = [ rsaEncryption.encrypt(ord(c), serverKeyD, serverKeyN) for c in bobCertificate ]

        # ----------------------- STEP 2 -----------------------
        # Send Bob's signed certificate to Alice
        print("(2) SERVER: Dear Alice, this is Bob's public key signed by me: " , bobSignedCertificate)

        # Alice decrypts Bob's certificate (with Server public key) to get Bob's public key
        rsaDecryption = RsaDecryption()

        decryptedBobCertificate = "".join(str(x) for x in [ chr(rsaDecryption.decrypt(c, serverKeyE, serverKeyN)) for c in bobSignedCertificate ])
        decryptedBobCertificate = decryptedBobCertificate.split(',') # Split the string at commas

        print("Alice decrypts Bob's certificate: ", decryptedBobCertificate)

        # Generate Alice's nonce
        aliceNonce = generateNonce()

        # Alice encrypts her nonce (with Bob's public key she just decrypted)
        # decryptedBobCertificate[1] is key E
        # decryptedBobCertificate[2] is key N
        aliceNonceEncryptedWithBobPublicKey = rsaEncryption.encrypt(int(aliceNonce), int(decryptedBobCertificate[1]), int(decryptedBobCertificate[2]))


        # ----------------------- STEP 3 -----------------------
        # Alice sends her encrypted nonce to Bob
        print("\n(3) ALICE: Dear Bob, this is Alice and I've sent you a nonce only you can read.")
        print("Alice's nonce plaintext: ", aliceNonce)
        print("Alice's nonce encrypted with Bob's public key: ", aliceNonceEncryptedWithBobPublicKey)

        aliceSendNonceToBob = str(input("\nPress 's' to send your nonce to Bob:"))

        if not aliceSendNonceToBob:
            print("ERROR: Nonce not sent. Please try again.")
            sys.exit(1)
        else:

            # ----------------------- STEP 4 -----------------------
            print ("\n(4) BOB: Dear Server, this is Bob and I'd like to get Alice's public key.")

            # Server signs Alice's certificate (with Server private key) (authentication)
            aliceSignedCertificate = [ rsaEncryption.encrypt(ord(c), serverKeyD, serverKeyN) for c in aliceCertificate ]


            # ----------------------- STEP 5 -----------------------
            # Server sends Alice's signed certificate to Bob
            print("\n(5) SERVER: Dear Bob, here's Alice's public key signed by me: " , aliceSignedCertificate)

            # Bob decrypts Alice's certificate (with Server public key) to get Alice's public key
            decryptedAliceCertificate = "".join(str(x) for x in [ chr(rsaDecryption.decrypt(c, serverKeyE, serverKeyN)) for c in aliceSignedCertificate ])
            decryptedAliceCertificate = decryptedAliceCertificate.split(',')
            print("Bob decrypts Alice's certificate: ", decryptedAliceCertificate)

            # Bob decrypts Alice's nonce (with his private key)
            decryptedAliceNonce = rsaDecryption.decrypt(aliceNonceEncryptedWithBobPublicKey, bobKeyD, bobKeyN)
            print("Bob decrypts Alice's nonce: ", decryptedAliceNonce)

            # Generate Bob nonce
            bobNonce = generateNonce()

            # Add decrypted Alice's nonce with Bob's nonce and encrypt it (with Alice public key)
            aliceNonceWithBobNonce = str(decryptedAliceNonce) + "," + str(bobNonce)
            print("Alice's nonce with Bob's nonce: ", aliceNonceWithBobNonce)

            # Bob encrypts his nonce plus decrypted Alice's nonce
            # using Alice's public key he just decrypted
            bobNonceEncryptedWithAlicePublicKey = [ rsaEncryption.encrypt(ord(c), int(decryptedAliceCertificate[1]), int(decryptedAliceCertificate[2])) for c in aliceNonceWithBobNonce ]


            # ----------------------- STEP 6 -----------------------
            # Bob sends his nonce plus decrypted Alice's nonce back to Alice
            print("\n(6) BOB: Dear Alice, here's my nonce and yours, proving I decrypted it: " , bobNonceEncryptedWithAlicePublicKey)

            # Alice decrypts Bob's nonce (with her private key)
            decryptedAliceNonceFromBob = "".join(str(x) for x in [ chr(rsaDecryption.decrypt(c, aliceKeyD, aliceKeyN)) for c in bobNonceEncryptedWithAlicePublicKey ])
            decryptedAliceNonceFromBob = decryptedAliceNonceFromBob.split(",")

            print("\nDecrypted Alice Nonce From Bob: ", decryptedAliceNonceFromBob)


            # Verify
            if decryptedAliceNonceFromBob[0] == str(aliceNonce):
                print("Alice verified decrypted Alice's nonce from Bob is correct.\n")
            else:
                print("ERROR: Decrypted Alice's nonce from Bob is not correct. Please try again.")
                sys.exit(1)

            # Alice encrypts Bob's nonce (with Bob's public key)
            encryptBobNonceToSendBack = [ rsaEncryption.encrypt(ord(c), bobKeyE, bobKeyN) for c in decryptedAliceNonceFromBob[1] ] #Alice's nonce is the first element of the array


            # ----------------------- STEP 7 -----------------------
            # Alice sends final encrypted Bob's nonce back to Bob
            print("(7) ALICE: Dear Bob, here's your nonce proving I decrypted it: " , encryptBobNonceToSendBack)

            finalBobNonceFromAlice = "".join(str(x) for x in [ chr(rsaDecryption.decrypt(c, bobKeyD, bobKeyN)) for c in encryptBobNonceToSendBack ])

            print("Bob decrypts nonce from Alice: ", finalBobNonceFromAlice)

            # Verify
            if finalBobNonceFromAlice == str(bobNonce):
                print("Bob verifies Bob's nonce from Alice is correct.")
            else:
                print("ERROR: Decrypted Bob's nonce from Alice is not correct. Please try again.")
                sys.exit(1)

            # Delete nonces from working memory as nonces are used only once
            del aliceNonce, bobNonce

            print("\n.:: TRANSMISSION SUCCESSFUL. CONNECTION CLOSED ::.\n")
            sys.exit(0)

menu()
