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

    sendRequest = str(input("Press 's' and enter to request the server for Bob's public key:"))

    if not sendRequest:
        print("ERROR: Request not sent. Please try again.")
        sys.exit(1)

    else:

        ### SIGN ALICE AND BOB PUBLIC KEYS ###

        # Generate public and private key for Alice, Bob and the server
        Alice_PublicKey, _ = generatePublicKeyPair()

        Bob_PublicKey, _  = generatePublicKeyPair()

        Server_PublicKey, _  = generatePublicKeyPair()
        _, Server_PrivateKey  = generatePublicKeyPair()

        # Create certificate of identity (name) and key (public key) to send to the server
        certificate = {}
        certificate['Alice'] = Alice_PublicKey
        certificate['Bob'] = Bob_PublicKey

        print(certificate)

        # Server signs Alice and Bob public keys using RSA encryption
        # this authenticates Alice and Bob
        # sign_certificate()
        signed_Alice_PublicKey = pow(certificate['Alice'], Server_PrivateKey, )
        # signed_Bob_PublicKey =

        # Send Bob's public key to Alice
        print("\nSERVER: Dear Alice, this is Bob's public key: " , signed_Alice_PublicKey)


        # Generate Alice's nonce
        Alice_Nonce = generateNonce()
        Bob_Nonce = generateNonce()
        # print(Alice_Nonce, Bob_Nonce)

        # Encrypt Alice's nonce
        # encrypted_Alice_Nonce = pow()

        # print("\nAlice\'s nonce is: ", encrypted_Alice_Nonce)

        print("\nALICE: Dear Bob, this is Alice and I've sent you a nonce only you can read.")
        sendBobNonce = str(input("Press 's' and enter to send your nonce to Bob:"))

        if not sendBobNonce:
            print("ERROR: Request not sent. Please try again.")
            sys.exit(1)
        else:

            pass

        # Delete nonces from working memory after use
        # del Alice_Nonce, encrypted_Alice_Nonce
        # del Bob_Nonce, encrypted_Bob_Nonce
menu()
