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

        # Create hashmap of identity and key
        hashMap = {}
        hashMap['Alice'] = Alice_PublicKey
        hashMap['Bob'] = Bob_PublicKey

        print(hashMap)

        # print("\nSERVER: Dear Alice, this is Bob's public key: " , Alice_PublicKeyPair)


        # Generate nonce
        Alice_Nonce = generateNonce()
        Bob_Nonce = generateNonce()
        # print("\nAlice\'s nonce is: ", Alice_Nonce)
        # print("\nBob\'s nonce is: ", Bob_Nonce)

        # Delete nonces from working memory after use
        # del Alice_Nonce
        # del Bob_Nonce
menu()
