# -*- coding: utf-8 -*-#

class RsaDecryption():

    def __init__(self):
        pass

    def modular_exponentiation(self, x, n, m):
        """ Returns x to the power of n modular m """
        return pow(x,n,m)

    def decrypt(self, ciphertext, publicKey, totient):
        """ Return plaintext by computing ciphertext to the power of publicKey modular totient """
        p = self.modular_exponentiation(ciphertext, publicKey, totient)
        return p
